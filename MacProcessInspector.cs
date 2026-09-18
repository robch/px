using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

// macOS has no /proc filesystem, so unlike Linux this needs its own native-API layer - similar
// effort-level to the Windows PEB-reading, just against different (semi-)documented APIs:
//
//   Command line + environment: sysctl(CTL_KERN, KERN_PROCARGS2, pid) via P/Invoke into libc -
//                                returns argc followed by a NUL-separated exec_path+argv+environ
//                                blob that has to be walked manually.
//   Image path:                  proc_pidpath() from libproc.
//   Current working directory:   proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, ...) from libproc,
//                                 reading the embedded vip_path field.
//   Parent pid:                  proc_pidinfo(pid, PROC_PIDTBSDINFO, ...) -> pbi_ppid.
//
// IMPORTANT - not yet verified on real hardware: this was written against the documented/stable
// BSD kernel struct layouts (bsd/sys/proc_info.h in Apple's open-source xnu kernel), but without
// a Mac available to cross-check with an actual `sizeof`/`offsetof` build. The KERN_PROCARGS2
// parsing and the PROC_PIDTBSDINFO (pbi_ppid) offset are simple/stable and very likely correct
// as-is. The PROC_PIDVNODEPATHINFO (cwd) offset math is the riskiest part - struct
// proc_vnodepathinfo embeds a vinfo_stat whose exact byte size is the one number here most worth
// double-checking on a real Mac (see ComputeCwdPathOffset below) - if it's off, --cwd will just
// come back empty/garbled while everything else (env, cmdline, image path, ppid) still works,
// since each piece is read and parsed independently.
[SupportedOSPlatform("macos")]
class MacProcessInspector : IProcessInspector
{
    const int CTL_KERN = 1;
    const int KERN_PROCARGS2 = 49;
    const int PROC_PIDLISTFDS = 1;
    const int PROC_PIDTBSDINFO = 3;
    const int PROC_PIDVNODEPATHINFO = 9;
    const int PROC_PIDFDVNODEPATHINFO = 2;
    const int PROC_PIDFDSOCKETINFO = 3;
    const uint PROX_FDTYPE_VNODE = 1;
    const uint PROX_FDTYPE_SOCKET = 2;
    const ushort S_IFMT = 0xF000;
    const ushort S_IFREG = 0x8000;
    const int MAXPATHLEN = 1024;

    // struct socket_fdinfo (bsd/sys/proc_info.h): { struct proc_fileinfo pfi; struct socket_info psi; }.
    // Byte offsets below are absolute from the start of socket_fdinfo, cross-checked against the
    // actively-maintained oshi-core-ffm project's explicit field-by-field struct layout (which
    // itself targets these same stable/documented XNU structs) rather than derived by hand:
    //   proc_fileinfo (pfi) is 24 bytes -> socket_info (psi) starts at 24.
    //   Within socket_info: soi_kind at +232, soi_proto (union) at +240.
    //   Within soi_proto, both tcp_sockinfo.tcpsi_ini and in_sockinfo (UDP's "pri_in") start at
    //   the same offset 0, so the shared in_sockinfo fields below (fport/lport/vflag/faddr/laddr)
    //   apply to TCP and UDP alike; tcpsi_state (TCP-only) follows the embedded in_sockinfo (80 bytes).
    const int SoiKindOffset = 24 + 232;
    const int InSockInfoOffset = 24 + 240;
    const int InsiLportOffset = InSockInfoOffset + 4;
    const int InsiFportOffset = InSockInfoOffset + 0;
    const int InsiVflagOffset = InSockInfoOffset + 24;
    const int InsiFaddrOffset = InSockInfoOffset + 32;
    const int InsiLaddrOffset = InSockInfoOffset + 48;
    const int TcpsiStateOffset = InSockInfoOffset + 80;
    const int SocketFdInfoBufferSize = 800; // generous; actual struct is well under this

    const int SOCKINFO_IN = 1; // UDP (or other non-TCP INET socket)
    const int SOCKINFO_TCP = 2;
    const byte INI_IPV4 = 0x1;
    const byte INI_IPV6 = 0x2;

    // TSI_S_* connection states (bsd/sys/proc_info.h), in enum order.
    static readonly string[] TcpStates = new[]
    {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSE_WAIT",
        "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT", "RESERVED"
    };

    [DllImport("libc", SetLastError = true)]
    static extern int sysctl(int[] mib, uint namelen, byte[] oldp, ref IntPtr oldlenp, IntPtr newp, IntPtr newlen);

    [DllImport("libproc.dylib", SetLastError = true)]
    static extern int proc_pidpath(int pid, byte[] buffer, uint buffersize);

    [DllImport("libproc.dylib", SetLastError = true)]
    static extern int proc_pidinfo(int pid, int flavor, ulong arg, byte[] buffer, int buffersize);

    [DllImport("libproc.dylib", SetLastError = true)]
    static extern int proc_pidinfo(int pid, int flavor, ulong arg, IntPtr buffer, int buffersize);

    [DllImport("libproc.dylib", SetLastError = true)]
    static extern int proc_pidfdinfo(int pid, int fd, int flavor, byte[] buffer, int buffersize);

    public ProcessDetails GetProcessDetails(int pid)
    {
        var details = new ProcessDetails();

        bool argsPermissionDenied = ReadArgsAndEnv(pid, out string cmdLine, out string envBlock);
        details.CommandLine = cmdLine;
        details.EnvBlock = envBlock;
        details.ImagePath = ReadImagePath(pid);
        details.CurrentDirectory = ReadCurrentDirectory(pid);
        details.ParentPid = ReadParentPid(pid);

        if (string.IsNullOrEmpty(details.CommandLine) && string.IsNullOrEmpty(details.ImagePath) &&
            details.ParentPid <= 0)
        {
            details.Error = "ERROR: could not read process " + pid + " (process may have exited, or you may lack permission)";
        }
        else if (argsPermissionDenied)
        {
            details.Error = "ERROR: permission denied reading arguments/environment for process " + pid +
                " (owned by another user - try sudo)";
        }

        return details;
    }

    public OpenFilesResult GetOpenFiles(int pid)
    {
        var result = new OpenFilesResult();

        try
        {
            // proc_fdinfo is two 32-bit values: descriptor number and descriptor type. Ask
            // libproc for the required size first, with a little room for descriptors opened
            // between the sizing and data calls.
            int requiredBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, IntPtr.Zero, 0);
            if (requiredBytes <= 0)
            {
                int error = Marshal.GetLastWin32Error();
                result.Error = error == 1 || error == 13
                    ? "ERROR: permission denied reading open files for process " + pid
                    : "ERROR: could not read open files for process " + pid + " (process may have exited)";
                return result;
            }

            byte[] descriptorBuffer = new byte[requiredBytes + 32 * 8];
            int descriptorBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, descriptorBuffer, descriptorBuffer.Length);
            if (descriptorBytes <= 0)
            {
                int error = Marshal.GetLastWin32Error();
                result.Error = error == 1 || error == 13
                    ? "ERROR: permission denied reading open files for process " + pid
                    : "ERROR: could not read open files for process " + pid + " (process may have exited)";
                return result;
            }

            var files = new HashSet<string>(StringComparer.Ordinal);
            for (int offset = 0; offset + 8 <= descriptorBytes; offset += 8)
            {
                int descriptor = BitConverter.ToInt32(descriptorBuffer, offset);
                uint descriptorType = BitConverter.ToUInt32(descriptorBuffer, offset + 4);
                if (descriptorType != PROX_FDTYPE_VNODE)
                    continue;

                byte[] vnodeBuffer = new byte[2048];
                int vnodeBytes = proc_pidfdinfo(pid, descriptor, PROC_PIDFDVNODEPATHINFO,
                    vnodeBuffer, vnodeBuffer.Length);
                if (vnodeBytes <= VnodePathOffset)
                    continue; // descriptor closed, became inaccessible, or has no path

                ushort mode = BitConverter.ToUInt16(vnodeBuffer, VnodeModeOffset);
                if ((mode & S_IFMT) != S_IFREG)
                    continue;

                int maximumPathBytes = Math.Min(MAXPATHLEN, vnodeBytes - VnodePathOffset);
                int pathEnd = Array.IndexOf(vnodeBuffer, (byte)0, VnodePathOffset, maximumPathBytes);
                if (pathEnd > VnodePathOffset)
                    files.Add(Encoding.UTF8.GetString(vnodeBuffer, VnodePathOffset, pathEnd - VnodePathOffset));
            }

            result.Files = files.OrderBy(path => path, StringComparer.Ordinal).ToArray();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            result.Error = "ERROR: open-file inspection is unavailable on this version of macOS";
        }

        return result;
    }

    public int GetParentPidOnly(int pid) => ReadParentPid(pid);

    public OpenPortsResult GetOpenPorts(int pid)
    {
        var result = new OpenPortsResult();

        try
        {
            int requiredBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, IntPtr.Zero, 0);
            if (requiredBytes <= 0)
            {
                int error = Marshal.GetLastWin32Error();
                result.Error = error == 1 || error == 13
                    ? "ERROR: permission denied reading open ports for process " + pid
                    : "ERROR: could not read open ports for process " + pid + " (process may have exited)";
                return result;
            }

            byte[] descriptorBuffer = new byte[requiredBytes + 32 * 8];
            int descriptorBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, descriptorBuffer, descriptorBuffer.Length);
            if (descriptorBytes <= 0)
            {
                int error = Marshal.GetLastWin32Error();
                result.Error = error == 1 || error == 13
                    ? "ERROR: permission denied reading open ports for process " + pid
                    : "ERROR: could not read open ports for process " + pid + " (process may have exited)";
                return result;
            }

            var ports = new List<PortInfo>();
            for (int offset = 0; offset + 8 <= descriptorBytes; offset += 8)
            {
                int descriptor = BitConverter.ToInt32(descriptorBuffer, offset);
                uint descriptorType = BitConverter.ToUInt32(descriptorBuffer, offset + 4);
                if (descriptorType != PROX_FDTYPE_SOCKET)
                    continue;

                byte[] socketBuffer = new byte[SocketFdInfoBufferSize];
                int socketBytes = proc_pidfdinfo(pid, descriptor, PROC_PIDFDSOCKETINFO, socketBuffer, socketBuffer.Length);
                if (socketBytes < TcpsiStateOffset)
                    continue; // descriptor closed or became inaccessible between listing and reading it

                int kind = BitConverter.ToInt32(socketBuffer, SoiKindOffset);
                if (kind != SOCKINFO_TCP && kind != SOCKINFO_IN)
                    continue; // not an internet-protocol socket (e.g. unix domain, kernel event, etc.)

                byte vflag = socketBuffer[InsiVflagOffset];
                if ((vflag & (INI_IPV4 | INI_IPV6)) == 0)
                    continue;

                bool isIPv6 = (vflag & INI_IPV6) != 0;
                int localPort = PortFromNetworkOrder(BitConverter.ToInt32(socketBuffer, InsiLportOffset));
                int remotePort = PortFromNetworkOrder(BitConverter.ToInt32(socketBuffer, InsiFportOffset));

                var portInfo = new PortInfo
                {
                    Protocol = kind == SOCKINFO_TCP ? "TCP" : "UDP",
                    LocalAddress = ReadSocketAddress(socketBuffer, InsiLaddrOffset, isIPv6),
                    LocalPort = localPort
                };

                if (kind == SOCKINFO_TCP)
                {
                    portInfo.RemoteAddress = ReadSocketAddress(socketBuffer, InsiFaddrOffset, isIPv6);
                    portInfo.RemotePort = remotePort;
                    int state = BitConverter.ToInt32(socketBuffer, TcpsiStateOffset);
                    portInfo.State = state >= 0 && state < TcpStates.Length ? TcpStates[state] : "UNKNOWN";
                }

                ports.Add(portInfo);
            }

            result.Ports = ports.OrderBy(p => p.Protocol).ThenBy(p => p.LocalPort).ToArray();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            result.Error = "ERROR: open-port inspection is unavailable on this version of macOS";
        }

        return result;
    }

    // insi_fport/insi_lport are 4-byte fields but only the low 16 bits are meaningful, holding
    // the port in network (big-endian) byte order - the same "ntohs of the low 16 bits" rule
    // every reference implementation (psutil, osquery, oshi, etc.) applies.
    static int PortFromNetworkOrder(int raw) =>
        ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    // insi_faddr/insi_laddr are each a 16-byte union of { in4in6_addr; in6_addr }. For IPv6, all
    // 16 bytes are the address verbatim. For IPv4, the address is the last 4 bytes of the union
    // (in4in6_addr's i46a_addr4 field, after 12 bytes of i46a_pad32 padding) - already in the
    // correct byte order for System.Net.IPAddress, no reversal needed (unlike Linux's /proc/net
    // hex dump, which uses the raw in-memory word order instead of network byte order).
    static string ReadSocketAddress(byte[] buffer, int offset, bool isIPv6)
    {
        byte[] addressBytes = new byte[isIPv6 ? 16 : 4];
        Array.Copy(buffer, isIPv6 ? offset : offset + 12, addressBytes, 0, addressBytes.Length);
        return new System.Net.IPAddress(addressBytes).ToString();
    }

    // KERN_PROCARGS2 buffer layout (well-documented/stable, used by `ps`, Activity Monitor-style
    // tools, etc.): [ argc:int32 ][ exec_path NUL-terminated ][ NUL padding ]
    //               [ argv[0] NUL-terminated ]...[ argv[argc-1] NUL-terminated ][ NUL padding ]
    //               [ environ[0] NUL-terminated ]...[ to end of buffer ].
    // Returns true if the sysctl call failed specifically due to a permission error (EPERM),
    // as opposed to any other failure (process gone, etc).
    static bool ReadArgsAndEnv(int pid, out string cmdLine, out string envBlock)
    {
        cmdLine = "";
        envBlock = "";

        var mib = new[] { CTL_KERN, KERN_PROCARGS2, pid };
        IntPtr size = IntPtr.Zero;

        // First call with a null buffer just to learn the required size.
        if (sysctl(mib, 3, null, ref size, IntPtr.Zero, IntPtr.Zero) != 0 || size == IntPtr.Zero)
            return Marshal.GetLastWin32Error() == 1; // EPERM == 1

        byte[] buffer = new byte[size.ToInt32()];
        if (sysctl(mib, 3, buffer, ref size, IntPtr.Zero, IntPtr.Zero) != 0)
            return Marshal.GetLastWin32Error() == 1;

        int total = size.ToInt32();
        if (total < 4) return false;

        int argc = BitConverter.ToInt32(buffer, 0);
        int pos = 4;

        // Skip the leading exec_path string (the resolved binary path - we already get this,
        // more reliably, from proc_pidpath, so it's discarded here).
        pos = SkipNulTerminatedString(buffer, pos, total);
        pos = SkipNulPadding(buffer, pos, total);

        var argvBuilder = new StringBuilder();
        for (int i = 0; i < argc && pos < total; i++)
        {
            int start = pos;
            pos = SkipNulTerminatedString(buffer, pos, total);
            argvBuilder.Append(Encoding.UTF8.GetString(buffer, start, Math.Max(0, pos - start - 1)));
            argvBuilder.Append('\0');
        }
        cmdLine = argvBuilder.ToString();

        pos = SkipNulPadding(buffer, pos, total);

        var envBuilder = new StringBuilder();
        while (pos < total)
        {
            int start = pos;
            pos = SkipNulTerminatedString(buffer, pos, total);
            if (pos - start <= 1) break; // ran into trailing padding/empty - end of environ block
            envBuilder.Append(Encoding.UTF8.GetString(buffer, start, pos - start - 1));
            envBuilder.Append('\0');
        }
        envBlock = envBuilder.ToString();

        return false;
    }

    static int SkipNulTerminatedString(byte[] buffer, int pos, int total)
    {
        while (pos < total && buffer[pos] != 0) pos++;
        return Math.Min(pos + 1, total);
    }

    static int SkipNulPadding(byte[] buffer, int pos, int total)
    {
        while (pos < total && buffer[pos] == 0) pos++;
        return pos;
    }

    static string ReadImagePath(int pid)
    {
        try
        {
            byte[] buffer = new byte[MAXPATHLEN];
            int len = proc_pidpath(pid, buffer, (uint)buffer.Length);
            return len > 0 ? Encoding.UTF8.GetString(buffer, 0, len) : "";
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return "";
        }
    }

    // struct proc_bsdinfo (bsd/sys/proc_info.h): pbi_flags, pbi_status, pbi_xstatus, pbi_pid are
    // each uint32_t (4 bytes), so pbi_ppid - the field we want - sits at a fixed byte offset of
    // 16. This part of the struct hasn't changed across macOS versions and is the same approach
    // Sysinternals-style/Activity-Monitor-style tools use, so this offset is low-risk.
    const int ProcBsdInfoSize = 4 * 1024; // generous fixed-size buffer, larger than struct proc_bsdinfo actually needs
    const int PbiPpidOffset = 16;

    static int ReadParentPid(int pid)
    {
        try
        {
            byte[] buffer = new byte[ProcBsdInfoSize];
            int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buffer, buffer.Length);
            return ret > PbiPpidOffset + 4 ? BitConverter.ToInt32(buffer, PbiPpidOffset) : -1;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return -1;
        }
    }

    // struct proc_vnodepathinfo { struct vnode_fdinfowithpath pvi_cdir; ... } where
    // vnode_fdinfowithpath embeds a vnode_info_path { struct vnode_info vip_vi; char
    // vip_path[MAXPATHLEN]; } and vnode_info embeds a vinfo_stat (a fixed-size,
    // platform-stable restatement of `struct stat`) followed by vi_type/vi_pad/vi_fsid.
    // This byte offset to vip_path is the single riskiest number in this file - see the
    // class-level comment. If --cwd comes back wrong/empty on real hardware, this is the
    // first place to check (e.g. via a tiny native `offsetof` probe compiled on the target Mac).
    const int CwdPathOffset = 152;

    // vnode_fdinfowithpath begins with a 24-byte proc_fileinfo followed by vnode_info_path.
    // vinfo_stat.vst_mode is four bytes into vnode_info_path, while vip_path begins 128 bytes
    // into it. These are the matching offsets from bsd/sys/proc_info.h.
    const int VnodeModeOffset = 28;
    const int VnodePathOffset = 176;

    static string ReadCurrentDirectory(int pid)
    {
        try
        {
            byte[] buffer = new byte[8192];
            int ret = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, buffer, buffer.Length);
            if (ret <= CwdPathOffset) return "";

            int end = Array.IndexOf(buffer, (byte)0, CwdPathOffset, Math.Min(MAXPATHLEN, buffer.Length - CwdPathOffset));
            if (end < 0) return "";

            return Encoding.UTF8.GetString(buffer, CwdPathOffset, end - CwdPathOffset);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or ArgumentOutOfRangeException)
        {
            return "";
        }
    }

    // KERN_PROCARGS2 already hands back argv as discrete NUL-separated strings - no re-parsing
    // needed, unlike Windows.
    public string[] ParseCommandLine(string cmdLine)
    {
        return string.IsNullOrEmpty(cmdLine)
            ? Array.Empty<string>()
            : cmdLine.Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    // /proc doesn't exist on macOS, but display-name-vs-truncated-comm is the same underlying
    // concern as Linux: prefer the untruncated argv[0] from KERN_PROCARGS2 over the kernel's
    // short name (which macOS also caps, via the same-spirit MAXCOMLEN limit as pbi_comm).
    public string GetDisplayName(int pid)
    {
        ReadArgsAndEnv(pid, out string cmdLine, out _);
        var argv = ParseCommandLine(cmdLine);
        if (argv.Length > 0 && !string.IsNullOrEmpty(argv[0]))
            return System.IO.Path.GetFileName(argv[0].TrimEnd('/'));

        string imagePath = ReadImagePath(pid);
        return !string.IsNullOrEmpty(imagePath) ? System.IO.Path.GetFileName(imagePath) : "?";
    }

    // Same POSIX shell-safe quoting rule as Linux.
    public string EscapeArgumentForDisplay(string arg)
    {
        if (arg.Length != 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\'', '"', '$', '`', '\\', '!', '*', '?', '[', ']', '(', ')', '{', '}', '&', '|', ';', '<', '>', '~' }) < 0)
            return arg;

        return "'" + arg.Replace("'", "'\\''") + "'";
    }
}
