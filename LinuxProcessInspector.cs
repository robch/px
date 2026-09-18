using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

// Linux exposes everything px needs directly as files under /proc/<pid>/, with no elevation
// needed for your own processes (same-user access to others' is normally allowed too; root
// required only for processes owned by other users) - no memory-reading tricks required:
//
//   /proc/<pid>/environ  - NUL-separated "NAME=VALUE" entries, same format GetProcessDetails
//                          already parses on Windows (ParseEnvironmentBlock in px.cs works as-is)
//   /proc/<pid>/cmdline  - NUL-separated argv, already split by the kernel (no CommandLineToArgvW
//                          equivalent needed - ParseCommandLine becomes a trivial Split('\0'))
//   /proc/<pid>/cwd      - symlink; resolves to the current working directory
//   /proc/<pid>/exe      - symlink; resolves to the on-disk executable path
//   /proc/<pid>/stat     - whitespace-separated fields; field 4 (1-indexed) is the parent pid
//                          (careful: field 2, the comm name, is parenthesized and may itself
//                          contain spaces/parens, so it can't be split naively - skip past the
//                          last ')' first)
[SupportedOSPlatform("linux")]
class LinuxProcessInspector : IProcessInspector
{
    const uint S_IFMT = 0xF000;
    const uint S_IFREG = 0x8000;
    const int StatModeOffset = 24; // x64 Linux struct stat: st_mode follows st_dev/st_ino/st_nlink

    [DllImport("libc", SetLastError = true)]
    static extern int stat(string path, byte[] buffer);

    public ProcessDetails GetProcessDetails(int pid)
    {
        var details = new ProcessDetails();
        string procDir = "/proc/" + pid;

        if (!Directory.Exists(procDir))
        {
            details.Error = "ERROR: no such process " + pid;
            return details;
        }

        // /proc/<pid>/environ and /proc/<pid>/cmdline: NUL-separated entries. Kept in the exact
        // same "NAME=VALUE\0NAME=VALUE\0..." / "arg0\0arg1\0..." shape the rest of px already
        // expects (ParseEnvironmentBlock in px.cs splits EnvBlock on '\0'; ParseCommandLine below
        // does the same for CommandLine) - identical to what the Windows PEB reader produces.
        //
        // /proc/<pid>/environ specifically is only readable by the process's own owner (or root) -
        // unlike cmdline/exe/cwd/stat, which are normally world-readable. So a permission failure
        // reading JUST environ (e.g. inspecting a root-owned process as a regular user) must be
        // surfaced as a real error, not silently presented as "this process simply has zero
        // environment variables" - that would be actively misleading.
        details.EnvBlock = TryReadAllBytesAsString(procDir + "/environ", out bool environPermissionDenied);
        details.CommandLine = TryReadAllBytesAsString(procDir + "/cmdline", out _);
        details.CurrentDirectory = TryReadLink(procDir + "/cwd");
        details.ImagePath = TryReadLink(procDir + "/exe");
        details.ParentPid = ReadParentPidFromStat(procDir + "/stat");

        if (string.IsNullOrEmpty(details.EnvBlock) && string.IsNullOrEmpty(details.CommandLine) &&
            string.IsNullOrEmpty(details.CurrentDirectory) && string.IsNullOrEmpty(details.ImagePath))
        {
            details.Error = "ERROR: could not read /proc/" + pid + " (process may have exited, or you may lack permission)";
        }
        else if (environPermissionDenied)
        {
            details.Error = "ERROR: permission denied reading environment variables for process " + pid +
                " (owned by another user - try sudo)";
        }

        return details;
    }

    public OpenFilesResult GetOpenFiles(int pid)
    {
        var result = new OpenFilesResult();
        string fdDirectory = "/proc/" + pid + "/fd";

        try
        {
            var files = new HashSet<string>(StringComparer.Ordinal);
            foreach (string descriptorPath in Directory.EnumerateFileSystemEntries(fdDirectory))
            {
                try
                {
                    // stat() follows the descriptor symlink and lets us reject directories,
                    // sockets, pipes, and devices before treating its target as a file path.
                    byte[] statBuffer = new byte[256];
                    if (stat(descriptorPath, statBuffer) != 0)
                        continue; // the descriptor may have closed while we were enumerating it

                    uint mode = BitConverter.ToUInt32(statBuffer, StatModeOffset);
                    if ((mode & S_IFMT) != S_IFREG)
                        continue;

                    // Read the link itself rather than resolving the final target so Linux's
                    // useful " (deleted)" suffix is retained for an unlinked-but-open file.
                    string target = new FileInfo(descriptorPath).LinkTarget ?? "";
                    if (target.StartsWith('/'))
                        files.Add(target);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Closing descriptors are an expected race; keep every path we did obtain.
                }
            }

            result.Files = files.OrderBy(path => path, StringComparer.Ordinal).ToArray();
        }
        catch (UnauthorizedAccessException)
        {
            result.Error = "ERROR: permission denied reading open files for process " + pid + " (try sudo)";
        }
        catch (IOException)
        {
            result.Error = "ERROR: could not read open files for process " + pid + " (process may have exited)";
        }

        return result;
    }

    // TCP connection states as they appear (hex) in /proc/net/tcp[6]'s "st" column - order and
    // naming mirrors the Windows MIB_TCP_STATE enum used by WindowsProcessInspector, so the
    // rendered output looks the same across platforms.
    static readonly string[] TcpStates = new[]
    {
        "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT",
        "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };

    public OpenPortsResult GetOpenPorts(int pid)
    {
        var result = new OpenPortsResult();

        try
        {
            var socketInodes = GetSocketInodes(pid);
            var ports = new List<PortInfo>();

            if (socketInodes.Count > 0)
            {
                ParseNetFile("/proc/net/tcp", "TCP", socketInodes, ports, includeRemote: true);
                ParseNetFile("/proc/net/tcp6", "TCP", socketInodes, ports, includeRemote: true);
                ParseNetFile("/proc/net/udp", "UDP", socketInodes, ports, includeRemote: false);
                ParseNetFile("/proc/net/udp6", "UDP", socketInodes, ports, includeRemote: false);
            }

            result.Ports = ports.OrderBy(p => p.Protocol).ThenBy(p => p.LocalPort).ToArray();
        }
        catch (UnauthorizedAccessException)
        {
            result.Error = "ERROR: permission denied reading open ports for process " + pid + " (try sudo)";
        }
        catch (IOException)
        {
            result.Error = "ERROR: could not read open ports for process " + pid + " (process may have exited)";
        }

        return result;
    }

    // /proc/<pid>/fd/<n> symlinks that represent sockets point to a pseudo-path of the form
    // "socket:[<inode>]" - collecting those inodes lets us cross-reference the system-wide
    // /proc/net/{tcp,tcp6,udp,udp6} tables (which have no per-pid view of their own) back to
    // this specific process, the same way `lsof`/`ss -p` do.
    static HashSet<long> GetSocketInodes(int pid)
    {
        var inodes = new HashSet<long>();
        string fdDirectory = "/proc/" + pid + "/fd";

        foreach (string descriptorPath in Directory.EnumerateFileSystemEntries(fdDirectory))
        {
            try
            {
                string target = new FileInfo(descriptorPath).LinkTarget ?? "";
                if (target.StartsWith("socket:[") && target.EndsWith(']'))
                {
                    string inodeText = target.Substring(8, target.Length - 9);
                    if (long.TryParse(inodeText, out long inode))
                        inodes.Add(inode);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Closing descriptors are an expected race; keep every one we did obtain.
            }
        }

        return inodes;
    }

    // /proc/net/tcp[6] and /proc/net/udp[6] are whitespace-separated tables, one connection/socket
    // per line, with a header line to skip. Column layout (0-indexed after splitting):
    //   0: sl  1: local_address  2: rem_address  3: st  4: tx_queue:rx_queue  5: tr:tm->when
    //   6: retrnsmt  7: uid  8: timeout  9: inode  ...
    // Every socket on the system is listed here (there's no per-pid view), so we only keep rows
    // whose inode is one this process actually has open.
    static void ParseNetFile(string path, string protocol, HashSet<long> socketInodes, List<PortInfo> ports, bool includeRemote)
    {
        if (!File.Exists(path)) return;

        string[] lines;
        try
        {
            lines = File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            string[] fields = lines[i].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 10) continue;
            if (!long.TryParse(fields[9], out long inode) || !socketInodes.Contains(inode)) continue;

            var (localAddress, localPort) = ParseHexAddressAndPort(fields[1]);
            int stateValue = Convert.ToInt32(fields[3], 16);

            var portInfo = new PortInfo
            {
                Protocol = protocol,
                LocalAddress = localAddress,
                LocalPort = localPort,
                State = includeRemote && stateValue >= 0 && stateValue < TcpStates.Length ? TcpStates[stateValue] : ""
            };

            if (includeRemote)
            {
                (portInfo.RemoteAddress, portInfo.RemotePort) = ParseHexAddressAndPort(fields[2]);
            }

            ports.Add(portInfo);
        }
    }

    // /proc/net's address:port columns are hex-encoded: the port is a plain big-endian 16-bit
    // hex value, but the address is the raw in-memory representation of an in_addr/in6_addr -
    // i.e. little-endian per 32-bit word on virtually all real-world (x86/ARM) kernels - so each
    // 4-byte (IPv4) or 4x4-byte (IPv6) group needs its bytes reversed before handing to IPAddress.
    static (string address, int port) ParseHexAddressAndPort(string field)
    {
        int colon = field.IndexOf(':');
        string addressHex = field.Substring(0, colon);
        int port = Convert.ToInt32(field.Substring(colon + 1), 16);

        int dwordCount = addressHex.Length / 8;
        byte[] bytes = new byte[dwordCount * 4];
        for (int dword = 0; dword < dwordCount; dword++)
        {
            for (int b = 0; b < 4; b++)
            {
                string byteHex = addressHex.Substring(dword * 8 + (3 - b) * 2, 2);
                bytes[dword * 4 + b] = Convert.ToByte(byteHex, 16);
            }
        }

        return (new System.Net.IPAddress(bytes).ToString(), port);
    }

    // Lightweight parent-PID lookup for ancestor-chain walking (--tree): only reads
    // /proc/<pid>/stat, skipping the environ/cmdline/symlink reads GetProcessDetails does for
    // the primary matched processes. Returns -1 on any failure.
    public int GetParentPidOnly(int pid) => ReadParentPidFromStat("/proc/" + pid + "/stat");

    static string TryReadAllBytesAsString(string path) => TryReadAllBytesAsString(path, out _);

    static string TryReadAllBytesAsString(string path, out bool permissionDenied)
    {
        permissionDenied = false;
        try
        {
            return Encoding.UTF8.GetString(File.ReadAllBytes(path));
        }
        catch (UnauthorizedAccessException)
        {
            permissionDenied = true;
            return "";
        }
        catch (IOException)
        {
            return "";
        }
    }

    // /proc/<pid>/cwd and /proc/<pid>/exe are symlinks; resolve them to their real target path
    // (following the full chain, equivalent to `readlink -f`).
    static string TryReadLink(string path)
    {
        try
        {
            return File.ResolveLinkTarget(path, returnFinalTarget: true)?.FullName ?? "";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "";
        }
    }

    // /proc/<pid>/stat fields (space-separated): (1) pid (2) comm (3) state (4) ppid ...
    // The comm field is parenthesized and may itself contain spaces or parens (e.g. a process
    // renamed to "my (weird) name"), so we can't just Split(' ') from the start - instead, skip
    // past the LAST ')' in the line (the standard, robust way the "man proc" page recommends
    // handling this), then the second whitespace-separated token after that is the parent pid
    // (the first is the single-character state).
    static int ReadParentPidFromStat(string statPath)
    {
        try
        {
            string content = File.ReadAllText(statPath);
            int lastParen = content.LastIndexOf(')');
            if (lastParen < 0) return -1;

            string rest = content.Substring(lastParen + 1).TrimStart();
            string[] fields = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return fields.Length >= 2 && int.TryParse(fields[1], out int ppid) ? ppid : -1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return -1;
        }
    }

    // /proc/<pid>/cmdline already gives argv split by NUL - no re-parsing needed, unlike Windows.
    public string[] ParseCommandLine(string cmdLine)
    {
        return string.IsNullOrEmpty(cmdLine)
            ? Array.Empty<string>()
            : cmdLine.Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    // The kernel's "comm" field (what Process.ProcessName reads on Linux, and what
    // /proc/<pid>/stat's 2nd field contains) is a fixed 16-byte buffer - only 15 printable
    // characters survive, always, no exceptions. That silently breaks both display AND
    // matching for perfectly common, recognizable names:
    //   systemd-resolved      (16 chars) -> comm: "systemd-resolve"  (px resolved -> no match)
    //   systemd-networkd      (16 chars) -> comm: "systemd-network"  (px networkd -> no match)
    //   unattended-upgrades   (19 chars) -> comm: "unattended-upgr"  (px upgrades -> no match)
    //
    // `ps` avoids this entirely by showing argv[0] (or a process's self-rewritten cmdline,
    // e.g. "postgres: checkpointer") instead of comm - argv/cmdline has no such length limit.
    // We do the same here: prefer the basename of argv[0] from /proc/<pid>/cmdline, and only
    // fall back to the truncated comm name if cmdline couldn't be read (e.g. permission denied,
    // or a kernel thread with no argv at all).
    public string GetDisplayName(int pid)
    {
        string cmdline = TryReadAllBytesAsString("/proc/" + pid + "/cmdline");
        if (!string.IsNullOrEmpty(cmdline))
        {
            string argv0 = cmdline.Split('\0', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } parts
                ? parts[0]
                : "";
            if (!string.IsNullOrEmpty(argv0))
                return System.IO.Path.GetFileName(argv0.TrimEnd('/'));
        }

        // Fallback: /proc/<pid>/comm (same truncated value as Process.ProcessName), trimmed of
        // its trailing newline.
        string comm = TryReadAllBytesAsString("/proc/" + pid + "/comm").TrimEnd('\n');
        return !string.IsNullOrEmpty(comm) ? comm : "?";
    }

    // POSIX shell-safe quoting: wrap in single quotes, escaping any embedded single quote as
    // '\'' (close quote, escaped literal quote, reopen quote). Simpler and more robust than
    // trying to mirror bash's many special characters individually.
    public string EscapeArgumentForDisplay(string arg)
    {
        if (arg.Length != 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\'', '"', '$', '`', '\\', '!', '*', '?', '[', ']', '(', ')', '{', '}', '&', '|', ';', '<', '>', '~' }) < 0)
            return arg;

        return "'" + arg.Replace("'", "'\\''") + "'";
    }
}
