using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

// Reads another process's environment block, raw command line, image path, and current
// directory by walking its PEB (Process Environment Block) via NtQueryInformationProcess +
// ReadProcessMemory - Windows exposes none of this through documented/managed APIs.
[SupportedOSPlatform("windows")]
class WindowsProcessInspector : IProcessInspector
{
    const int PROCESS_DUP_HANDLE = 0x0040;
    const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    const uint FILE_TYPE_DISK = 0x0001;
    const int SystemExtendedHandleInformation = 64;
    const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, byte[] pi, int piLen, out int retLen);

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int informationClass, IntPtr information, int informationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buffer, int size, out int bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
        out IntPtr targetHandle, uint desiredAccess, bool inheritHandle, uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetFileType(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(IntPtr handle, int fileInformationClass,
        out FileStandardInfo fileInformation, uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(IntPtr handle, StringBuilder path, uint pathLength, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    struct FileStandardInfo
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending;
        public byte Directory;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CommandLineToArgvW(string cmdLine, out int numArgs);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    static byte[] SubArray(byte[] src, int offset, int len)
    {
        byte[] r = new byte[len];
        Array.Copy(src, offset, r, 0, len);
        return r;
    }

    // Reads a remote UNICODE_STRING given the local copy of its containing struct (ppBuf) and
    // the byte offset within it where the UNICODE_STRING (Length:2, MaximumLength:2, pad:4, Buffer:8) starts.
    static string ReadRemoteUnicodeString(IntPtr h, byte[] ppBuf, int offset)
    {
        ushort length = BitConverter.ToUInt16(ppBuf, offset);
        if (length == 0) return "";

        long bufAddr = BitConverter.ToInt64(ppBuf, offset + 8);
        if (bufAddr == 0) return "";

        byte[] buf = new byte[length];
        int read;
        if (!ReadProcessMemory(h, new IntPtr(bufAddr), buf, length, out read) || read <= 0) return "";

        return Encoding.Unicode.GetString(buf, 0, read);
    }

    public ProcessDetails GetProcessDetails(int pid)
    {
        var details = new ProcessDetails();

        IntPtr h = OpenProcess(0x0410, false, pid); // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            details.Error = "ERROR: OpenProcess failed, code=" + err;
            return details;
        }
        try
        {
            byte[] pbi = new byte[48];
            int retLen;
            int status = NtQueryInformationProcess(h, 0, pbi, pbi.Length, out retLen);
            if (status != 0)
            {
                details.Error = "ERROR: NtQueryInformationProcess status=" + status;
                return details;
            }

            IntPtr pebAddr = new IntPtr(BitConverter.ToInt64(pbi, 8));

            // PROCESS_BASIC_INFORMATION (64-bit): InheritedFromUniqueProcessId is the parent PID,
            // at byte offset 40 (ExitStatus:8, PebBaseAddress:8, AffinityMask:8, BasePriority:8,
            // UniqueProcessId:8, InheritedFromUniqueProcessId:8). Already have this data in pbi,
            // no extra syscall needed.
            details.ParentPid = (int)BitConverter.ToInt64(pbi, 40);

            byte[] pebBuf = new byte[0x150];
            int read;
            if (!ReadProcessMemory(h, pebAddr, pebBuf, pebBuf.Length, out read))
            {
                details.Error = "ERROR: ReadProcessMemory(PEB) failed, code=" + Marshal.GetLastWin32Error();
                return details;
            }

            IntPtr procParamsAddr = new IntPtr(BitConverter.ToInt64(pebBuf, 0x20));

            byte[] ppBuf = new byte[0x100];
            if (!ReadProcessMemory(h, procParamsAddr, ppBuf, ppBuf.Length, out read))
            {
                details.Error = "ERROR: ReadProcessMemory(ProcParams) failed, code=" + Marshal.GetLastWin32Error();
                return details;
            }

            // RTL_USER_PROCESS_PARAMETERS (64-bit): CurrentDirectory.DosPath UNICODE_STRING at 0x38
            // (part of the embedded CURDIR struct), ImagePathName at 0x60, CommandLine at 0x70.
            details.CurrentDirectory = ReadRemoteUnicodeString(h, ppBuf, 0x38);
            details.ImagePath = ReadRemoteUnicodeString(h, ppBuf, 0x60);
            details.CommandLine = ReadRemoteUnicodeString(h, ppBuf, 0x70);

            IntPtr envAddr = new IntPtr(BitConverter.ToInt64(ppBuf, 0x80));

            int chunkSize = 4096;
            byte[] all = new byte[0];
            int totalRead = 0;
            int maxTotal = 1024 * 1024;
            bool foundEnd = false;
            while (!foundEnd && totalRead < maxTotal)
            {
                byte[] chunk = new byte[chunkSize];
                bool ok = ReadProcessMemory(h, new IntPtr(envAddr.ToInt64() + totalRead), chunk, chunkSize, out read);
                if (!ok || read == 0) break;
                byte[] newAll = new byte[all.Length + read];
                Array.Copy(all, newAll, all.Length);
                Array.Copy(chunk, 0, newAll, all.Length, read);
                all = newAll;
                totalRead += read;
                for (int i = 0; i + 3 < all.Length; i += 2)
                {
                    if (all[i] == 0 && all[i + 1] == 0 && all[i + 2] == 0 && all[i + 3] == 0)
                    {
                        foundEnd = true;
                        all = SubArray(all, 0, i + 2);
                        break;
                    }
                }
            }

            details.EnvBlock = Encoding.Unicode.GetString(all);
            return details;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    sealed class SystemHandleSnapshot
    {
        public Dictionary<int, List<IntPtr>> HandlesByPid = new();
        public string Error = "";
    }

    readonly Lazy<SystemHandleSnapshot> systemHandles = new(CaptureSystemHandles);

    static SystemHandleSnapshot CaptureSystemHandles()
    {
        var snapshot = new SystemHandleSnapshot();
        IntPtr handleTable = IntPtr.Zero;

        try
        {
            int bufferSize = 1024 * 1024;
            int status;
            int requiredSize;
            while (true)
            {
                handleTable = Marshal.AllocHGlobal(bufferSize);
                status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleTable, bufferSize, out requiredSize);
                if (status != STATUS_INFO_LENGTH_MISMATCH)
                    break;

                Marshal.FreeHGlobal(handleTable);
                handleTable = IntPtr.Zero;
                bufferSize = Math.Max(bufferSize * 2, requiredSize + 65536);
            }

            if (status != 0)
            {
                snapshot.Error = "ERROR: could not enumerate system handles, status=" + status;
                return snapshot;
            }

            ulong handleCount = unchecked((ulong)Marshal.ReadInt64(handleTable));
            const int headerSize = 16;
            const int entrySize = 40;

            for (ulong index = 0; index < handleCount; index++)
            {
                IntPtr entry = IntPtr.Add(handleTable, checked(headerSize + (int)(index * entrySize)));
                ulong ownerPid = unchecked((ulong)Marshal.ReadInt64(entry, 8));
                if (ownerPid > int.MaxValue)
                    continue;

                int pid = (int)ownerPid;
                if (!snapshot.HandlesByPid.TryGetValue(pid, out List<IntPtr> handles))
                {
                    handles = new List<IntPtr>();
                    snapshot.HandlesByPid.Add(pid, handles);
                }
                handles.Add(new IntPtr(Marshal.ReadInt64(entry, 16)));
            }
        }
        finally
        {
            if (handleTable != IntPtr.Zero)
                Marshal.FreeHGlobal(handleTable);
        }

        return snapshot;
    }

    public OpenFilesResult GetOpenFiles(int pid)
    {
        var result = new OpenFilesResult();
        SystemHandleSnapshot snapshot = systemHandles.Value;
        if (!string.IsNullOrEmpty(snapshot.Error))
        {
            result.Error = snapshot.Error;
            return result;
        }

        IntPtr processHandle = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
        if (processHandle == IntPtr.Zero)
        {
            result.Error = "ERROR: could not read open files for process " + pid +
                ", OpenProcess code=" + Marshal.GetLastWin32Error();
            return result;
        }

        try
        {
            var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            IntPtr currentProcess = GetCurrentProcess();
            if (!snapshot.HandlesByPid.TryGetValue(pid, out List<IntPtr> handles))
            {
                result.Files = Array.Empty<string>();
                return result;
            }

            foreach (IntPtr sourceHandle in handles)
            {
                if (!DuplicateHandle(processHandle, sourceHandle, currentProcess, out IntPtr localHandle,
                    0, false, DUPLICATE_SAME_ACCESS))
                    continue;

                try
                {
                    if (GetFileType(localHandle) != FILE_TYPE_DISK)
                        continue;

                    if (!GetFileInformationByHandleEx(localHandle, 1, out FileStandardInfo fileInfo,
                        (uint)Marshal.SizeOf<FileStandardInfo>()) || fileInfo.Directory != 0)
                        continue;

                    var path = new StringBuilder(32768);
                    uint pathLength = GetFinalPathNameByHandle(localHandle, path, (uint)path.Capacity, 0);
                    if (pathLength == 0 || pathLength >= path.Capacity)
                        continue;

                    string normalizedPath = NormalizeWindowsPath(path.ToString());
                    if (!string.IsNullOrEmpty(normalizedPath))
                        files.Add(normalizedPath);
                }
                finally
                {
                    CloseHandle(localHandle);
                }
            }

            result.Files = files.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
            return result;
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    static string NormalizeWindowsPath(string path)
    {
        const string extendedUncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";

        if (path.StartsWith(extendedUncPrefix, StringComparison.OrdinalIgnoreCase))
            return @"\\" + path.Substring(extendedUncPrefix.Length);
        if (path.StartsWith(extendedPrefix, StringComparison.OrdinalIgnoreCase))
            return path.Substring(extendedPrefix.Length);
        return path;
    }

    // Lightweight parent-PID lookup for ancestor-chain walking (--parents N/all): only opens
    // the process and reads PROCESS_BASIC_INFORMATION, skipping the PEB/env-block work that
    // GetProcessDetails does for the primary matched processes. Returns -1 on any failure.
    public int GetParentPidOnly(int pid)
    {
        IntPtr h = OpenProcess(0x0400, false, pid); // PROCESS_QUERY_INFORMATION
        if (h == IntPtr.Zero) return -1;
        try
        {
            byte[] pbi = new byte[48];
            int retLen;
            int status = NtQueryInformationProcess(h, 0, pbi, pbi.Length, out retLen);
            if (status != 0) return -1;
            return (int)BitConverter.ToInt64(pbi, 40);
        }
        finally
        {
            CloseHandle(h);
        }
    }

    // Parses a raw Win32 command-line string into argv, using the same rules the OS itself uses.
    public string[] ParseCommandLine(string cmdLine)
    {
        if (string.IsNullOrEmpty(cmdLine)) return Array.Empty<string>();

        int argc;
        IntPtr argv = CommandLineToArgvW(cmdLine, out argc);
        if (argv == IntPtr.Zero) return Array.Empty<string>();

        try
        {
            var result = new string[argc];
            for (int i = 0; i < argc; i++)
            {
                IntPtr strPtr = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                result[i] = Marshal.PtrToStringUni(strPtr) ?? "";
            }
            return result;
        }
        finally
        {
            LocalFree(argv);
        }
    }

    // Escapes a single argument per the standard Windows CommandLineToArgvW-compatible rules:
    // backslashes are only special immediately before a '"', and must be doubled there (plus one
    // more to escape the quote itself); a run of backslashes at the very end of the argument
    // (right before the closing quote we add) must also be doubled.
    public string EscapeArgumentForDisplay(string arg)
    {
        if (arg.Length != 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            return arg;

        var sb = new StringBuilder();
        sb.Append('"');

        for (int i = 0; i < arg.Length; )
        {
            int backslashes = 0;
            while (i < arg.Length && arg[i] == '\\')
            {
                backslashes++;
                i++;
            }

            if (i == arg.Length)
            {
                sb.Append('\\', backslashes * 2);
                break;
            }
            else if (arg[i] == '"')
            {
                sb.Append('\\', backslashes * 2 + 1);
                sb.Append('"');
                i++;
            }
            else
            {
                sb.Append('\\', backslashes);
                sb.Append(arg[i]);
                i++;
            }
        }

        sb.Append('"');
        return sb.ToString();
    }
}
