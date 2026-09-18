using System;

using System.Collections.Generic;
using System.Diagnostics;

// Everything px needs to know "about another process" that the OS doesn't hand you through
// ordinary managed APIs (env vars, raw command line, image path, cwd, parent pid) lives behind
// this seam. Windows, Linux, and macOS each expose this information through completely
// different mechanisms (undocumented PEB reads, /proc files, and libproc/sysctl calls,
// respectively) - but everything ABOVE this interface (arg parsing/filtering, --tree building,
// colorized rendering, run/shell/rerun launching via Process.Start) is 100% OS-agnostic and
// does not need to know which platform it's running on.
interface IProcessInspector
{
    // Reads env block, raw command line, image path, cwd, and parent pid for the given process.
    ProcessDetails GetProcessDetails(int pid);

    // Lists regular filesystem files currently open by the process. Directories, sockets,
    // pipes, devices, and other OS-specific handle/descriptor types are intentionally excluded.
    OpenFilesResult GetOpenFiles(int pid);

    // Lists TCP/UDP ports currently owned by the process. Not yet implemented on every
    // platform; the default falls back to a "not supported" error so callers don't need to
    // special-case platforms that haven't added a real implementation yet.
    OpenPortsResult GetOpenPorts(int pid) =>
        new OpenPortsResult { Error = "ERROR: --ports is not yet supported on this platform" };

    // Lightweight parent-PID-only lookup, used for ancestor-chain walking (--tree) where the
    // full env-block/PEB read would be wasted work.
    int GetParentPidOnly(int pid);

    // Splits a raw command-line string into argv, using whatever rule the target OS itself
    // uses to do so. On Windows this re-parses a single string (CommandLineToArgvW rules);
    // on Linux/macOS the OS already hands back an argv array (NUL-separated), so this is
    // effectively a no-op/passthrough there.
    string[] ParseCommandLine(string cmdLine);

    // Escapes a single argument for round-trip display/rerun in a way that's safe to paste
    // back into a shell on the current platform (Windows CommandLineToArgvW-compatible
    // quoting vs. POSIX shell quoting).
    string EscapeArgumentForDisplay(string arg);

    // The "friendly name" used for both display and name/substring/glob matching (e.g. 'px
    // bash', 'px 'cyco*''). Default implementation just uses Process.ProcessName, which is
    // fine on Windows (derived from the exe's image name, no length limit) but is overridden
    // on Linux to avoid the kernel's 15-char truncated "comm" field - see
    // LinuxProcessInspector.GetDisplayName for why that matters (e.g. "systemd-resolved" would
    // otherwise show/match as the truncated "systemd-resolve").
    string GetDisplayName(int pid) =>
        SafeProcessName(pid);

    protected static string SafeProcessName(int pid)
    {
        try { return System.Diagnostics.Process.GetProcessById(pid).ProcessName; }
        catch { return "?"; }
    }
}

class OpenFilesResult
{
    public IReadOnlyList<string> Files = Array.Empty<string>();
    public string Error = ""; // empty = no error (an empty Files list is valid)
}

class PortInfo
{
    public string Protocol = ""; // "TCP" or "UDP"
    public string LocalAddress = "";
    public int LocalPort;
    public string RemoteAddress = ""; // empty for UDP (connectionless)
    public int RemotePort; // 0 for UDP
    public string State = ""; // TCP connection state; empty for UDP
}

class OpenPortsResult
{
    public IReadOnlyList<PortInfo> Ports = Array.Empty<PortInfo>();
    public string Error = ""; // empty = no error (an empty Ports list is valid)
}

class ProcessDetails
{
    public string EnvBlock = "";
    public string ImagePath = "";
    public string CommandLine = "";
    public string CurrentDirectory = "";
    public string Error = ""; // empty = no error
    public int ParentPid = -1; // -1 = unknown/not read
}
