using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    // The one platform-conditional seam: everything needed to inspect ANOTHER process's private
    // state (env vars, raw command line, image path, cwd, parent pid, open files) lives behind this
    // interface, since Windows/Linux/macOS each expose it through totally different mechanisms.
    // Everything else below (arg parsing/filtering, --tree building, colorized rendering,
    // run/shell/rerun launching) is OS-agnostic and doesn't change per platform.
    static readonly IProcessInspector Inspector =
        OperatingSystem.IsWindows() ? new WindowsProcessInspector() :
        OperatingSystem.IsLinux() ? new LinuxProcessInspector() :
        OperatingSystem.IsMacOS() ? new MacProcessInspector() :
        throw new PlatformNotSupportedException("px is not supported on this operating system.");

    // --- True-color (24-bit RGB) support, borrowed from the cycodca Engine/AnsiColor.cs +
    // Highlighter.cs pattern (Atom One Dark palette). Falls back to the nearest 16-color
    // ConsoleColor on terminals that don't advertise true-color support, and skips coloring
    // entirely when output is redirected either way.

    readonly struct AnsiColor
    {
        public readonly byte R, G, B;
        public AnsiColor(int r, int g, int b) { R = (byte)r; G = (byte)g; B = (byte)b; }

        public string FgEscape() => $"\x1b[38;2;{R};{G};{B}m";
        public const string Reset = "\x1b[0m";

        public ConsoleColor ToConsoleColor()
        {
            var best = ConsoleColor.Gray;
            var bestDist = double.MaxValue;
            foreach (var (cc, cr, cg, cb) in _vgaPalette)
            {
                double dr = R - cr, dg = G - cg, db = B - cb;
                double d = dr * dr + dg * dg + db * db;
                if (d < bestDist) { bestDist = d; best = cc; }
            }
            return best;
        }

        static readonly (ConsoleColor CC, byte R, byte G, byte B)[] _vgaPalette =
        {
            (ConsoleColor.Black, 0, 0, 0),
            (ConsoleColor.DarkBlue, 0, 0, 128),
            (ConsoleColor.DarkGreen, 0, 128, 0),
            (ConsoleColor.DarkCyan, 0, 128, 128),
            (ConsoleColor.DarkRed, 128, 0, 0),
            (ConsoleColor.DarkMagenta, 128, 0, 128),
            (ConsoleColor.DarkYellow, 128, 128, 0),
            (ConsoleColor.Gray, 192, 192, 192),
            (ConsoleColor.DarkGray, 128, 128, 128),
            (ConsoleColor.Blue, 0, 0, 255),
            (ConsoleColor.Green, 0, 255, 0),
            (ConsoleColor.Cyan, 0, 255, 255),
            (ConsoleColor.Red, 255, 0, 0),
            (ConsoleColor.Magenta, 255, 0, 255),
            (ConsoleColor.Yellow, 255, 255, 0),
            (ConsoleColor.White, 255, 255, 255),
        };
    }

    static readonly bool SupportsTrueColor = DetectTrueColor();

    static bool DetectTrueColor()
    {
        var colorterm = Environment.GetEnvironmentVariable("COLORTERM");
        if (colorterm is "truecolor" or "24bit") return true;
        if (Environment.GetEnvironmentVariable("WT_SESSION") != null) return true;
        var termProg = Environment.GetEnvironmentVariable("TERM_PROGRAM");
        if (termProg is "iTerm.app" or "Hyper" or "vscode") return true;
        return false;
    }

    static void Write(string text, AnsiColor? color = null)
    {
        if (color == null || Console.IsOutputRedirected)
        {
            Console.Write(text);
            return;
        }

        if (SupportsTrueColor)
        {
            Console.Write(color.Value.FgEscape());
            Console.Write(text);
            Console.Write(AnsiColor.Reset);
        }
        else
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = color.Value.ToConsoleColor();
            Console.Write(text);
            Console.ForegroundColor = prev;
        }
    }

    static void WriteLine(string text = "", AnsiColor? color = null)
    {
        Write(text, color);
        Console.WriteLine();
    }

    // Atom One Dark palette (https://github.com/atom/one-dark-syntax), reused here to give each
    // kind of token (PID, path, option name/value, env name/value, ...) a distinct, semantically
    // meaningful color instead of the flat 16-color palette.
    static class Colors
    {
        public static readonly AnsiColor Header = new(0x61, 0xAF, 0xEF);      // function (blue)
        public static readonly AnsiColor Muted = new(0x5C, 0x63, 0x70);       // comment (muted blue-gray) - parens, path dir/ext
        public static readonly AnsiColor Pid = new(0x98, 0xC3, 0x79);         // string (green)
        public static readonly AnsiColor Name = new(0x61, 0xAF, 0xEF);        // function (blue) - process base name
        public static readonly AnsiColor Subcommand = new(0xC6, 0x78, 0xDD); // keyword (purple) - first bare arg after exe
        public static readonly AnsiColor OptName = new(0x56, 0xB6, 0xC2);     // operator (teal) - option prefix + name
        public static readonly AnsiColor OptValue = new(0xAB, 0xB2, 0xBF);    // variable (light gray) - option value
        public static readonly AnsiColor QuotedString = new(0x98, 0xC3, 0x79); // string (green) - quoted args/values
        public static readonly AnsiColor EnvName = new(0xE0, 0x6C, 0x75);     // attribute (red)
        public static readonly AnsiColor EnvValue = new(0xAB, 0xB2, 0xBF);    // variable (light gray)
        public static readonly AnsiColor Error = new(0xE0, 0x6C, 0x75);       // attribute/red
    }

    static readonly string[] FilterFlags = new[]
    {
        "--contains", "--env-contains", "--name-contains", "--env-name-contains", "--name-starts-with", "--env-name-starts-with",
        "--value-contains", "--env-value-contains", "--value-starts-with", "--env-value-starts-with"
    };

    static readonly string[] BooleanFlags = new[] { "--where", "--location", "--args", "--env", "--files", "--ports", "--pid", "--all", "--tree", "--cwd" };

    // --- Help-text colorizing helpers -----------------------------------------------------

    static readonly Regex InlineFlagPattern = new(@"(--[a-zA-Z][a-zA-Z0-9-]*)");

    // Highlights any --flag-looking word mentioned inline within a plain descriptive sentence.
    static void WriteBodyLine(string line)
    {
        var parts = InlineFlagPattern.Split(line);
        foreach (var part in parts)
        {
            if (part.StartsWith("--"))
                Write(part, Colors.OptName);
            else
                Console.Write(part);
        }
        Console.WriteLine();
    }

    static void WriteSectionHeader(string text) => WriteLine(text, Colors.Header);

    static List<string> TokenizeExample(string s)
    {
        var tokens = new List<string>();
        int i = 0;
        while (i < s.Length)
        {
            while (i < s.Length && s[i] == ' ') i++;
            if (i >= s.Length) break;

            int start = i;
            if (s[i] == '\'' || s[i] == '"')
            {
                char q = s[i];
                i++;
                while (i < s.Length && s[i] != q) i++;
                if (i < s.Length) i++;
            }
            else
            {
                while (i < s.Length && s[i] != ' ') i++;
            }
            tokens.Add(s.Substring(start, i - start));
        }
        return tokens;
    }

    // Colors a single example-command token using the same semantic rules as real px output:
    // quoted tokens -> QuotedString, numeric -> Pid, flags -> OptName(+OptValue), bare words
    // before the first flag -> Subcommand (process name/fragment target), bare words after
    // the first flag -> OptValue (a value belonging to the preceding flag).
    static void WriteExampleToken(string arg, ref bool seenOption)
    {
        if (arg.Length >= 2 && (arg[0] == '\'' || arg[0] == '"') && arg[^1] == arg[0])
        {
            Write(arg, Colors.QuotedString);
            return;
        }

        if (int.TryParse(arg, out _))
        {
            Write(arg, Colors.Pid);
            return;
        }

        bool isOption = arg.StartsWith("--") || arg.StartsWith("/") || arg.StartsWith("-");
        if (!isOption)
        {
            Write(arg, seenOption ? Colors.OptValue : Colors.Subcommand);
            return;
        }

        seenOption = true;
        int splitAt = arg.IndexOfAny(new[] { '=', ':' });
        string namePart = splitAt >= 0 ? arg.Substring(0, splitAt) : arg;
        string valuePart = splitAt >= 0 ? arg.Substring(splitAt) : "";

        Write(namePart, Colors.OptName);
        if (valuePart.Length > 0)
        {
            Write(valuePart.Substring(0, 1), Colors.Muted);
            Write(valuePart.Substring(1), Colors.OptValue);
        }
    }

    // Writes one fully-colorized "  px ... " example line, with an optional trailing
    // "(explanatory comment)" rendered in the muted comment color.
    static void WriteExampleLine(string command, string comment = "")
    {
        Write("  ");
        var tokens = TokenizeExample(command);
        bool seenOption = false;
        for (int i = 0; i < tokens.Count; i++)
        {
            if (i > 0) Write(" ");
            if (i == 0) { Write(tokens[i], Colors.Name); continue; } // "px" itself
            WriteExampleToken(tokens[i], ref seenOption);
        }

        if (!string.IsNullOrEmpty(comment))
        {
            Write("    ");
            Write(comment, Colors.Muted);
        }

        Console.WriteLine();
    }

    static void PrintUsage()
    {
        WriteLine("px - inspect running processes: list PIDs, exe paths, command lines, env vars, and open files", Colors.Header);
        Console.WriteLine();
        WriteSectionHeader("USAGE:");
        Console.WriteLine("  px <pid|process-name|name-fragment> [...] [<filter-value> ...] [<filter-flag> <value> [<value> ...]] ...");
        Console.WriteLine("  px --tree|--args|--env|... (with no target - implies '*', i.e. every process)");
        Console.WriteLine("  px <pid> shell");
        Console.WriteLine("  px <pid> run [--] <command> [<arg> ...]");
        Console.WriteLine("  px <pid> rerun");
        Console.WriteLine();
        WriteSectionHeader("PROCESS ACTIONS:");
        Console.WriteLine("  shell   start the nearest shell found in the process ancestry, using the target");
        Console.WriteLine("          process's current directory and environment");
        Console.WriteLine("  run     run a command using the target process's current directory and environment;");
        Console.WriteLine("          the conventional -- separator is supported but optional");
        Console.WriteLine("  rerun   run the target's original executable and arguments again, using its current");
        Console.WriteLine("          directory and environment");
        Console.WriteLine();
        WriteSectionHeader("HOW PROCESS TARGETS ARE RESOLVED (in order):");
        Console.WriteLine("  1. Numeric token           -> treated as a PID");
        Console.WriteLine("  2. Exact process name match -> that process (case-insensitive)");
        Console.WriteLine("  3. Token has '*' or '?'     -> glob match against process names (e.g. 'cyco*')");
        Console.WriteLine("  4. If NOTHING matched yet   -> try remaining tokens as name substrings (e.g. 'chrome')");
        Console.WriteLine();
        WriteSectionHeader("HOW LEFTOVER TOKENS BECOME ENV-VAR FILTERS:");
        Console.WriteLine("  Once at least one process target is resolved, any leftover token filters env vars");
        Console.WriteLine("  by NAME, in this order:");
        Console.WriteLine("    1. Token has '*' or '?'        -> glob match against variable names");
        Console.WriteLine("    2. Exact match (case-sensitive) -> used if one exists");
        Console.WriteLine("    3. Exact match (case-insensitive) -> used only if no case-sensitive match exists");
        Console.WriteLine("    (no substring/prefix guessing otherwise)");
        Console.WriteLine();
        WriteSectionHeader("OTHER FLAGS:");
        WriteBodyLine("  --pid       always show (PID) on the main line, even with --location/--args");
        WriteBodyLine("  --location  show the full path to each process's executable");
        WriteBodyLine("  --args      show the process's command-line args (fancy-colored) on the main line");
        WriteBodyLine("  --env       after everything else, show ALL environment variables for each process");
        WriteBodyLine("  --files     show regular files currently open by each process");
        WriteBodyLine("  --ports     show TCP/UDP ports currently open by each process");
        WriteBodyLine("  --all       also show processes with no matching environment variables (see below)");
        WriteBodyLine("  --tree      show each matched process's full ancestry as a real tree (see below)");
        WriteBodyLine("  --cwd       show the process's current working directory right on its main line");
        WriteBodyLine("  --where     alias for BOTH --location AND --cwd together (\"where\" the thing is, and");
        WriteBodyLine("              \"where\" it's running)");
        Console.WriteLine();
        WriteBodyLine("  By default (neither --location nor --args) the main line is '(PID)  name' (with a");
        WriteBodyLine("  '.exe' suffix on Windows). --location alone shows the full path instead of the");
        WriteBodyLine("  PID/name. --args alone shows 'name <args>' instead of the PID. Add --pid to force the");
        WriteBodyLine("  PID to show either way. If BOTH --location and --args are given, the main line is");
        WriteBodyLine("  'name <args>' and the");
        WriteBodyLine("  full path is shown on its own indented line underneath. --cwd appends '  (<cwd>)' right");
        WriteBodyLine("  on the main line, after the args (or after the base name if no args) - this also means");
        WriteBodyLine("  it shows up per-node when combined with --tree.");
        Console.WriteLine();
        WriteSectionHeader("TREE MODE (--tree):");
        WriteBodyLine("  Walks each matched process's ancestry (parent, grandparent, etc.) as far as it can be");
        WriteBodyLine("  traced, merging shared ancestors so two matched processes under the same parent appear");
        WriteBodyLine("  as two branches of one tree, not two separate trees. Distinct ancestries with no common");
        WriteBodyLine("  ancestor are printed as separate root trees (a forest), each block separated by a blank");
        WriteBodyLine("  line. Matched PIDs are shown in the PID color; ancestor-only PIDs are muted. If --args");
        WriteBodyLine("  is also given, each tree node shows its command-line args too.");
        Console.WriteLine();
        WriteBodyLine("  A matched process whose parent has already exited (or has no parent at all) isn't");
        WriteBodyLine("  shown as a trivial one-node tree - instead it's listed at the end with either");
        WriteBodyLine("  '(dead parent <PID>)' (in red) or '(no parent)'.");
        Console.WriteLine();
        WriteBodyLine("  The normal top list is SKIPPED when --tree is given, since the tree (with --args if");
        WriteBodyLine("  requested) already shows everything it would - UNLESS --location (or --where), --files,");
        WriteBodyLine("  --ports, or any env-showing flag is also given, since those show info the tree view doesn't.");
        Console.WriteLine();
        WriteSectionHeader("ENV FILTER FLAGS (each implies --env; accepts one or more values, OR'd together):");
        WriteBodyLine("  --env-contains <value> [<value> ...]          (matches if NAME or VALUE contains it)");
        WriteBodyLine("  --env-name-contains <value> [<value> ...]");
        WriteBodyLine("  --env-name-starts-with <value> [<value> ...]");
        WriteBodyLine("  --env-value-contains <value> [<value> ...]");
        WriteBodyLine("  --env-value-starts-with <value> [<value> ...]");
        Console.WriteLine();
        WriteBodyLine("  Shorter aliases (--contains, --name-contains, --name-starts-with, --value-contains,");
        WriteBodyLine("  --value-starts-with) are also accepted for all of the above.");
        Console.WriteLine();
        Console.WriteLine("  A leftover positional token (not resolved to a process) also implies --env and acts");
        Console.WriteLine("  as an env-var NAME filter (see below).");
        Console.WriteLine();
        WriteBodyLine("  When any env filter is active (--env-* flags or a leftover token), processes with NO");
        WriteBodyLine("  matching environment variables are excluded from the whole list. Pass --all to");
        WriteBodyLine("  override this and show every matched process regardless of env filter results.");
        Console.WriteLine();
        WriteSectionHeader("EXAMPLE:");
        WriteExampleLine("px 12345 shell", "(open the nearest ancestor shell in PID 12345's context)");
        WriteExampleLine("px 12345 run -- git status", "(run git with PID 12345's cwd and environment)");
        WriteExampleLine("px 12345 rerun", "(run PID 12345's original command again)");
        WriteExampleLine("px 12345");
        WriteExampleLine("px 12345 67890");
        WriteExampleLine("px chrome");
        WriteExampleLine("px chrome notepad");
        WriteExampleLine("px 'cyco*' --location");
        WriteExampleLine("px 'cyco*' --args");
        WriteExampleLine("px 'cyco*' --location --args");
        WriteExampleLine("px 'cyco*' --where", "(same as --location --cwd together)");
        WriteExampleLine("px cycodd --env");
        WriteExampleLine("px cycodd --files", "(show regular files currently open by each process)");
        WriteExampleLine("px cycodd --ports", "(show TCP/UDP ports currently open by each process)");
        WriteExampleLine("px cycodd CYCODD_DAEMON_CHILD", "(implicit exact-match env var name filter, implies --env)");
        WriteExampleLine("px cycodd 'CYCODD_*'", "(implicit glob env var name filter, implies --env)");
        WriteExampleLine("px cycodd --env-name-contains PATH TEMP");
        WriteExampleLine("px cycodd --env-value-contains localhost");
        WriteExampleLine("px cycodd --env-contains BLH", "(matches if var NAME or VALUE contains 'BLH')");
        WriteExampleLine("px cycodd --env-name-contains DAEMON --all", "(show every process, even ones with no match)");
        WriteExampleLine("px 'cyco*' --tree", "(show all matched processes as a single ancestry tree/forest)");
        WriteExampleLine("px cycodd --cwd", "(show each process's current working directory)");
        WriteExampleLine("px 'cyco*' --tree --cwd", "(cwd shown per-node in the tree too)");
    }

    // The "friendly name" used for display and matching, delegated to the platform inspector -
    // on Linux/macOS this avoids the kernel's truncated "comm" field (see
    // LinuxProcessInspector.GetDisplayName); on Windows it's just Process.ProcessName.
    static string GetProcessNameSafe(int pid) => Inspector.GetDisplayName(pid);

    // Cached once per run: the full snapshot of currently-running PIDs, from Process.GetProcesses().
    // Used instead of opening each individual process handle to check aliveness, since
    // Process.GetProcessById(pid).HasExited requires SYNCHRONIZE access - which can be denied for
    // protected/system processes (e.g. a SYSTEM-owned svchost.exe) even when they ARE alive,
    // causing them to be misreported as "exited" (dead parent) when they're not.
    static readonly Lazy<HashSet<int>> LivePids = new(() =>
        new HashSet<int>(Process.GetProcesses().Select(p => p.Id)));

    static bool IsProcessAlive(int pid) => LivePids.Value.Contains(pid);



    // Named entry type for a resolved+filtered process, replacing the anonymous type previously
    // returned by the LINQ projection - needed so tree mode can reference matched entries by PID
    // when building the ancestor forest.
    class MatchedEntry
    {
        public int Pid;
        public ProcessDetails Details = new();
        public string ShortName = "";
        public string[] RestArgs = Array.Empty<string>();
        public string Cwd = "";
        public string SortKey = "";
        public (string Raw, string Name, string Value)[] ParsedVars = Array.Empty<(string, string, string)>();
        public int EnvMatchCount;
        public OpenFilesResult OpenFiles = new();
        public OpenPortsResult OpenPorts = new();
    }

    class ParsedArgs
    {
        public SortedSet<int> Pids = new SortedSet<int>();
        public List<string> Contains = new List<string>();
        public List<string> NameContains = new List<string>();
        public List<string> NameStartsWith = new List<string>();
        public List<string> ValueContains = new List<string>();
        public List<string> ValueStartsWith = new List<string>();
        public bool ShowLocation = false;
        public bool ShowArgs = false;
        public bool ShowEnvExplicit = false;
        public bool ShowFiles = false;
        public bool ShowPorts = false;
        public bool ShowPidExplicit = false;
        public bool ShowAll = false;
        public bool ShowTree = false;
        public bool ShowCwd = false;

        // Leftover tokens (not resolved to a process): matched against env var NAMES using
        // an exact-first progression (see CompileImplicitFilters), NOT contains/starts-with,
        // unless the token itself contains '*'/'?'.
        public List<string> ImplicitFilters = new List<string>();
        public List<string> UnresolvedTargets = new List<string>();

        public bool HasFilters =>
            Contains.Count > 0 ||
            NameContains.Count > 0 || NameStartsWith.Count > 0 ||
            ValueContains.Count > 0 || ValueStartsWith.Count > 0 ||
            ImplicitFilters.Count > 0;

        // Env vars are shown if --env was given explicitly, OR any env filter (implicit or
        // explicit --env-*) was given - filters imply you want to see the (filtered) env vars.
        public bool ShouldShowEnv => ShowEnvExplicit || HasFilters;

        // When --env is given with NO filters at all, show everything (unfiltered).
        public bool ShowEnvAll => ShowEnvExplicit && !HasFilters;
    }

    // Windows executables conventionally get a ".exe" suffix appended for display (matching
    // what you'd type at a shell prompt); Linux/macOS executables have no such convention, so
    // the suffix would look nonsensical there (e.g. "bash.exe" instead of "bash").
    static readonly string ExeSuffix = OperatingSystem.IsWindows() ? ".exe" : "";

    // Process.ProcessName never includes the ".exe" extension, so strip a trailing ".exe"
    // (case-insensitive) from a token before comparing it against process names - lets
    // 'px cycod.exe' work the same as 'px cycod'. Only meaningful on Windows; a no-op elsewhere
    // since there's no suffix convention to strip.
    static string StripExeSuffix(string arg) =>
        ExeSuffix.Length > 0 && arg.EndsWith(ExeSuffix, StringComparison.OrdinalIgnoreCase) ? arg.Substring(0, arg.Length - ExeSuffix.Length) : arg;

    static Regex GlobToRegex(string glob)
    {
        var sb = new StringBuilder("^");
        foreach (var c in glob)
        {
            if (c == '*') sb.Append(".*");
            else if (c == '?') sb.Append('.');
            else sb.Append(Regex.Escape(c.ToString()));
        }
        sb.Append('$');
        return new Regex(sb.ToString(), RegexOptions.IgnoreCase);
    }

    static ParsedArgs ParseArgs(string[] args)
    {
        var result = new ParsedArgs();
        var allProcesses = Process.GetProcesses();
        var pending = new List<string>();

        // Match names/globs/substrings against the platform's "friendly name" (Inspector.GetDisplayName)
        // rather than Process.ProcessName directly - on Linux/macOS that avoids the kernel's
        // 15-char-truncated "comm" field breaking lookups like 'px resolved' for
        // 'systemd-resolved' (see LinuxProcessInspector.GetDisplayName). Computed once per PID
        // since it involves file I/O on Linux/macOS.
        var displayNames = allProcesses.ToDictionary(p => p.Id, p => Inspector.GetDisplayName(p.Id));

        // Tracks whether any token was actually an attempt at specifying a target (a PID, a
        // glob, a bare name) as opposed to purely recognized flags (e.g. 'px --tree' alone).
        // Used below to default to "all processes" when the user supplied flags only and never
        // tried to name a target at all - as opposed to naming one that simply didn't match
        // anything (a likely typo), which should still produce today's explicit error.
        bool sawTargetToken = false;

        // Pass 1: handle filter flags, numeric PIDs, and exact process-name matches
        // immediately (these are unambiguous). Anything else is deferred to "pending".
        int i = 0;
        while (i < args.Length)
        {
            var arg = args[i];

            var argLower = arg.ToLowerInvariant();

            if (argLower == "--location")
            {
                result.ShowLocation = true;
                i++;
                continue;
            }

            if (argLower == "--where")
            {
                // --where is an alias for BOTH --location and --cwd: "where" the thing IS
                // (its exe path) and "where" it's running (its current working directory).
                result.ShowLocation = true;
                result.ShowCwd = true;
                i++;
                continue;
            }

            if (argLower == "--args")
            {
                result.ShowArgs = true;
                i++;
                continue;
            }

            if (argLower == "--env")
            {
                result.ShowEnvExplicit = true;
                i++;
                continue;
            }

            if (argLower == "--files")
            {
                result.ShowFiles = true;
                i++;
                continue;
            }

            if (argLower == "--ports")
            {
                result.ShowPorts = true;
                i++;
                continue;
            }

            if (argLower == "--pid")
            {
                result.ShowPidExplicit = true;
                i++;
                continue;
            }

            if (argLower == "--all")
            {
                result.ShowAll = true;
                i++;
                continue;
            }

            if (argLower == "--tree")
            {
                result.ShowTree = true;
                i++;
                continue;
            }

            if (argLower == "--cwd")
            {
                result.ShowCwd = true;
                i++;
                continue;
            }

            if (Array.IndexOf(FilterFlags, argLower) >= 0)
            {
                var target = arg.ToLowerInvariant() switch
                {
                    "--contains" or "--env-contains" => result.Contains,
                    "--name-contains" or "--env-name-contains" => result.NameContains,
                    "--name-starts-with" or "--env-name-starts-with" => result.NameStartsWith,
                    "--value-contains" or "--env-value-contains" => result.ValueContains,
                    "--value-starts-with" or "--env-value-starts-with" => result.ValueStartsWith,
                    _ => null
                };
                i++;
                while (i < args.Length &&
                       Array.IndexOf(FilterFlags, args[i].ToLowerInvariant()) < 0 &&
                       Array.IndexOf(BooleanFlags, args[i].ToLowerInvariant()) < 0)
                {
                    target!.Add(args[i]);
                    i++;
                }
                continue;
            }

            int pid;
            if (int.TryParse(arg, out pid))
            {
                sawTargetToken = true;
                result.Pids.Add(pid);
                i++;
                continue;
            }

            if (arg.IndexOf('*') >= 0 || arg.IndexOf('?') >= 0)
            {
                sawTargetToken = true;
                // Explicit wildcard: try it as a process-name glob first (unconditionally,
                // regardless of whether other exact matches already exist). If it matches
                // zero processes, don't discard it - let it fall through to "pending" so it
                // can still be used as an env-var-name glob filter (e.g. 'CYCODD_*').
                var regex = GlobToRegex(StripExeSuffix(arg));
                var globMatches = allProcesses.Where(p => regex.IsMatch(displayNames[p.Id])).ToArray();
                if (globMatches.Length > 0)
                {
                    foreach (var p in globMatches) result.Pids.Add(p.Id);
                    i++;
                    continue;
                }

                pending.Add(arg);
                i++;
                continue;
            }

            var exactMatches = allProcesses.Where(p => string.Equals(displayNames[p.Id], StripExeSuffix(arg), StringComparison.OrdinalIgnoreCase)).ToArray();
            sawTargetToken = true;
            if (exactMatches.Length > 0)
            {
                foreach (var p in exactMatches) result.Pids.Add(p.Id);
                i++;
                continue;
            }

            pending.Add(arg);
            i++;
        }

        // Pass 2: if we already have definite targets (from PIDs or exact name matches),
        // any remaining "pending" tokens are unambiguously filters - no fragment stealing.
        // Only if we have NO definite targets yet do we fall back to fragment/substring
        // matching against process names, so a lone token like "chrome" still works.
        if (result.Pids.Count == 0)
        {
            var stillPending = new List<string>();
            foreach (var arg in pending)
            {
                var substringMatches = allProcesses.Where(p => displayNames[p.Id].IndexOf(StripExeSuffix(arg), StringComparison.OrdinalIgnoreCase) >= 0).ToArray();
                if (substringMatches.Length > 0)
                    foreach (var p in substringMatches) result.Pids.Add(p.Id);
                else
                    stillPending.Add(arg);
            }
            pending = stillPending;
        }

        foreach (var arg in pending)
        {
            result.ImplicitFilters.Add(arg);
            result.UnresolvedTargets.Add(arg);
        }

        // Flags-only invocation (e.g. 'px --tree'): no token was ever an attempt at naming a
        // target, so default to "all processes" - the same as if '*' had been typed explicitly.
        // A token that WAS an attempt but matched nothing (a likely typo) still falls through to
        // the normal "no PID and no running process matched" error in Main, since sawTargetToken
        // is true in that case.
        if (!sawTargetToken && result.Pids.Count == 0)
            foreach (var p in allProcesses) result.Pids.Add(p.Id);

        return result;
    }

    // For each implicit (leftover) filter token, decide its match strategy against the
    // ACTUAL variable names of one specific process:
    //   1. Token has '*' or '?'  -> glob match (case-insensitive), can match multiple names.
    //   2. Else, if some var name equals the token exactly (case-sensitive)  -> use that,
    //      i.e. do NOT fall back to case-insensitive matching.
    //   3. Else, if some var name equals the token exactly (case-insensitive) -> use that.
    //   4. Else -> token matches nothing for this process (no contains/starts-with fallback).
    static List<Func<string, bool>> CompileImplicitFilters(List<string> tokens, string[] varNames)
    {
        var predicates = new List<Func<string, bool>>();
        foreach (var token in tokens)
        {
            if (token.IndexOf('*') >= 0 || token.IndexOf('?') >= 0)
            {
                var regex = GlobToRegex(token);
                predicates.Add(name => regex.IsMatch(name));
                continue;
            }

            var t = token;
            if (varNames.Any(n => string.Equals(n, t, StringComparison.Ordinal)))
            {
                predicates.Add(name => string.Equals(name, t, StringComparison.Ordinal));
                continue;
            }

            if (varNames.Any(n => string.Equals(n, t, StringComparison.OrdinalIgnoreCase)))
            {
                predicates.Add(name => string.Equals(name, t, StringComparison.OrdinalIgnoreCase));
                continue;
            }

            predicates.Add(name => false);
        }
        return predicates;
    }

    static bool PassesFilters(ParsedArgs parsed, string name, string value, List<Func<string, bool>> compiledImplicit)
    {
        if (!parsed.HasFilters)
            return true;

        if (parsed.Contains.Any(f => name.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)) return true;
        if (parsed.NameContains.Any(f => name.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)) return true;
        if (parsed.NameStartsWith.Any(f => name.StartsWith(f, StringComparison.OrdinalIgnoreCase))) return true;
        if (parsed.ValueContains.Any(f => value.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)) return true;
        if (parsed.ValueStartsWith.Any(f => value.StartsWith(f, StringComparison.OrdinalIgnoreCase))) return true;
        if (compiledImplicit.Any(p => p(name))) return true;

        return false;
    }

    // Writes a filesystem path with the directory portion and file extension muted, and just
    // the filename's base (no dir, no extension) in the "Name" color -
    // e.g. C:\dir\ (muted) cycod (blue) .exe (muted).
    static void WriteExePathColored(string display)
    {
        int lastSlash = display.LastIndexOfAny(new[] { '\\', '/' });
        string dirPart = lastSlash >= 0 ? display.Substring(0, lastSlash + 1) : "";
        string fileName = lastSlash >= 0 ? display.Substring(lastSlash + 1) : display;

        int lastDot = fileName.LastIndexOf('.');
        string baseName = lastDot > 0 ? fileName.Substring(0, lastDot) : fileName;
        string ext = lastDot > 0 ? fileName.Substring(lastDot) : "";

        Write(dirPart, Colors.Muted);
        Write(baseName, Colors.Name);
        Write(ext, Colors.Muted);
    }

    // Writes a single already-escaped command-line argument with "fancy" One-Dark-inspired
    // coloring, tracking a single "seenOption" phase flag across the whole arg list:
    //   - quoted args (start with '"')                -> always QuotedString (green), in
    //                                                     either phase
    //   - before the FIRST -, --, or / prefixed arg    -> bare/unquoted args are the leading
    //                                                     "noun/verb" run (e.g. 'cycodd start')
    //                                                     -> Subcommand (purple)
    //   - once any -, --, or / prefixed arg is seen    -> we're in "option land" from then on:
    //       - prefixed args   -> prefix+name in OptName (blue), value after '='/':' in
    //                            OptValue (orange), or QuotedString if that value is quoted
    //       - bare args       -> treated as a value for the preceding option (e.g. 'en-US'
    //                            after '--lang') -> OptValue (orange)
    static void WriteArgColored(string arg, ref bool seenOption)
    {
        if (arg.StartsWith("\""))
        {
            Write(arg, Colors.QuotedString);
            return;
        }

        bool isOption = arg.StartsWith("--") || arg.StartsWith("/") || arg.StartsWith("-");

        if (!isOption)
        {
            Write(arg, seenOption ? Colors.OptValue : Colors.Subcommand);
            return;
        }

        seenOption = true;

        int splitAt = arg.IndexOfAny(new[] { '=', ':' });
        string namePart = splitAt >= 0 ? arg.Substring(0, splitAt) : arg;
        string valuePart = splitAt >= 0 ? arg.Substring(splitAt) : "";

        Write(namePart, Colors.OptName);
        if (valuePart.Length > 0)
        {
            var sep = valuePart[0];
            var valueRest = valuePart.Substring(1);
            Write(sep.ToString(), Colors.Muted);
            Write(valueRest, valueRest.StartsWith("\"") ? Colors.QuotedString : Colors.OptValue);
        }
    }

    static int SafeConsoleWidth()
    {
        try
        {
            return Console.IsOutputRedirected ? 0 : Console.WindowWidth;
        }
        catch
        {
            return 0;
        }
    }

    // --- Tree mode (--tree): build a real ancestry tree/forest out of the matched PIDs -------
    //
    // For each matched PID, walk up via GetParentPidOnly() until we hit a PID that's exited
    // (dead parents are NOT included as nodes - we simply treat that PID as if it had no
    // parent at all, since there's nothing meaningful left to show about it), has no further
    // parent, or that we've already seen (cycle guard). Any PID visited along the way (matched
    // or merely a still-alive ancestor) becomes a node; nodes are merged by PID so that two
    // matched processes sharing an ancestor produce ONE tree with two leaves, not two separate
    // trees. The result is a forest: one root per distinct ancestry line that has no further
    // living parent to climb to. Roots that have at least one child are printed as trees, each
    // separated by a blank line. Matched PIDs that end up as childless roots (no live parent,
    // and nothing else chains up through them) are NOT printed as their own trivial one-node
    // trees - they're collected and listed separately at the end under "no parent".

    class TreeNode
    {
        public int Pid;
        public bool IsMatched;      // true if this PID is one of the original matched/filtered entries
        public string Name = "";
        public string[] RestArgs = Array.Empty<string>();
        public string Cwd = "";
        public bool HasParent = false;
        public int? DeadParentPid = null; // set when a parent PID was found but has since exited
        public List<TreeNode> Children = new();
    }

    static (List<TreeNode> Trees, List<TreeNode> NoParent) BuildForest(MatchedEntry[] entries, bool includeArgs, bool includeCwd)
    {
        var nodesByPid = new Dictionary<int, TreeNode>();

        TreeNode GetOrCreateNode(int pid)
        {
            if (nodesByPid.TryGetValue(pid, out var existing)) return existing;
            var node = new TreeNode { Pid = pid };
            nodesByPid[pid] = node;
            return node;
        }

        foreach (var e in entries)
        {
            var node = GetOrCreateNode(e.Pid);
            node.IsMatched = true;
            node.Name = e.ShortName;
            node.RestArgs = e.RestArgs;
            node.Cwd = e.Cwd;
        }

        // Walk up from each matched PID, linking parent/child as we go, until we hit a dead
        // (exited) parent - recorded on the child as DeadParentPid but not added as a node in
        // its own right, since there's nothing meaningful left to show about it - a PID with
        // no further parent, or one we've already climbed through (cycle guard against PID reuse).
        foreach (var e in entries)
        {
            var child = nodesByPid[e.Pid];
            var visited = new HashSet<int> { child.Pid };

            while (!child.HasParent)
            {
                int parentPid = Inspector.GetParentPidOnly(child.Pid);
                if (parentPid <= 0 || !visited.Add(parentPid)) break;

                if (!IsProcessAlive(parentPid))
                {
                    child.DeadParentPid = parentPid;
                    break;
                }

                var parentNode = GetOrCreateNode(parentPid);
                if (string.IsNullOrEmpty(parentNode.Name))
                {
                    if (includeArgs || includeCwd)
                    {
                        var det = Inspector.GetProcessDetails(parentPid);
                        if (includeArgs)
                        {
                            var argv = Inspector.ParseCommandLine(det.CommandLine);
                            parentNode.RestArgs = argv.Length > 1 ? argv.Skip(1).Select(Inspector.EscapeArgumentForDisplay).ToArray() : Array.Empty<string>();
                        }
                        if (includeCwd)
                            parentNode.Cwd = det.CurrentDirectory;
                    }
                    parentNode.Name = GetProcessNameSafe(parentPid) + ExeSuffix;
                }

                child.HasParent = true;
                if (!parentNode.Children.Contains(child))
                    parentNode.Children.Add(child);

                child = parentNode;
            }
        }

        var roots = nodesByPid.Values.Where(n => !n.HasParent).OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var trees = roots.Where(n => n.Children.Count > 0).ToList();
        var noParent = roots.Where(n => n.Children.Count == 0 && n.IsMatched).OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase).ToList();
        return (trees, noParent);
    }

    // Writes "  (<cwd>)" after a process's name/args, muted/dark-gray throughout.
    static void WriteCwdSuffix(string cwd)
    {
        if (string.IsNullOrEmpty(cwd)) return;
        Write("  ");
        Write("(", Colors.Muted);
        Write(cwd, Colors.Muted);
        Write(")", Colors.Muted);
    }

    static void WriteTreeNodeLabel(TreeNode node, bool showArgs, bool showCwd)
    {
        if (showArgs)
        {
            Write(node.Name, Colors.Name);
            bool seenOption = false;
            foreach (var a in node.RestArgs)
            {
                Write(" ");
                WriteArgColored(a, ref seenOption);
            }
        }
        else
        {
            WriteExePathColored(node.Name);
        }
    }

    static void PrintTreeNode(TreeNode node, string prefix, bool isLast, bool isRoot, bool showArgs, bool showCwd)
    {
        if (!isRoot)
        {
            Write(prefix, Colors.Muted);
            Write(isLast ? "└─ " : "├─ ", Colors.Muted);
        }

        Write("(", Colors.Muted);
        Write(node.Pid.ToString(), node.IsMatched ? Colors.Pid : Colors.Muted);
        Write(")", Colors.Muted);
        Write("  ");
        WriteTreeNodeLabel(node, showArgs, showCwd);
        if (showCwd) WriteCwdSuffix(node.Cwd);
        Console.WriteLine();

        var childPrefix = isRoot ? "" : prefix + (isLast ? "   " : "│  ");
        for (int i = 0; i < node.Children.Count; i++)
            PrintTreeNode(node.Children[i], childPrefix, i == node.Children.Count - 1, isRoot: false, showArgs, showCwd);
    }

    static void PrintForest(MatchedEntry[] entries, bool showArgs, bool showCwd)
    {
        var (trees, noParent) = BuildForest(entries, showArgs, showCwd);

        for (int i = 0; i < trees.Count; i++)
        {
            if (i > 0) Console.WriteLine();
            PrintTreeNode(trees[i], "", true, isRoot: true, showArgs, showCwd);
        }

        if (noParent.Count > 0)
        {
            if (trees.Count > 0) Console.WriteLine();
            foreach (var node in noParent)
            {
                Write("(", Colors.Muted);
                Write(node.Pid.ToString(), Colors.Pid);
                Write(")", Colors.Muted);
                Write("  ");
                WriteTreeNodeLabel(node, showArgs, showCwd);
                if (showCwd) WriteCwdSuffix(node.Cwd);
                Write("  ");
                if (node.DeadParentPid.HasValue)
                {
                    Write("(dead parent ", Colors.Muted);
                    Write(node.DeadParentPid.Value.ToString(), Colors.Error);
                    Write(")", Colors.Muted);
                    Console.WriteLine();
                }
                else
                {
                    WriteLine("(no parent)", Colors.Muted);
                }
            }
        }
    }

    static readonly HashSet<string> ShellProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "bash", "zsh", "fish", "sh"
    };

    static Dictionary<string, string> ParseEnvironmentBlock(string environmentBlock)
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string entry in environmentBlock.Split('\0', StringSplitOptions.RemoveEmptyEntries))
        {
            // Win32 environment blocks can contain hidden entries such as "=C:=C:\\work".
            // ProcessStartInfo does not accept those pseudo-variable names, and they are not
            // ordinary environment variables inherited by applications.
            int separator = entry.IndexOf('=', entry.StartsWith("=", StringComparison.Ordinal) ? 1 : 0);
            if (separator <= 0) continue;
            environment[entry.Substring(0, separator)] = entry.Substring(separator + 1);
        }
        return environment;
    }

    static string ExpandEnvironmentVariables(string value, IReadOnlyDictionary<string, string> environment)
    {
        return Regex.Replace(value, "%([^%]+)%", match =>
            environment.TryGetValue(match.Groups[1].Value, out string expanded) ? expanded : match.Value);
    }

    static string ResolveExecutable(string command, ProcessDetails target, IReadOnlyDictionary<string, string> environment)
    {
        bool hasDirectory = command.IndexOfAny(new[] { '\\', '/' }) >= 0;
        string[] extensions;
        if (System.IO.Path.HasExtension(command))
        {
            extensions = new[] { "" };
        }
        else
        {
            string pathExt = environment.TryGetValue("PATHEXT", out string configuredPathExt)
                ? configuredPathExt
                : ".COM;.EXE;.BAT;.CMD";
            extensions = new[] { "" }.Concat(pathExt.Split(';', StringSplitOptions.RemoveEmptyEntries)).ToArray();
        }

        IEnumerable<string> directories;
        if (hasDirectory)
        {
            string candidate = System.IO.Path.IsPathRooted(command)
                ? command
                : System.IO.Path.Combine(target.CurrentDirectory, command);
            directories = new[] { System.IO.Path.GetDirectoryName(candidate) ?? target.CurrentDirectory };
            command = System.IO.Path.GetFileName(candidate);
        }
        else
        {
            string path = environment.TryGetValue("PATH", out string configuredPath) ? configuredPath : "";
            directories = new[] { target.CurrentDirectory }
                .Concat(path.Split(';', StringSplitOptions.RemoveEmptyEntries));
        }

        foreach (string directory in directories)
        {
            string expandedDirectory = ExpandEnvironmentVariables(directory.Trim().Trim('"'), environment);
            foreach (string extension in extensions)
            {
                string candidate = System.IO.Path.Combine(expandedDirectory, command + extension);
                if (System.IO.File.Exists(candidate)) return System.IO.Path.GetFullPath(candidate);
            }
        }

        return command;
    }

    static int LaunchInProcessContext(ProcessDetails target, string executable, IEnumerable<string> arguments)
    {
        if (!string.IsNullOrEmpty(target.Error))
        {
            WriteLine(target.Error, Colors.Error);
            return 1;
        }
        if (string.IsNullOrEmpty(target.CurrentDirectory) || string.IsNullOrEmpty(target.EnvBlock))
        {
            WriteLine("ERROR: could not read the target process's current directory or environment", Colors.Error);
            return 1;
        }

        Dictionary<string, string> environment = ParseEnvironmentBlock(target.EnvBlock);
        string resolvedExecutable = ResolveExecutable(executable, target, environment);
        var startInfo = new ProcessStartInfo
        {
            FileName = resolvedExecutable,
            WorkingDirectory = target.CurrentDirectory,
            UseShellExecute = false
        };
        startInfo.Environment.Clear();
        foreach ((string name, string value) in environment)
            startInfo.Environment[name] = value;
        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(argument);

        try
        {
            using Process child = Process.Start(startInfo);
            if (child == null)
            {
                WriteLine("ERROR: failed to start '" + executable + "'", Colors.Error);
                return 1;
            }
            child.WaitForExit();
            return child.ExitCode;
        }
        catch (Exception ex)
        {
            WriteLine("ERROR: could not start '" + executable + "': " + ex.Message, Colors.Error);
            return 1;
        }
    }

    static int RunProcessAction(int pid, string action, string[] actionArguments)
    {
        ProcessDetails target = Inspector.GetProcessDetails(pid);
        if (!string.IsNullOrEmpty(target.Error))
        {
            WriteLine(target.Error, Colors.Error);
            return 1;
        }

        if (action == "run")
        {
            int commandIndex = actionArguments.Length > 0 && actionArguments[0] == "--" ? 1 : 0;
            if (commandIndex >= actionArguments.Length)
            {
                WriteLine("ERROR: 'run' requires a command", Colors.Error);
                return 2;
            }
            return LaunchInProcessContext(target, actionArguments[commandIndex], actionArguments.Skip(commandIndex + 1));
        }

        if (action == "rerun")
        {
            if (actionArguments.Length != 0)
            {
                WriteLine("ERROR: 'rerun' does not accept arguments", Colors.Error);
                return 2;
            }
            string[] originalArguments = Inspector.ParseCommandLine(target.CommandLine);
            if (string.IsNullOrEmpty(target.ImagePath))
            {
                WriteLine("ERROR: could not read the target process's executable path", Colors.Error);
                return 1;
            }
            return LaunchInProcessContext(target, target.ImagePath, originalArguments.Skip(1));
        }

        if (actionArguments.Length != 0)
        {
            WriteLine("ERROR: 'shell' does not accept arguments; use 'run' to start a specific shell", Colors.Error);
            return 2;
        }

        int currentPid = pid;
        var visited = new HashSet<int>();
        while (currentPid > 0 && visited.Add(currentPid))
        {
            string processName = GetProcessNameSafe(currentPid);
            if (ShellProcessNames.Contains(processName))
            {
                ProcessDetails shell = currentPid == pid ? target : Inspector.GetProcessDetails(currentPid);
                if (!string.IsNullOrEmpty(shell.ImagePath))
                    return LaunchInProcessContext(target, shell.ImagePath, Array.Empty<string>());
            }
            currentPid = Inspector.GetParentPidOnly(currentPid);
        }

        WriteLine("ERROR: no supported shell was found in the process ancestry", Colors.Error);
        return 1;
    }

    static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { /* redirected/non-interactive output may not allow this */ }

        // px itself must never be killed by Ctrl-C - especially while a child process launched
        // via 'run'/'rerun'/'shell' is running (e.g. waiting on child.WaitForExit()). Without
        // this handler, the default Ctrl-C behavior terminates the whole console process, which
        // would kill px right along with (or even instead of) the child it's supposed to be
        // babysitting. Marking the event as handled suppresses that default termination; the
        // Ctrl-C (SIGINT) still reaches the child process normally via the shared console/process
        // group, so the child can react to it as it normally would.
        Console.CancelKeyPress += (_, e) => e.Cancel = true;

        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        if (args.Length >= 2 && int.TryParse(args[0], out int actionPid))
        {
            string action = args[1].ToLowerInvariant();
            if (action is "shell" or "run" or "rerun")
                return RunProcessAction(actionPid, action, args.Skip(2).ToArray());
        }

        var parsed = ParseArgs(args);

        if (parsed.Pids.Count == 0)
        {
            WriteLine("ERROR: no PID and no running process matched any of the given names/fragments '" + string.Join("', '", parsed.UnresolvedTargets) + "'", Colors.Error);
            return 1;
        }

        var detailsByPid = new Dictionary<int, ProcessDetails>();
        foreach (var pid in parsed.Pids)
            detailsByPid[pid] = Inspector.GetProcessDetails(pid);

        bool showPid = parsed.ShowPidExplicit || (!parsed.ShowLocation && !parsed.ShowArgs);
        bool showLocationIndented = parsed.ShowLocation && parsed.ShowArgs;

        var entries = parsed.Pids
            .Select(pid =>
            {
                var details = detailsByPid[pid];
                var shortName = GetProcessNameSafe(pid) + ExeSuffix;
                var argv = Inspector.ParseCommandLine(details.CommandLine);
                var restArgs = argv.Length > 1 ? argv.Skip(1).Select(Inspector.EscapeArgumentForDisplay).ToArray() : Array.Empty<string>();

                // Sort key matches what's actually relevant/visible: by full path only when
                // --location is in effect, otherwise by the short name (even if --args is also
                // shown, since the args themselves aren't a stable sort key).
                var sortKey = parsed.ShowLocation && !string.IsNullOrEmpty(details.ImagePath) ? details.ImagePath : shortName;

                (string Raw, string Name, string Value)[] parsedVars = Array.Empty<(string, string, string)>();
                int matchCount = 0;

                if (parsed.ShouldShowEnv && string.IsNullOrEmpty(details.Error))
                {
                    var vars = details.EnvBlock.Split('\0').Where(v => !string.IsNullOrEmpty(v)).ToArray();
                    Array.Sort(vars, StringComparer.OrdinalIgnoreCase);

                    parsedVars = vars.Select(v =>
                    {
                        var eq = v.IndexOf('=', v.StartsWith("=") ? 1 : 0);
                        var name = eq >= 0 ? v.Substring(0, eq) : v;
                        var value = eq >= 0 ? v.Substring(eq + 1) : "";
                        return (Raw: v, Name: name, Value: value);
                    }).ToArray();

                    var varNames = parsedVars.Select(pv => pv.Name).ToArray();
                    var compiledImplicit = CompileImplicitFilters(parsed.ImplicitFilters, varNames);

                    matchCount = parsed.ShowEnvAll
                        ? parsedVars.Length
                        : parsedVars.Count(pv => PassesFilters(parsed, pv.Name, pv.Value, compiledImplicit));
                }

                return new MatchedEntry
                {
                    Pid = pid, Details = details, ShortName = shortName, RestArgs = restArgs, Cwd = details.CurrentDirectory, SortKey = sortKey,
                    ParsedVars = parsedVars, EnvMatchCount = matchCount,
                    OpenFiles = parsed.ShowFiles ? Inspector.GetOpenFiles(pid) : new OpenFilesResult(),
                    OpenPorts = parsed.ShowPorts ? Inspector.GetOpenPorts(pid) : new OpenPortsResult()
                };
            })
            .OrderBy(e => e.SortKey, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // When env filters are active (any --env-* flag or a leftover implicit filter token),
        // exclude processes with zero matching environment variables from the whole list -
        // unless --all is given to override this and show every matched process regardless.
        if (parsed.HasFilters && !parsed.ShowAll)
            entries = entries.Where(e => e.EnvMatchCount > 0).ToArray();

        if (entries.Length == 0)
        {
            WriteLine("(no processes had environment variables matching the given filter(s); use --all to show them anyway)", Colors.Muted);
            return 0;
        }

        int pidDigits = entries.Max(e => e.Pid.ToString().Length);

        // In "bare args" mode (--args given, but no --location line and no env vars to
        // separate entries), a single \n between processes isn't enough if a line wraps in the
        // terminal - it becomes impossible to tell where one process's args end and the next
        // one's PID/name begins. Detect that case and, if a given line's actual rendered width
        // would exceed the console width, add an extra blank line after it.
        bool bareArgsMode = parsed.ShowArgs && !showLocationIndented && !parsed.ShouldShowEnv && !parsed.ShowFiles && !parsed.ShowPorts;
        int consoleWidth = SafeConsoleWidth();

        // When --tree is active, the top flat list is redundant UNLESS location, environment,
        // or open-file details are requested. Args are already shown per-node in the tree itself.
        bool printTopList = !parsed.ShowTree || parsed.ShowLocation || parsed.ShouldShowEnv || parsed.ShowFiles || parsed.ShowPorts;

        if (printTopList)
        foreach (var e in entries)
        {
            string pidPrefixPlain = "";
            if (showPid)
            {
                var pidDigitsStr = e.Pid.ToString().PadLeft(pidDigits);
                pidPrefixPlain = "(" + pidDigitsStr + ")  ";
                Write("(", Colors.Muted);
                Write(pidDigitsStr, Colors.Pid);
                Write(")", Colors.Muted);
                Write("  ");
            }

            // --- Main line content ---
            if (parsed.ShowArgs)
            {
                Write(e.ShortName, Colors.Name);
                bool seenOption = false;
                foreach (var a in e.RestArgs)
                {
                    Write(" ");
                    WriteArgColored(a, ref seenOption);
                }
            }
            else if (parsed.ShowLocation && !string.IsNullOrEmpty(e.Details.ImagePath))
            {
                WriteExePathColored(e.Details.ImagePath);
            }
            else
            {
                WriteExePathColored(e.ShortName);
            }

            // --- cwd, right on the process line, after args (or after the base name if no args) ---
            if (parsed.ShowCwd) WriteCwdSuffix(e.Cwd);

            Console.WriteLine();

            if (bareArgsMode)
            {
                var plainLine = pidPrefixPlain + e.ShortName + string.Concat(e.RestArgs.Select(a => " " + a));
                if (consoleWidth > 0 && plainLine.Length > consoleWidth)
                    Console.WriteLine();
            }

            // --- Indented location line, only when both --args and --location are given ---
            bool hasPathLine = showLocationIndented && !string.IsNullOrEmpty(e.Details.ImagePath);
            if (hasPathLine)
            {
                Console.WriteLine();
                WriteLine("  " + e.Details.ImagePath, Colors.Muted);
                Console.WriteLine();
            }

            // --- Open regular files, open ports, and env vars, when requested ---
            if (!parsed.ShowFiles && !parsed.ShowPorts && !parsed.ShouldShowEnv) continue;

            if (!hasPathLine) Console.WriteLine();

            if (parsed.ShowFiles)
            {
                if (!string.IsNullOrEmpty(e.OpenFiles.Error))
                {
                    WriteLine("  " + e.OpenFiles.Error, Colors.Error);
                }
                else if (e.OpenFiles.Files.Count == 0)
                {
                    WriteLine("  (no open files)", Colors.Muted);
                }
                else
                {
                    foreach (string file in e.OpenFiles.Files)
                    {
                        Write("  ");
                        WriteExePathColored(file);
                        Console.WriteLine();
                    }
                }

                if (parsed.ShowPorts || parsed.ShouldShowEnv)
                    Console.WriteLine();
            }

            if (parsed.ShowPorts)
            {
                if (!string.IsNullOrEmpty(e.OpenPorts.Error))
                {
                    WriteLine("  " + e.OpenPorts.Error, Colors.Error);
                }
                else if (e.OpenPorts.Ports.Count == 0)
                {
                    WriteLine("  (no open ports)", Colors.Muted);
                }
                else
                {
                    foreach (var port in e.OpenPorts.Ports)
                    {
                        string line = port.RemotePort != 0 || !string.IsNullOrEmpty(port.RemoteAddress) && port.RemoteAddress != "0.0.0.0" && port.RemoteAddress != "::"
                            ? $"  {port.Protocol,-3} {port.LocalAddress}:{port.LocalPort} -> {port.RemoteAddress}:{port.RemotePort} {port.State}"
                            : $"  {port.Protocol,-3} {port.LocalAddress}:{port.LocalPort} {port.State}";
                        WriteLine(line.TrimEnd(), Colors.Muted);
                    }
                }

                if (parsed.ShouldShowEnv)
                    Console.WriteLine();
            }

            if (parsed.ShouldShowEnv)
            {
                if (!string.IsNullOrEmpty(e.Details.Error))
                {
                    WriteLine("  " + e.Details.Error, Colors.Error);
                }
                else
                {
                    var varNames = e.ParsedVars.Select(pv => pv.Name).ToArray();
                    var compiledImplicit = CompileImplicitFilters(parsed.ImplicitFilters, varNames);

                    foreach (var pv in e.ParsedVars)
                    {
                        if (parsed.ShowEnvAll || PassesFilters(parsed, pv.Name, pv.Value, compiledImplicit))
                        {
                            Write("  ");
                            Write(pv.Name, Colors.EnvName);
                            Write("=");
                            WriteLine(pv.Value, Colors.EnvValue);
                        }
                    }

                    if (e.EnvMatchCount == 0)
                        WriteLine("  (no matching environment variables)", Colors.Muted);
                }
            }

            Console.WriteLine();
        }

        if (parsed.ShowTree)
        {
            if (printTopList) Console.WriteLine();
            PrintForest(entries, parsed.ShowArgs, parsed.ShowCwd);
        }

        return 0;
    }
}
