# px

`px` (formerly `penv`) is a small cross-platform console utility for inspecting
running processes on Windows, Linux, and macOS. It can:

- Resolve processes by PID, exact name, name fragment, or glob pattern
- Display PIDs, executable names, executable paths, and current directories
- Display command-line arguments with platform-appropriate escaping
- Display and filter environment variables
- List regular files currently open by a process
- List TCP and UDP ports owned by a process
- Display process ancestry as a merged tree or forest
- Launch a shell or command using another process's working directory and environment
- Rerun another process with its original executable and arguments

## Process selection

Targets are resolved in this order:

1. A numeric token is treated as a PID.
2. An exact process-name match is selected.
3. A token containing `*` or `?` is treated as a process-name glob.
4. If no process has been selected yet, remaining tokens are matched as
   case-insensitive name fragments.

Examples:

```text
px 12345
px chrome
px 'chrome*'
px 12345 67890
```

With no target, a command containing only options such as `--tree`, `--args`, or
`--env` operates on all running processes.

## Process information

```text
px <target> --pid       # always show the PID
px <target> --location  # show the executable path
px <target> --args      # show escaped command-line arguments
px <target> --cwd       # show the current working directory
px <target> --where     # equivalent to --location --cwd
```

By default, the main line shows the PID and process name. `--location` replaces
that with the executable path, while `--args` shows the process name followed by
its arguments. Use `--pid` to force the PID to be shown in either mode.

## Environment variables

Use `--env` to display all environment variables:

```text
px <target> --env
```

Environment filters imply `--env` and accept one or more values, which are ORed
together:

```text
px <target> --env-contains PATH TEMP
px <target> --env-name-contains HOME
px <target> --env-name-starts-with APP_
px <target> --env-value-contains localhost
px <target> --env-value-starts-with https://
```

The shorter aliases `--contains`, `--name-contains`, `--name-starts-with`,
`--value-contains`, and `--value-starts-with` are also supported.

A leftover positional argument can be used as an environment-variable name
filter. Exact names and glob patterns are supported:

```text
px 12345 PATH
px 12345 'APP_*'
```

When filtering is active, processes with no matching variables are hidden. Use
`--all` to show them anyway.

## Open files

Use `--files` to list regular filesystem files currently open by each matched
process:

```text
px <pid> --files
px chrome --files
```

The list is deduplicated and sorted. Directories, sockets, pipes, devices, and
other OS-specific handles/descriptors are intentionally excluded. Access may
be limited by process ownership, elevation, sandboxing, or other operating
system security controls.

## Open ports

Use `--ports` to list TCP and UDP ports currently owned by each matched process:

```text
px <pid> --ports
px chrome --ports
```

TCP entries include local and remote addresses, ports, and connection state.
UDP entries include the local address and port. Port inspection is subject to
the permissions and security controls of the operating system.

## Process trees

Use `--tree` to display selected processes and their living ancestors as a
merged ancestry tree or forest:

```text
px 12345 --tree
px 'worker*' --tree --args
px 'worker*' --tree --cwd
```

Shared ancestors are printed once. If a matched process has no living parent,
it is listed separately with either `(no parent)` or `(dead parent <PID>)`.
The normal flat list is skipped unless additional information such as
`--location`, `--env`, `--files`, or `--ports` was requested.

## Process actions

The PID-first action syntax uses the selected process's current working
directory and environment:

```text
px <pid> shell
px <pid> run [--] <command> [<arg> ...]
px <pid> rerun
```

- `shell` walks up the process ancestry and starts a new instance of the nearest
  recognized shell (`cmd`, `powershell`, `pwsh`, `bash`, `zsh`, `fish`, or
  `sh`). The new shell uses the selected PID's context, not the ancestor's.
- `run` starts the supplied command in the selected PID's context. The
  conventional `--` separator is supported but optional.
- `rerun` starts the selected process's original executable and arguments again
  in its current context.

Examples:

```text
px 32600 shell
px 32600 run -- git status
px 32600 run dotnet test
px 32600 rerun
```

These operations reproduce launch context, not in-memory process state, open
handles, shell-local aliases/functions, or other unexported state.

## Platform implementation

Windows reads process details from the target process's PEB using
`OpenProcess`, `NtQueryInformationProcess`, and `ReadProcessMemory`.

Linux reads process details from `/proc/<pid>/`, and cross-references file
descriptors with `/proc/net/{tcp,tcp6,udp,udp6}` for port inspection.

macOS uses Apple's `libproc` and `sysctl` APIs. macOS support should be tested
on the macOS versions and architectures you intend to support, particularly
current-working-directory inspection, which depends on native structure offsets.

## Requirements

- Windows, Linux, or macOS (x64)
- .NET 10 SDK to build
- Permission to inspect the target process; access to another user's process
  may require elevation, `sudo`, or additional operating-system permissions

## Build

```text
dotnet build
```

The debug build output is:

```text
bin/Debug/net10.0/px.exe   # Windows
bin/Debug/net10.0/px       # Linux/macOS
```
