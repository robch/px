# px

`px` (formerly `penv`) is a small cross-platform console utility for inspecting
running processes: resolve them by PID, exact name, name fragment, or glob;
list their PIDs and executable names/paths; dump a ready-to-run command line
(exe + properly re-escaped args); print/filter their environment variables;
and list regular files they currently have open. It can also launch a shell or
command in a process's context, or rerun that process.

Windows doesn't expose another process's environment block (or full
command line) through normal tools like `tasklist` or PowerShell's
`Get-Process` - you have to read it directly out of the target process's
memory. `px` does this by:

1. Calling `OpenProcess` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
2. Calling `NtQueryInformationProcess` to get the process's **PEB** address
3. Reading the PEB to get the `RTL_USER_PROCESS_PARAMETERS` pointer
4. Reading `ProcessParameters` to get the `ImagePathName`, `CommandLine`,
   and `Environment` block pointers
5. Reading each of those and printing/filtering the results

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

## Requirements

- Windows, Linux, or macOS (x64)
- .NET 10 SDK to build
- You must have permission to read the target process's memory (this
  generally works for your own processes without elevation; for processes
  owned by other users you'll need to run elevated)

## Build

```
dotnet build
```

The debug build output is:

```
bin\Debug\net10.0\px.exe
```
