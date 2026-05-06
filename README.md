# WinFaultDiag Toolkit

Generic one-click Windows crash / WER / EventLog diagnostics.

## Quick start

Double-click:

```bat
Run-WinFaultDiag.cmd
```

## Examples

### Read-only collection

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\WinFaultDiag.ps1 `
  -TargetProcessName DingTalkReal `
  -TargetExePath "D:\Software\Wukong\0.9.39-26042905\DingTalkReal.exe" `
  -Keywords "DingTalkReal,msedgewebview2,msedge,Symantec,agentshell_guard" `
  -Hours 6
```

### Launch target and observe

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\WinFaultDiag.ps1 `
  -TargetProcessName DingTalkReal `
  -TargetExePath "D:\Software\Wukong\0.9.39-26042905\DingTalkReal.exe" `
  -Keywords "DingTalkReal,msedgewebview2,msedge,Symantec,agentshell_guard" `
  -Hours 6 `
  -RunProbe `
  -KillExisting
```

### Enable WER LocalDumps and reproduce

Run PowerShell as Administrator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\WinFaultDiag.ps1 `
  -TargetProcessName DingTalkReal `
  -TargetExePath "D:\Software\Wukong\0.9.39-26042905\DingTalkReal.exe" `
  -EnableLocalDumps `
  -RunProbe `
  -KillExisting
```

Dumps default to:

```text
.\CrashDumps
```

### Disable LocalDumps entries

Run PowerShell as Administrator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\WinFaultDiag.ps1 `
  -TargetProcessName DingTalkReal `
  -DisableLocalDumps
```

## Output

```text
.\WinFaultDiagOutput\WinFaultDiag-YYYYMMDD-HHMMSS
```

Read:

- `SUMMARY.md`
- `TIMELINE.md`
- `FINDINGS.json`

## Privacy

Reports can include usernames, local paths, process command lines, policies, WER paths, and security-product logs. Review before sharing externally.


## v2 local-output behavior

When launched via `Run-WinFaultDiag.cmd`, all outputs are written under the CMD directory:

```text
<tool-folder>\WinFaultDiagOutput\WinFaultDiag-YYYYMMDD-HHMMSS
<tool-folder>\WinFaultDiagOutput\WinFaultDiag-YYYYMMDD-HHMMSS.zip
<tool-folder>\CrashDumps
```

When `WinFaultDiag.ps1` is launched directly without `-OutputRoot` or `-DumpFolder`, it uses the directory containing `WinFaultDiag.ps1` as the base folder.

You can still override explicitly:

```powershell
-OutputRoot "D:\DiagOutput" -DumpFolder "D:\DiagOutput\CrashDumps"
```
