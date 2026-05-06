<#
.SYNOPSIS
  WinFaultDiag - one-click Windows WER/EventLog/process diagnostic collector and rule-based analyzer.

.DESCRIPTION
  Generic Windows fault diagnostics tool. Default mode is read-only.
  It collects:
    - Application Error 1000 / WER 1001 / Application Hang 1002 / .NET Runtime 1026
    - WER ReportArchive / ReportQueue metadata and Report.wer text
    - CodeIntegrity / AppLocker / Defender / Symantec / common security-product signals
    - target process snapshots, optional launch probe, optional loaded modules
    - registry policy indicators: Edge/WebView2/Defender/AppLocker/IFEO/AppInit_DLLs
    - optional WER LocalDumps configuration

  It outputs:
    - SUMMARY.md
    - TIMELINE.md
    - FINDINGS.json
    - raw CSV/TXT evidence files
    - zip package

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFaultDiag.ps1 `
    -TargetProcessName DingTalkReal `
    -TargetExePath "D:\Software\Wukong\0.9.39-26042905\DingTalkReal.exe" `
    -Keywords "DingTalkReal,msedgewebview2,msedge,Symantec,agentshell_guard" `
    -Hours 6 `
    -RunProbe `
    -KillExisting

.EXAMPLE
  # Administrator PowerShell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFaultDiag.ps1 `
    -TargetProcessName DingTalkReal `
    -TargetExePath "D:\Software\Wukong\0.9.39-26042905\DingTalkReal.exe" `
    -EnableLocalDumps `
    -RunProbe `
    -KillExisting
#>

param(
  [string]$TargetProcessName = "",
  [string]$TargetExePath = "",
  [string]$Keywords = "",
  [int]$Hours = 24,
  [string]$OutputRoot = "",
  [switch]$RunProbe,
  [int]$ObserveSeconds = 30,
  [switch]$KillExisting,
  [switch]$EnableLocalDumps,
  [switch]$DisableLocalDumps,
  [string]$DumpFolder = "",
  [switch]$IncludeModuleList,
  [switch]$DeepSearchWer,
  [int]$CorrelationSeconds = 120
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

# Default output locations:
# - When launched from Run-WinFaultDiag.cmd, the CMD passes explicit paths under its own directory.
# - When launched directly, use the directory containing this PS1 if available; otherwise use current directory.
$script:ToolBaseDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:ToolBaseDir)) {
  try { $script:ToolBaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path } catch {}
}
if ([string]::IsNullOrWhiteSpace($script:ToolBaseDir)) {
  $script:ToolBaseDir = (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
  $OutputRoot = Join-Path $script:ToolBaseDir "WinFaultDiagOutput"
}

if ([string]::IsNullOrWhiteSpace($DumpFolder)) {
  $DumpFolder = Join-Path $script:ToolBaseDir "CrashDumps"
}


function SafeStr([object]$v, [int]$max = 8000) {
  if ($null -eq $v) { return "" }
  $s = [string]$v
  if ($s.Length -gt $max) { return $s.Substring(0, $max) + "...[truncated]" }
  return $s
}

function IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function NormProc([string]$n) {
  if ([string]::IsNullOrWhiteSpace($n)) { return "" }
  $x=$n.Trim()
  if ($x.ToLowerInvariant().EndsWith(".exe")) { return $x.Substring(0,$x.Length-4) }
  return $x
}
function NormExe([string]$n) {
  if ([string]::IsNullOrWhiteSpace($n)) { return "" }
  $x=$n.Trim()
  if ($x.ToLowerInvariant().EndsWith(".exe")) { return $x }
  return "$x.exe"
}

function ErrLine([string]$m) {
  try { $m | Out-File -FilePath (Join-Path $script:OutDir "errors.txt") -Append -Encoding UTF8 } catch {}
}
function TryDo([scriptblock]$b, [string]$name) {
  try { & $b } catch { ErrLine "[ERROR] $name failed: $($_.Exception.Message)" }
}

function ExportRows($rows, [string]$name) {
  $csv = Join-Path $script:OutDir "$name.csv"
  $txt = Join-Path $script:OutDir "$name.txt"
  $a = @()
  if ($null -ne $rows) { $a = @($rows | Where-Object { $null -ne $_ }) }
  if ($a.Count -eq 0) { $a = @([PSCustomObject]@{Status="NO_ROWS"; Message="No matching data collected."}) }
  try { $a | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv } catch {
    ErrLine "Export-Csv failed for $name: $($_.Exception.Message)"
    @([PSCustomObject]@{Status="EXPORT_ERROR";Message=$_.Exception.Message}) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
  }
  try { $a | Format-List * | Out-File -Encoding UTF8 -FilePath $txt -Width 4096 } catch { ErrLine "Out-File failed for $name: $($_.Exception.Message)" }
}

function ReadCsv([string]$p) { if (!(Test-Path $p)) { return @() }; try { return @(Import-Csv $p) } catch { return @() } }

function FileInfoSafe([string]$p) {
  if ([string]::IsNullOrWhiteSpace($p) -or !(Test-Path $p)) { return [PSCustomObject]@{Path=$p;Exists=$false;Error="Not found"} }
  try {
    $i=Get-Item $p -ErrorAction Stop; $h=""; try {$h=(Get-FileHash $p -Algorithm SHA256).Hash} catch {}
    $sigStatus=""; $sigSubject=""; try { $sig=Get-AuthenticodeSignature $p; $sigStatus=$sig.Status; if($sig.SignerCertificate){$sigSubject=$sig.SignerCertificate.Subject} } catch {}
    return [PSCustomObject]@{Path=$i.FullName;Exists=$true;Name=$i.Name;Length=$i.Length;LastWriteTime=$i.LastWriteTime;FileVersion=$i.VersionInfo.FileVersion;ProductVersion=$i.VersionInfo.ProductVersion;CompanyName=$i.VersionInfo.CompanyName;ProductName=$i.VersionInfo.ProductName;SHA256=$h;SignatureStatus=$sigStatus;SignatureSubject=$sigSubject;Error=""}
  } catch { return [PSCustomObject]@{Path=$p;Exists=$false;Error=$_.Exception.Message} }
}

function GetEvents([string]$log, [datetime]$start, [string]$pattern, [int[]]$ids=$null, [int]$max=800) {
  try {
    $f=@{LogName=$log;StartTime=$start}; if($ids){$f.Id=$ids}
    $raw=@(Get-WinEvent -FilterHashtable $f -ErrorAction Stop -MaxEvents 4000)
    if(-not [string]::IsNullOrWhiteSpace($pattern)){ $raw=@($raw | Where-Object { $_.ProviderName -match $pattern -or $_.Message -match $pattern -or ([string]$_.Id) -match $pattern }) }
    return @($raw | Select-Object -First $max | ForEach-Object { [PSCustomObject]@{TimeCreated=$_.TimeCreated;Id=$_.Id;Level=$_.LevelDisplayName;ProviderName=$_.ProviderName;LogName=$_.LogName;RecordId=$_.RecordId;ProcessId=$_.ProcessId;Message=SafeStr $_.Message 12000;Xml=SafeStr $_.ToXml() 20000} })
  } catch {
    return @([PSCustomObject]@{TimeCreated=$null;Id=$null;Level="ERROR";ProviderName=$log;LogName=$log;RecordId=$null;ProcessId=$null;Message=$_.Exception.Message;Xml=""})
  }
}

function GetAppEvents([datetime]$start,[string]$pattern) {
  GetEvents "Application" $start $pattern @(1000,1001,1002,1005,10010,1026,11707,11708,45) 1200
}

function GetSecurityEvents([datetime]$start,[string]$pattern) {
  $rows=@()
  foreach($log in @("System","Microsoft-Windows-CodeIntegrity/Operational","Microsoft-Windows-AppLocker/EXE and DLL","Microsoft-Windows-AppLocker/MSI and Script","Microsoft-Windows-AppLocker/Packaged app-Execution","Microsoft-Windows-AppLocker/Packaged app-Deployment","Microsoft-Windows-Windows Defender/Operational")){
    $rows += GetEvents $log $start $pattern $null 500
  }
  $av="Symantec|Defender|CrowdStrike|Sentinel|Carbon Black|McAfee|Trellix|Sophos|Kaspersky|ESET|360|Huorong|火绒|agentshell|guard|Tamper|Access denied|blocked|denied|quarantine|隔离|拦截|阻止|拒绝"
  if(-not [string]::IsNullOrWhiteSpace($pattern)){ $av="($av)|($pattern)" }
  $rows += GetEvents "Application" $start $av $null 800
  return $rows
}

function GetRegRows([string[]]$roots) {
  $rows=@()
  foreach($root in $roots){
    if(!(Test-Path $root)){continue}
    try{
      $keys=@(Get-Item $root -ErrorAction SilentlyContinue) + @(Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue)
      foreach($k in $keys){
        try{
          $props=Get-ItemProperty $k.PSPath -ErrorAction Stop
          foreach($p in $props.PSObject.Properties){
            if($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$'){
              $rows += [PSCustomObject]@{Path=$k.Name;Name=$p.Name;Value=SafeStr $p.Value 3000}
            }
          }
        }catch{}
      }
    }catch{ $rows += [PSCustomObject]@{Path=$root;Name="__ERROR__";Value=$_.Exception.Message} }
  }
  return $rows
}

function GetWERReports([datetime]$start,[string]$pattern) {
  $roots=@("$env:ProgramData\Microsoft\Windows\WER\ReportArchive","$env:ProgramData\Microsoft\Windows\WER\ReportQueue","$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive","$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue")
  if($DeepSearchWer){ $roots += @("$env:ProgramData\Microsoft\Windows\WER","$env:LOCALAPPDATA\Microsoft\Windows\WER") }
  $copy=Join-Path $script:OutDir "WER_Report_wers"; New-Item -ItemType Directory -Force -Path $copy | Out-Null
  $rows=@()
  foreach($r in ($roots|Select-Object -Unique)){
    if(!(Test-Path $r)){continue}
    try{
      $dirs=@(Get-ChildItem $r -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $start -or ([string]$_.Name -match $pattern) } | Sort-Object LastWriteTime -Descending | Select-Object -First 200)
      foreach($d in $dirs){
        $report=Join-Path $d.FullName "Report.wer"; $txt=""; $eventType=""; $app=""; $mod=""; $code=""
        if(Test-Path $report){
          try{
            $txt=Get-Content $report -Raw -ErrorAction Stop
            $eventType=([regex]::Match($txt,'(?m)^EventType=(.+)$')).Groups[1].Value.Trim()
            $app=([regex]::Match($txt,'(?m)^P1=(.+)$')).Groups[1].Value.Trim()
            $mod=([regex]::Match($txt,'(?m)^P4=(.+)$')).Groups[1].Value.Trim()
            $code=([regex]::Match($txt,'(?m)^P8=(.+)$')).Groups[1].Value.Trim()
          }catch{}
        }
        $files=@(Get-ChildItem $d.FullName -File -ErrorAction SilentlyContinue); $dumps=@($files|Where-Object {$_.Extension -ieq ".dmp"})
        $fileNames=($files|Select-Object -ExpandProperty Name)-join "; "
        if([string]::IsNullOrWhiteSpace($pattern) -or $d.Name -match $pattern -or $txt -match $pattern -or $fileNames -match $pattern -or $d.LastWriteTime -ge $start){
          $rows += [PSCustomObject]@{Root=$r;Directory=$d.FullName;Name=$d.Name;LastWriteTime=$d.LastWriteTime;HasReportWer=(Test-Path $report);EventType=$eventType;AppName=$app;FaultModule=$mod;ExceptionCode=$code;DumpCount=$dumps.Count;DumpFiles=($dumps|Select-Object -ExpandProperty FullName)-join "; ";Files=$fileNames}
          if(Test-Path $report){ $safe=($d.Name -replace '[^\w\.-]','_'); Copy-Item $report (Join-Path $copy "$safe.Report.wer.txt") -Force -ErrorAction SilentlyContinue }
        }
      }
    }catch{ $rows += [PSCustomObject]@{Root=$r;Directory="";Name="__ERROR__";LastWriteTime=$null;HasReportWer=$false;EventType="";AppName="";FaultModule="";ExceptionCode="";DumpCount=0;DumpFiles="";Files=$_.Exception.Message} }
  }
  return $rows
}

function GetDumps([string]$pattern) {
  $roots=@("$env:LOCALAPPDATA\CrashDumps","$env:TEMP",".\CrashDumps",$DumpFolder)|Where-Object{$_}|Select-Object -Unique
  $rows=@()
  foreach($r in $roots){ if(!(Test-Path $r)){continue}; Get-ChildItem $r -File -Filter *.dmp -ErrorAction SilentlyContinue | Where-Object { [string]::IsNullOrWhiteSpace($pattern) -or $_.Name -match $pattern -or $_.FullName -match $pattern } | Sort-Object LastWriteTime -Descending | Select-Object -First 100 | ForEach-Object { $rows += [PSCustomObject]@{Root=$r;Name=$_.Name;FullName=$_.FullName;Length=$_.Length;LastWriteTime=$_.LastWriteTime} } }
  return $rows
}

function GetProcs([string]$pattern) {
  try{ return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { [string]::IsNullOrWhiteSpace($pattern) -or $_.Name -match $pattern -or $_.CommandLine -match $pattern -or $_.ExecutablePath -match $pattern } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,@{Name="CommandLine";Expression={SafeStr $_.CommandLine 5000}},CreationDate) }
  catch { return @([PSCustomObject]@{ProcessId=$null;ParentProcessId=$null;Name="__ERROR__";ExecutablePath="";CommandLine=$_.Exception.Message;CreationDate=$null}) }
}
function ObserveProcs([string]$pattern,[int]$sec,[string]$tag) {
  $rows=@(); $end=(Get-Date).AddSeconds($sec)
  while((Get-Date) -lt $end){ foreach($p in (GetProcs $pattern)){ $rows += [PSCustomObject]@{Tag=$tag;Time=Get-Date;ProcessId=$p.ProcessId;ParentProcessId=$p.ParentProcessId;Name=$p.Name;ExecutablePath=$p.ExecutablePath;CommandLine=$p.CommandLine;CreationDate=$p.CreationDate} }; Start-Sleep -Milliseconds 500 }
  return $rows
}
function GetModules([string]$pattern) {
  $rows=@(); $procs=@(Get-Process -ErrorAction SilentlyContinue | Where-Object { [string]::IsNullOrWhiteSpace($pattern) -or $_.ProcessName -match $pattern -or $_.Path -match $pattern })
  foreach($p in $procs){ try{ foreach($m in $p.Modules){ $rows += [PSCustomObject]@{ProcessId=$p.Id;ProcessName=$p.ProcessName;ModuleName=$m.ModuleName;FileName=$m.FileName;FileVersion=$m.FileVersionInfo.FileVersion;CompanyName=$m.FileVersionInfo.CompanyName} } }catch{ $rows += [PSCustomObject]@{ProcessId=$p.Id;ProcessName=$p.ProcessName;ModuleName="__ERROR__";FileName=$_.Exception.Message;FileVersion="";CompanyName=""} } }
  return $rows
}

function DumpTargets(){
  $names=New-Object System.Collections.Generic.List[string]
  if($TargetProcessName){$names.Add((NormExe $TargetProcessName))}
  if($TargetExePath){try{$names.Add((Split-Path $TargetExePath -Leaf))}catch{}}
  foreach($n in @("msedge.exe","msedgewebview2.exe","WerFault.exe","electron.exe","chrome.exe")){$names.Add($n)}
  return @($names|Where-Object{$_}|Select-Object -Unique)
}
function ConfigDumps([switch]$Enable,[switch]$Disable){
  if(-not (IsAdmin)){ return @([PSCustomObject]@{Status="SKIPPED";Message="LocalDumps modification requires Administrator PowerShell.";DumpFolder=$DumpFolder}) }
  $rows=@(); $base="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
  foreach($exe in (DumpTargets)){ $key=Join-Path $base $exe; try{ if($Disable){ if(Test-Path $key){Remove-Item $key -Recurse -Force; $rows += [PSCustomObject]@{Status="DISABLED";Exe=$exe;Key=$key;DumpFolder=""}} else {$rows += [PSCustomObject]@{Status="NO_KEY";Exe=$exe;Key=$key;DumpFolder=""}} } elseif($Enable){ New-Item -ItemType Directory -Force -Path $DumpFolder | Out-Null; New-Item $key -Force | Out-Null; New-ItemProperty $key DumpFolder -PropertyType ExpandString -Value $DumpFolder -Force | Out-Null; New-ItemProperty $key DumpCount -PropertyType DWord -Value 10 -Force | Out-Null; New-ItemProperty $key DumpType -PropertyType DWord -Value 2 -Force | Out-Null; $rows += [PSCustomObject]@{Status="ENABLED";Exe=$exe;Key=$key;DumpFolder=$DumpFolder} } } catch { $rows += [PSCustomObject]@{Status="ERROR";Exe=$exe;Key=$key;DumpFolder=$DumpFolder;Error=$_.Exception.Message} } }
  return $rows
}

function ParseCrash([string]$msg){
  $app=([regex]::Match($msg,'错误应用程序名称:\s*([^,\r\n]+)')).Groups[1].Value.Trim(); if(!$app){$app=([regex]::Match($msg,'Faulting application name:\s*([^,\r\n]+)')).Groups[1].Value.Trim()}
  $mod=([regex]::Match($msg,'错误模块名称:\s*([^,\r\n]+)')).Groups[1].Value.Trim(); if(!$mod){$mod=([regex]::Match($msg,'Faulting module name:\s*([^,\r\n]+)')).Groups[1].Value.Trim()}
  $code=([regex]::Match($msg,'异常代码:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)')).Groups[1].Value.Trim(); if(!$code){$code=([regex]::Match($msg,'Exception code:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)')).Groups[1].Value.Trim()}
  $appPath=([regex]::Match($msg,'错误应用程序路径:\s*(.+)')).Groups[1].Value.Trim(); if(!$appPath){$appPath=([regex]::Match($msg,'Faulting application path:\s*(.+)')).Groups[1].Value.Trim()}
  $modPath=([regex]::Match($msg,'错误模块路径:\s*(.+)')).Groups[1].Value.Trim(); if(!$modPath){$modPath=([regex]::Match($msg,'Faulting module path:\s*(.+)')).Groups[1].Value.Trim()}
  $rid=([regex]::Match($msg,'报告 ID:\s*(.+)')).Groups[1].Value.Trim(); if(!$rid){$rid=([regex]::Match($msg,'Report Id:\s*(.+)')).Groups[1].Value.Trim()}
  return [PSCustomObject]@{Process=$app;Module=$mod;ExceptionCode=$code.ToLowerInvariant();ApplicationPath=$appPath;ModulePath=$modPath;ReportId=$rid}
}
function ParseWER([string]$msg){
  $event=([regex]::Match($msg,'(?m)^事件名称:\s*(.+)$')).Groups[1].Value.Trim(); if(!$event){$event=([regex]::Match($msg,'(?m)^Event Name:\s*(.+)$')).Groups[1].Value.Trim()}
  $p=@{}; for($i=1;$i -le 10;$i++){$p["P$i"]=([regex]::Match($msg,"(?m)^P$i`:\s*(.*)$")).Groups[1].Value.Trim()}
  return [PSCustomObject]@{EventName=$event;Process=$p["P1"];Version=$p["P2"];Module=$p["P4"];ExceptionCode=$p["P8"];Param9=$p["P9"]}
}
function SecScore($provider,$msg){ $s=0; if($provider -match 'Symantec|Defender|CodeIntegrity|AppLocker|CrowdStrike|Sentinel|McAfee|Trellix|Sophos|Kaspersky|Carbon Black|ESET|agentshell|guard'){$s+=2}; if($msg -match 'Tamper Protection|Access denied|blocked|denied|prevented|quarantine|threat|Code Integrity|policy|AppLocker|Controlled Folder Access|拦截|阻止|拒绝|隔离'){$s+=3}; return $s }

function Analyze($appEvents,$secEvents,$werReports,$snaps){
  $crashes=@(); $wers=@(); $secs=@(); $timeline=@(); $find=@()
  foreach($e in $appEvents){ $id=[string]$e.Id; $prov=[string]$e.ProviderName; $msg=[string]$e.Message; if($id -eq '1000' -or $prov -match 'Application Error'){ $p=ParseCrash $msg; if($p.Process){$crashes += [PSCustomObject]@{TimeCreated=$e.TimeCreated;ProviderName=$prov;EventId=$id;Process=$p.Process;Module=$p.Module;ExceptionCode=$p.ExceptionCode;ApplicationPath=$p.ApplicationPath;ModulePath=$p.ModulePath;ReportId=$p.ReportId;RawMessage=SafeStr $msg 3000}} }; if($id -eq '1001' -or $prov -match 'Windows Error Reporting'){ $w=ParseWER $msg; if($w.EventName -or $w.Process){$wers += [PSCustomObject]@{TimeCreated=$e.TimeCreated;ProviderName=$prov;EventId=$id;EventName=$w.EventName;Process=$w.Process;Module=$w.Module;ExceptionCode=$w.ExceptionCode;Param9=$w.Param9;RawMessage=SafeStr $msg 3000}} } }
  foreach($e in $secEvents){ $score=SecScore $e.ProviderName $e.Message; if($score -gt 0){ $secs += [PSCustomObject]@{TimeCreated=$e.TimeCreated;ProviderName=$e.ProviderName;EventId=$e.Id;Score=$score;Message=SafeStr $e.Message 3000} } }
  foreach($c in $crashes){ $timeline += [PSCustomObject]@{TimeCreated=$c.TimeCreated;Kind='Crash.ApplicationError';Provider=$c.ProviderName;EventId=$c.EventId;Process=$c.Process;Detail="$($c.Process) crashed in $($c.Module), exception=$($c.ExceptionCode)";Evidence=$c.RawMessage} }
  foreach($w in $wers){ $timeline += [PSCustomObject]@{TimeCreated=$w.TimeCreated;Kind='Crash.WER';Provider=$w.ProviderName;EventId=$w.EventId;Process=$w.Process;Detail="WER $($w.EventName), module=$($w.Module), exception=$($w.ExceptionCode)";Evidence=$w.RawMessage} }
  foreach($s in $secs){ $timeline += [PSCustomObject]@{TimeCreated=$s.TimeCreated;Kind='Security.Signal';Provider=$s.ProviderName;EventId=$s.EventId;Process='';Detail=SafeStr $s.Message 500;Evidence=$s.Message} }
  foreach($g in ($crashes|Group-Object Process,Module,ExceptionCode)){ if($g.Count -ge 2){ $s=$g.Group[0]; $find += [PSCustomObject]@{Severity='P1';Category='Crash.RepeatedSignature';Confidence=0.85;Title="Repeated crash: $($s.Process) / $($s.Module) / $($s.ExceptionCode)";Evidence="Count=$($g.Count)";Recommendation='Collect a dump and prioritize this repeated signature.'} } }
  foreach($w in $wers){ if($w.EventName -match 'BEX|BEX64' -or $w.ExceptionCode -match 'c0000409|0xc0000409'){ $find += [PSCustomObject]@{Severity='P1';Category='Crash.BEX64FailFast';Confidence=0.8;Title="BEX/fail-fast crash: $($w.Process)";Evidence="EventName=$($w.EventName); Module=$($w.Module); Exception=$($w.ExceptionCode); Time=$($w.TimeCreated)";Recommendation='0xc0000409 is often fail-fast/stack-buffer-overrun style termination. Inspect dump stack and loaded modules.'} } }
  foreach($c in $crashes){ if($c.Process -match 'msedgewebview2\.exe|msedge\.exe'){ $find += [PSCustomObject]@{Severity='P1';Category='Runtime.EdgeWebView2Crash';Confidence=0.9;Title="Edge/WebView2 crashed: $($c.Process)";Evidence="Module=$($c.Module); Exception=$($c.ExceptionCode); Path=$($c.ApplicationPath)";Recommendation='For Tauri/Electron/WebView2 hosts, this can prevent UI display. Check WebView2 repair, user data, GPU, and security software.'} } }
  foreach($c in $crashes){ foreach($s in $secs){ try{ $d=[math]::Abs((([datetime]$c.TimeCreated)-([datetime]$s.TimeCreated)).TotalSeconds); if($d -le $CorrelationSeconds){ $cat='Security.InterferenceNearCrash'; $title='Security/policy signal near crash'; $conf=0.75; if($s.ProviderName -match 'Symantec' -and $s.Message -match 'Tamper Protection|Access denied'){$cat='Security.SymantecTamperProtection';$title='Symantec Tamper Protection / Access Denied near crash';$conf=0.9}; $find += [PSCustomObject]@{Severity='P1';Category=$cat;Confidence=$conf;Title=$title;Evidence="Crash=$($c.Process) at $($c.TimeCreated); Security=$($s.ProviderName)/$($s.EventId) at $($s.TimeCreated); DeltaSeconds=$([int]$d); Message=$(SafeStr $s.Message 700)";Recommendation='Validate by IT-controlled whitelist/disable policy. Collect dump and inspect injected modules.'} } }catch{} } }
  if(@($werReports|Where-Object {$_.Status -ne 'NO_ROWS'}).Count -gt 0){ $find += [PSCustomObject]@{Severity='INFO';Category='Crash.WERReportsFound';Confidence=0.95;Title='WER reports found';Evidence="ReportCount=$(@($werReports).Count)";Recommendation='Check 04_wer_reports and WER_Report_wers. Dump binaries are not copied.'} }
  if(@($snaps|Where-Object {$_.Name -match 'WerFault'}).Count -gt 0){ $find += [PSCustomObject]@{Severity='P1';Category='Crash.WerFaultObserved';Confidence=0.85;Title='WerFault.exe observed during probe';Evidence='WerFault was seen in process snapshots.';Recommendation='Correlate Application Error 1000 and WER 1001.'} }
  $dedup=@(); $seen=@{}; foreach($f in $find){ $k="$($f.Category)|$($f.Title)|$(SafeStr $f.Evidence 250)"; if(!$seen.ContainsKey($k)){$seen[$k]=$true;$dedup+=$f} }
  return [PSCustomObject]@{Crashes=$crashes;WerEvents=$wers;SecuritySignals=$secs;Timeline=@($timeline|Sort-Object TimeCreated);Findings=$dedup}
}

function WriteReports($a){
  ($a|ConvertTo-Json -Depth 8) | Out-File (Join-Path $script:OutDir 'FINDINGS.json') -Encoding UTF8
  $tl=@('# WinFaultDiag Timeline','','| Time | Kind | Provider | EventId | Process | Detail |','|---|---|---|---:|---|---|')
  foreach($e in ($a.Timeline|Sort-Object TimeCreated)){ $d=([string]$e.Detail).Replace('|','\|').Replace("`r",' ').Replace("`n",' '); if($d.Length -gt 500){$d=$d.Substring(0,500)+'...'}; $tl += "| $($e.TimeCreated) | $($e.Kind) | $($e.Provider) | $($e.EventId) | $($e.Process) | $d |" }
  $tl -join "`r`n" | Out-File (Join-Path $script:OutDir 'TIMELINE.md') -Encoding UTF8
  $sum=@('# WinFaultDiag Summary','',"Generated: $(Get-Date -Format o)",'','## Target','',"- TargetProcessName: `$TargetProcessName`","- TargetExePath: `$TargetExePath`","- Keywords: `$Keywords`","- Hours: `$Hours`","- RunProbe: `$RunProbe`","- EnableLocalDumps: `$EnableLocalDumps`","- Output: `$script:OutDir`",'','## Top Findings','')
  $ordered=@($a.Findings|Sort-Object @{Expression={switch($_.Severity){'P0'{0};'P1'{1};'P2'{2};'INFO'{9};default{5}}}},@{Expression='Confidence';Descending=$true})
  if($ordered.Count -eq 0){$sum += 'No high-confidence findings. Check raw event files.'} else { foreach($f in ($ordered|Select-Object -First 20)){ $sum += "### [$($f.Severity)] $($f.Title)"; $sum += ''; $sum += "- Category: `$($f.Category)`"; $sum += "- Confidence: `$($f.Confidence)`"; $sum += "- Evidence: $($f.Evidence)"; $sum += "- Recommendation: $($f.Recommendation)"; $sum += '' } }
  $sum += '## Crash Signatures'; $sum += ''
  if($a.Crashes.Count -eq 0){$sum += 'No Application Error 1000 crash signatures parsed.'} else { $sum += '| Time | Process | Module | Exception | Path |'; $sum += '|---|---|---|---|---|'; foreach($c in ($a.Crashes|Sort-Object TimeCreated -Descending|Select-Object -First 30)){ $sum += "| $($c.TimeCreated) | $($c.Process) | $($c.Module) | $($c.ExceptionCode) | $($c.ApplicationPath) |" } }
  $sum += ''; $sum += '## Important Files'; $sum += '- `TIMELINE.md`'; $sum += '- `FINDINGS.json`'; $sum += '- `03_application_crash_events.*`'; $sum += '- `04_wer_reports.*` and `WER_Report_wers/`'; $sum += '- `05_security_relevant_events.*`'; $sum += '- `06_process_snapshots.*`'; $sum += '- `09_registry_policy_indicators.*`'; $sum += '- `10_existing_dumps.*`'; $sum += ''; $sum += '## Privacy'; $sum += 'Reports can include local paths, usernames, process command lines, policies, and event messages. Review before sharing.'
  $sum -join "`r`n" | Out-File (Join-Path $script:OutDir 'SUMMARY.md') -Encoding UTF8
}
function WriteGuide(){ @'
# Where to look manually

Run `eventvwr.msc`.

Check:

1. Windows Logs -> Application
   - Application Error 1000
   - Windows Error Reporting 1001
   - Application Hang 1002
   - .NET Runtime 1026
   - Symantec AntiVirus 45

2. Windows Logs -> System

3. Applications and Services Logs -> Microsoft -> Windows -> CodeIntegrity -> Operational

4. Applications and Services Logs -> Microsoft -> Windows -> AppLocker
   - EXE and DLL
   - MSI and Script
   - Packaged app-Execution
   - Packaged app-Deployment

5. Applications and Services Logs -> Microsoft -> Windows -> Windows Defender -> Operational

Reliability Monitor: `perfmon /rel`

WER paths:

- `C:\ProgramData\Microsoft\Windows\WER\ReportArchive`
- `C:\ProgramData\Microsoft\Windows\WER\ReportQueue`
- `%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive`
- `%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue`

WinDbg commands:

```
.symfix
.reload
!analyze -v
lm
kv
```
'@ | Out-File (Join-Path $script:OutDir 'WHERE_TO_LOOK.md') -Encoding UTF8 }

# Main
$timestamp=Get-Date -Format 'yyyyMMdd-HHmmss'; $script:OutDir=Join-Path $OutputRoot "WinFaultDiag-$timestamp"; New-Item -ItemType Directory -Force -Path $script:OutDir | Out-Null
$startTime=(Get-Date).AddHours(-1*$Hours); $norm=NormProc $TargetProcessName; $exeName=NormExe $TargetProcessName
$terms=New-Object System.Collections.Generic.List[string]
if($norm){$terms.Add([regex]::Escape($norm));$terms.Add([regex]::Escape($exeName))}
if($TargetExePath){try{$terms.Add([regex]::Escape((Split-Path $TargetExePath -Leaf))); $parent=Split-Path $TargetExePath -Parent; if($parent){$terms.Add([regex]::Escape($parent))}}catch{}}
foreach($k in ($Keywords -split ',')){if($k.Trim()){$terms.Add([regex]::Escape($k.Trim()))}}
foreach($k in @('WerFault','Windows Error Reporting','Application Error','msedgewebview2','msedge','chrome','electron','WebView2','Symantec','Defender','CodeIntegrity','AppLocker','Access denied','Tamper Protection','agentshell_guard')){$terms.Add([regex]::Escape($k))}
$pattern=(($terms|Select-Object -Unique)-join '|'); if(!$pattern){$pattern='Application Error|Windows Error Reporting|WerFault'}
Write-Host "WinFaultDiag output: $script:OutDir"
Write-Host "SearchPattern: $pattern"

TryDo { ExportRows @([PSCustomObject]@{Name='Generated';Value=(Get-Date -Format o)},[PSCustomObject]@{Name='Computer';Value=$env:COMPUTERNAME},[PSCustomObject]@{Name='User';Value="$env:USERDOMAIN\$env:USERNAME"},[PSCustomObject]@{Name='IsAdmin';Value=(IsAdmin)},[PSCustomObject]@{Name='TargetProcessName';Value=$TargetProcessName},[PSCustomObject]@{Name='TargetExePath';Value=$TargetExePath},[PSCustomObject]@{Name='Keywords';Value=$Keywords},[PSCustomObject]@{Name='Hours';Value=$Hours},[PSCustomObject]@{Name='RunProbe';Value=$RunProbe},[PSCustomObject]@{Name='EnableLocalDumps';Value=$EnableLocalDumps},[PSCustomObject]@{Name='DumpFolder';Value=$DumpFolder}) '01_system' } 'system'
TryDo { if($TargetExePath){ExportRows (FileInfoSafe $TargetExePath) '02_target_file_info'} else {ExportRows @([PSCustomObject]@{Status='NO_TARGET_EXE';Message='TargetExePath not provided.'}) '02_target_file_info'} } 'fileinfo'
TryDo { if($EnableLocalDumps -or $DisableLocalDumps){ExportRows (ConfigDumps -Enable:$EnableLocalDumps -Disable:$DisableLocalDumps) '02_localdumps_config_result'} else {ExportRows @([PSCustomObject]@{Status='NOT_REQUESTED';Message='Use -EnableLocalDumps or -DisableLocalDumps.'}) '02_localdumps_config_result'} } 'dumps-config'
TryDo { ExportRows (GetAppEvents $startTime $pattern) '03_application_crash_events' } 'app-events'
TryDo { ExportRows (GetWERReports $startTime $pattern) '04_wer_reports' } 'wer'
TryDo { ExportRows (GetSecurityEvents $startTime $pattern) '05_security_relevant_events' } 'security'
TryDo { ExportRows (GetProcs $pattern) '06_process_live_before_probe' } 'procs-before'
$probeRows=@()
TryDo { if($RunProbe){ if(!$TargetExePath -or !(Test-Path $TargetExePath)){ $probeRows=@([PSCustomObject]@{Tag='ProbeStartError';Time=Get-Date;ProcessId=$null;ParentProcessId=$null;Name='__ERROR__';ExecutablePath=$TargetExePath;CommandLine='TargetExePath is empty or not found.';CreationDate=$null}) } else { if($KillExisting){ $kill=@(); if($norm){$kill+=$norm}; $kill+=@('msedge','msedgewebview2','WerFault'); foreach($kn in ($kill|Select-Object -Unique)){try{Get-Process $kn -ErrorAction SilentlyContinue|Stop-Process -Force -ErrorAction SilentlyContinue}catch{}}; Start-Sleep -Seconds 1 }; try{$p=Start-Process -FilePath $TargetExePath -PassThru -ErrorAction Stop; $probeRows += [PSCustomObject]@{Tag='ProbeStart';Time=Get-Date;ProcessId=$p.Id;ParentProcessId=$null;Name=(Split-Path $TargetExePath -Leaf);ExecutablePath=$TargetExePath;CommandLine='Started by WinFaultDiag';CreationDate=$null}}catch{$probeRows += [PSCustomObject]@{Tag='ProbeStartError';Time=Get-Date;ProcessId=$null;ParentProcessId=$null;Name='__ERROR__';ExecutablePath=$TargetExePath;CommandLine=$_.Exception.Message;CreationDate=$null}}; $probeRows += ObserveProcs $pattern $ObserveSeconds 'ProbeObserve'; if($p){$alive=[bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue);$exit='';if(!$alive){try{$p.Refresh();$exit=$p.ExitCode}catch{}};$probeRows += [PSCustomObject]@{Tag='ProbeResult';Time=Get-Date;ProcessId=$p.Id;ParentProcessId=$null;Name=(Split-Path $TargetExePath -Leaf);ExecutablePath=$TargetExePath;CommandLine="Alive=$alive; ExitCode=$exit";CreationDate=$null}} } } else {$probeRows=@([PSCustomObject]@{Tag='NO_PROBE';Time=Get-Date;ProcessId=$null;ParentProcessId=$null;Name='';ExecutablePath='';CommandLine='RunProbe not requested.';CreationDate=$null})}; ExportRows $probeRows '06_process_snapshots' } 'probe'
TryDo { if($IncludeModuleList){ExportRows (GetModules $pattern) '07_loaded_modules'} else {ExportRows @([PSCustomObject]@{Status='NOT_REQUESTED';Message='Use -IncludeModuleList.'}) '07_loaded_modules'} } 'modules'
TryDo { $regs=@('HKLM:\SOFTWARE\Policies\Microsoft\Edge','HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate','HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2','HKCU:\SOFTWARE\Policies\Microsoft\Edge','HKCU:\SOFTWARE\Policies\Microsoft\EdgeUpdate','HKCU:\SOFTWARE\Policies\Microsoft\Edge\WebView2','HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender','HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'); ExportRows (GetRegRows $regs) '09_registry_policy_indicators' } 'registry'
TryDo { ExportRows (GetDumps $pattern) '10_existing_dumps' } 'existing-dumps'
TryDo { $analysis=Analyze (ReadCsv (Join-Path $script:OutDir '03_application_crash_events.csv')) (ReadCsv (Join-Path $script:OutDir '05_security_relevant_events.csv')) (ReadCsv (Join-Path $script:OutDir '04_wer_reports.csv')) (ReadCsv (Join-Path $script:OutDir '06_process_snapshots.csv')); ExportRows $analysis.Crashes '08_parsed_crashes'; ExportRows $analysis.WerEvents '08_parsed_wer_events'; ExportRows $analysis.SecuritySignals '08_parsed_security_signals'; ExportRows $analysis.Findings '08_findings'; WriteReports $analysis } 'analysis'
TryDo { WriteGuide } 'guide'
TryDo { $zip="$script:OutDir.zip"; if(Test-Path $zip){Remove-Item $zip -Force}; Compress-Archive -Path (Join-Path $script:OutDir '*') -DestinationPath $zip -Force; "ZIP: $zip" | Out-File (Join-Path $script:OutDir 'ZIP_PATH.txt') -Encoding UTF8; Write-Host "Done."; Write-Host "Report directory: $script:OutDir"; Write-Host "Zip: $zip"; Write-Host "Open SUMMARY.md first." } 'zip'
try{ Get-Content (Join-Path $script:OutDir 'SUMMARY.md') -ErrorAction SilentlyContinue | Write-Host }catch{}
