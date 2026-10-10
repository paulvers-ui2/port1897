# Copyright (c) 2026 RethinkDNS and its authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# End-to-end test of AuroraVPN Service (cmd/fswin/service_windows.go) on a
# GitHub runner (admin): installs the service for this PowerShell, which
# stands in for AuroraVPN.exe, asks it over the pipe for an engine in DNS-only
# mode, checks the engine's API and who it runs as (SYSTEM, with the user's
# files the user's), stops it both ways (the service, the app's API), has a
# standard user (no admin rights) turn it on, as with Proton VPN, checks what
# the service refuses, and uninstalls.
# Every check is recorded; the script exits 1 if any check failed.
#
#   pwsh tools/sim/service-windows.ps1 -Dist dist -Out sim-out

param(
  [string]$Dist = 'dist',
  [string]$Out = 'sim-out'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$fswin = (Resolve-Path (Join-Path $Dist 'fswin.exe')).Path
$root = (Get-Item $fswin).Directory.FullName # the service runs from here, and logs here
$me = (Get-Process -Id $PID).Path
$api = '127.0.0.1:47897'
$tokFile = Join-Path $Out 'svc-api-token'
$token = 'svc' + [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($tokFile, $token)
$hdr = @{ Authorization = "Bearer $token" }
$results = [Collections.Generic.List[object]]::new()

function Check([string]$what, [bool]$ok, [string]$detail = '') {
  $r = if ($ok) { 'PASS' } else { 'FAIL' }
  $results.Add([pscustomobject]@{ Check = $what; Result = $r; Detail = $detail })
  Write-Host "[$r] $what $(if ($detail) { "-- $detail" })"
}

# One request to the service, as the app sends it.
function Pipe([hashtable]$req) {
  $c = [IO.Pipes.NamedPipeClientStream]::new('.', 'AuroraVPN', [IO.Pipes.PipeDirection]::InOut)
  try {
    $c.Connect(5000)
    $w = [IO.StreamWriter]::new($c)
    $w.AutoFlush = $true
    $w.WriteLine(($req | ConvertTo-Json -Compress -Depth 4))
    $line = [IO.StreamReader]::new($c).ReadLine()
    return $line | ConvertFrom-Json
  } finally {
    $c.Dispose()
  }
}

function Api([string]$path, [string]$method = 'GET') {
  Invoke-RestMethod -Uri "http://$api$path" -Headers $hdr -Method $method -TimeoutSec 5
}

function Wait-Api([int]$seconds) {
  for ($i = 0; $i -lt $seconds * 2; $i++) {
    try { return Api '/api/status' } catch { Start-Sleep -Milliseconds 500 }
  }
  return $null
}

function Wait-Exit([int]$id, [int]$seconds) {
  for ($i = 0; $i -lt $seconds * 2; $i++) {
    if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

$engineArgs = @('-api', $api, '-token-file', $tokFile, '-logfile', (Join-Path $Out 'svc.engine.log'), '-dns', 'doh')

try {
  & $fswin -service install -app $me
  Check 'install exits 0' ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE"
  $svc = Get-Service AuroraVPN -ErrorAction SilentlyContinue
  Check 'the service runs' ($svc -and $svc.Status -eq 'Running') "$($svc.Status)"
  $usersWrite = (Get-Acl $root).Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }
  Check 'its folder: users cannot write' (-not $usersWrite) "$($usersWrite | ForEach-Object { "$($_.IdentityReference): $($_.FileSystemRights)" })"

  $r = Pipe @{ cmd = 'ping' }
  Check 'ping answers the installed app' ($r.ok -and $r.version) ($r | ConvertTo-Json -Compress)

  # an engine through the service
  $r = Pipe @{ cmd = 'start'; args = $engineArgs }
  Check 'start answers with the engine''s process' ($r.ok -and $r.pid -gt 0) ($r | ConvertTo-Json -Compress)
  $enginePid = $r.pid
  $st = Wait-Api 45
  Check 'the engine comes up (its API answers)' ($null -ne $st) "$(Get-Content (Join-Path $Out 'svc.engine.log') -Tail 5 -ErrorAction SilentlyContinue)"
  if ($enginePid) {
    $p = Get-Process -Id $enginePid -IncludeUserName -ErrorAction SilentlyContinue
    $mine = (Get-Process -Id $PID -IncludeUserName).UserName
    Check 'the engine runs as SYSTEM, as Proton VPN''s does' ($p -and $p.UserName -eq 'NT AUTHORITY\SYSTEM') "engine: $($p.UserName)"
    # what it writes for the user it writes as the user (-user-token)
    $owner = (Get-Acl (Join-Path $Out 'svc.engine.log') -ErrorAction SilentlyContinue).Owner
    Check 'the engine writes the user''s files as the user' ($owner -eq $mine) "log owner: $owner, app: $mine"
  }

  # what the service refuses
  $r = Pipe @{ cmd = 'start'; args = @('-usque', "$env:SystemRoot\System32\calc.exe") }
  Check 'a flag that picks a program is refused' (-not $r.ok -and $r.error -match 'not allowed') ($r | ConvertTo-Json -Compress)
  $other = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command @'
$c = New-Object IO.Pipes.NamedPipeClientStream('.', 'AuroraVPN', [IO.Pipes.PipeDirection]::InOut)
$c.Connect(5000)
$w = New-Object IO.StreamWriter($c); $w.AutoFlush = $true
$w.WriteLine('{"cmd":"ping"}')
(New-Object IO.StreamReader($c)).ReadLine()
'@
  Check 'another program is refused' ($other -match 'not the AuroraVPN app') "$other"

  # stop through the service: the engine stops as for the app
  $r = Pipe @{ cmd = 'stop' }
  Check 'stop through the service' ($r.ok) ($r | ConvertTo-Json -Compress)
  Check 'the engine exits' ($enginePid -and (Wait-Exit $enginePid 30)) ''
  Check 'the engine says the service stopped it' ((Get-Content (Join-Path $Out 'svc.engine.log') -Raw -ErrorAction SilentlyContinue) -match 'requested by AuroraVPN Service') ''

  # again, stopped by the app's own API this time
  $r = Pipe @{ cmd = 'start'; args = $engineArgs }
  $st = Wait-Api 45
  Check 'a second engine comes up' ($r.ok -and $null -ne $st) ($r | ConvertTo-Json -Compress)

  # a start as soon as the app's stop took the API down, while the old engine
  # still removes its adapter (switching exits): a new engine, not the old one
  $old = $r.pid
  try { $null = Api '/api/stop' 'POST' } catch {}
  for ($i = 0; $i -lt 100; $i++) { try { $null = Api '/api/status'; Start-Sleep -Milliseconds 100 } catch { break } }
  $r = Pipe @{ cmd = 'start'; args = $engineArgs }
  $st = Wait-Api 45
  Check 'a start while the old engine ends starts a new one' ($r.ok -and $r.pid -and $r.pid -ne $old -and $null -ne $st) "old $old, new $($r | ConvertTo-Json -Compress)"
  Check 'the old engine is gone' ($old -and (Wait-Exit $old 5)) ''
  try { $null = Api '/api/stop' 'POST' } catch {}
  Check 'the app''s stop still works' ($r.pid -and (Wait-Exit $r.pid 30)) ''

  $r = Pipe @{ cmd = 'cleanup' }
  Check 'cleanup through the service' ($r.ok) ($r | ConvertTo-Json -Compress)

  # ---------- a standard user, with no admin rights ----------
  # The same app (this PowerShell), run by a new local account in Users only:
  # the service used to refuse it ("only an administrator ..."); now it starts
  # the engine, which reads and writes that user's files as that user.
  $std = 'auroravpn-sim'
  $stdDir = 'C:\auroravpn-sim'
  try {
    # a throwaway password made in a SecureString from random bytes, never a
    # plain string; 'Aa1!' meets Windows' complexity rules
    $pw = [Security.SecureString]::new()
    foreach ($ch in [char[]]'Aa1!') { $pw.AppendChar($ch) }
    $rnd = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
    foreach ($b in $rnd) { $pw.AppendChar([char](0x61 + ($b % 26))) }
    $pw.MakeReadOnly()
    $cred = [pscredential]::new($std, $pw)
    New-LocalUser -Name $std -Password $cred.Password -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Check 'the account is not an administrator' (-not (Get-LocalGroupMember Administrators | Where-Object Name -like "*\$std")) ''
    New-Item -ItemType Directory -Force $stdDir | Out-Null
    $acl = Get-Acl $stdDir
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($std, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl $stdDir $acl
    $stdTok = Join-Path $stdDir 'api-token'
    $stdLog = Join-Path $stdDir 'engine.log'
    [IO.File]::WriteAllText($stdTok, $token)
    $req = @{ cmd = 'start'; args = @('-api', $api, '-token-file', $stdTok, '-logfile', $stdLog, '-dns', 'doh') } | ConvertTo-Json -Compress
    $script = @"
`$c = [IO.Pipes.NamedPipeClientStream]::new('.', 'AuroraVPN', [IO.Pipes.PipeDirection]::InOut)
`$c.Connect(5000)
`$w = [IO.StreamWriter]::new(`$c); `$w.AutoFlush = `$true
`$w.WriteLine('$($req -replace "'", "''")')
[IO.StreamReader]::new(`$c).ReadLine()
"@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    # the app (this PowerShell) as that user. Start-Process -Credential failed
    # here with "The parameter is incorrect": it starts in this job's folder,
    # which the new account cannot open. ProcessStartInfo sets one it can.
    $psi = [Diagnostics.ProcessStartInfo]::new($me)
    foreach ($a in '-NoProfile', '-NonInteractive', '-EncodedCommand', $enc) { $psi.ArgumentList.Add($a) }
    $psi.UserName = $std
    $psi.Domain = $env:COMPUTERNAME
    $psi.Password = $cred.Password
    $psi.LoadUserProfile = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $stdDir
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [Diagnostics.Process]::Start($psi)
    $replyText = $proc.StandardOutput.ReadToEnd()
    $errText = $proc.StandardError.ReadToEnd()
    $null = $proc.WaitForExit(60000)
    $reply = $replyText | ConvertFrom-Json -ErrorAction SilentlyContinue
    Check 'a standard user turns protection on through the service' ($reply.ok -and $reply.pid -gt 0) ("$replyText $errText".Trim())
    $st = Wait-Api 45
    Check 'the standard user''s engine comes up' ($null -ne $st) "$(Get-Content $stdLog -Tail 5 -ErrorAction SilentlyContinue)"
    $logOwner = (Get-Acl $stdLog -ErrorAction SilentlyContinue).Owner
    Check 'the engine writes the standard user''s files as that user' ($logOwner -like "*\$std") "log owner: $logOwner"
    $r = Pipe @{ cmd = 'stop' }
    Check 'and it stops' ($r.ok -and $reply.pid -and (Wait-Exit $reply.pid 30)) ($r | ConvertTo-Json -Compress)
  } catch {
    Check 'standard user scenario ran' $false "$_"
  } finally {
    Remove-LocalUser -Name $std -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $stdDir -ErrorAction SilentlyContinue
  }
} catch {
  Check 'ran to the end' $false "$_"
} finally {
  & $fswin -service uninstall
  Check 'uninstall exits 0' ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE"
  Check 'the service is gone' (-not (Get-Service AuroraVPN -ErrorAction SilentlyContinue)) ''
  $log = Join-Path $root 'service.log'
  if (Test-Path $log) { Write-Host "--- service.log"; Get-Content $log | Write-Host }
  Copy-Item $log (Join-Path $Out 'service.log') -ErrorAction SilentlyContinue
  $failed = @($results | Where-Object Result -eq 'FAIL').Count
  $md = @('## AuroraVPN Service', '', '| Check | Result | Detail |', '|---|---|---|') + ($results | ForEach-Object { "| $($_.Check) | $($_.Result) | $(($_.Detail -replace '\|', '\|' -replace "`r?`n", ' ')) |" })
  if ($env:GITHUB_STEP_SUMMARY) { $md -join "`n" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY }
  Write-Host "$($results.Count) checks, $failed failed"
  if ($failed) { exit 1 }
}
