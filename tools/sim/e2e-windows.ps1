# Copyright (c) 2026 RethinkDNS and its authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# End-to-end simulation of fswin on a real Windows machine (a GitHub runner,
# which is admin): starts the engine in DNS-only mode, so the runner keeps
# its own connection, and replays the failures seen on users' PCs:
#   baseline       DoH works; queries to our DNS address are not logged as flows
#   doh-unreachable  the DoH server's IPs never answer (Proton VPN case)
#   doh-firewalled   Windows Firewall blocks fswin's DoH connections
#   other-vpn      another VPN's catch-all NRPT rule; fswin must warn
#   servfail / refused / nxdomain / drop   a plain DNS upstream misbehaving
# Every check is recorded; the script exits 1 if any check failed.
#
#   pwsh tools/sim/e2e-windows.ps1 -Dist dist -Out sim-out

param(
  [string]$Dist = 'dist',
  [string]$Out = 'sim-out'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$fswin = (Resolve-Path (Join-Path $Dist 'fswin.exe')).Path
$fakedns = (Resolve-Path (Join-Path $Dist 'fakedns.exe')).Path
$api = '127.0.0.1:47897'
$tokFile = Join-Path $Out 'api-token'
$token = 'sim' + [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($tokFile, $token)
$hdr = @{ Authorization = "Bearer $token" }
$fake4 = '10.111.222.3'
$results = [Collections.Generic.List[object]]::new()

function Check([string]$scenario, [string]$what, [bool]$ok, [string]$detail = '') {
  $r = if ($ok) { 'PASS' } else { 'FAIL' }
  $results.Add([pscustomobject]@{ Scenario = $scenario; Check = $what; Result = $r; Detail = $detail })
  Write-Host "[$r] ${scenario}: $what $(if ($detail) { "-- $detail" })"
}

function Note([string]$scenario, [string]$what, [string]$detail) {
  $results.Add([pscustomobject]@{ Scenario = $scenario; Check = $what; Result = 'INFO'; Detail = $detail })
  Write-Host "[INFO] ${scenario}: $what -- $detail"
}

function Api([string]$path, [string]$method = 'GET') {
  Invoke-RestMethod -Uri "http://$api$path" -Headers $hdr -Method $method -TimeoutSec 5
}

function Start-Fswin([string]$name, [string[]]$extra) {
  $log = Join-Path $Out "$name.engine.log"
  $argv = @('-api', $api, '-token-file', $tokFile, '-logfile', $log) + $extra
  Write-Host "--- $name`: fswin $($argv -join ' ')"
  $p = Start-Process -FilePath $fswin -ArgumentList $argv -PassThru -WindowStyle Hidden
  for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Milliseconds 500
    try { $null = Api '/api/status'; return [pscustomobject]@{ Proc = $p; Log = $log } } catch {}
    if ($p.HasExited) { break }
  }
  throw "fswin ($name) did not come up (exit $($p.ExitCode)); log:`n$(Get-Content $log -Raw -ErrorAction SilentlyContinue)"
}

function Stop-Fswin($f) {
  try { $null = Api '/api/stop' 'POST' } catch {}
  if (-not $f.Proc.WaitForExit(45000)) { Stop-Process -Id $f.Proc.Id -Force -ErrorAction SilentlyContinue }
  & $fswin -cleanup | Out-Null
}

function Start-FakeDns([string]$addr, [string]$mode) {
  $log = Join-Path $Out "fakedns-$mode.log"
  $p = Start-Process -FilePath $fakedns -ArgumentList @('-addr', $addr, '-mode', $mode) -PassThru -NoNewWindow -RedirectStandardError $log -RedirectStandardOutput "$log.out"
  Start-Sleep -Seconds 1
  if ($p.HasExited) { throw "fakedns $mode did not start: $(Get-Content $log -Raw)" }
  $p
}

# Resolve asks our DNS address directly; Windows gives up long before a
# failing upstream does, so the answer is read back from fswin's events.
function Resolve([string]$name) {
  try {
    $r = Resolve-DnsName -Name $name -Type A -Server $fake4 -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop
    ($r | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ','
  } catch {
    "error: $($_.Exception.Message)"
  }
}

function Wait-DnsEvent([string]$domain, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $ev = @(Api '/api/events?after=0&max=2000') | ForEach-Object { $_ } | Where-Object { $_.kind -eq 'dns' -and $_.domain -eq $domain } | Select-Object -Last 1
    if ($ev) { return $ev }
    Start-Sleep -Seconds 1
  }
  $null
}

function Events() { @(Api '/api/events?after=0&max=2000') | ForEach-Object { $_ } }

function LogHas($f, [string]$pattern) { [bool](Select-String -Path $f.Log -Pattern $pattern -Quiet) }

function Rand([string]$tag) { "sim-$tag-$([guid]::NewGuid().ToString('N').Substring(0, 8)).example.com" }

function Remove-SimRules {
  Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Sim VPN' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
  Remove-NetFirewallRule -DisplayName 'sim-block-doh' -ErrorAction SilentlyContinue
}

$fakes = @()
try {
  & $fswin -version
  Remove-SimRules

  # ---------- baseline ----------
  $s = 'baseline'
  $f = Start-Fswin $s @('-dns', 'doh')
  $ans = Resolve 'example.com'
  Check $s 'example.com resolves through fswin' ($ans -match '^\d') $ans
  $ev = Wait-DnsEvent 'example.com' 30
  Check $s 'DNS event recorded, without an error' ($ev -and -not $ev.error) ($ev | ConvertTo-Json -Compress)
  $flows = @(Events | Where-Object { $_.kind -eq 'flow' -and $_.dst -eq "${fake4}:53" })
  Check $s "queries to ${fake4}:53 are not logged as flows" ($flows.Count -eq 0) "$($flows.Count) flow events"
  $st = Api '/api/status'
  Check $s 'status has an empty conflicts list' (($st.PSObject.Properties.Name -contains 'conflicts') -and @($st.conflicts).Count -eq 0) (($st.conflicts | ConvertTo-Json -Compress))
  Check $s 'status counts no failed lookups' ($st.dns.failed -eq 0) "queries $($st.dns.queries), failed $($st.dns.failed)"
  Check $s 'engine log names the adapter firestack uses' (LogHas $f "own traffic leaves via interface #\d+ \S") ''
  Check $s "firestack's own log lines reach engine.log, with timestamps" (LogHas $f '^\d\d:\d\d:\d\d\.\d{6} ') ''
  $env:SIM_LIVE = '1'; $env:SIM_TUN = 'port1897'
  $live = go test -count=1 -run '^TestDescribeLive$' -v ./win/ifbind 2>&1
  $live | Set-Content (Join-Path $Out 'describe-live.txt')
  Check $s 'other-VPN detection: fswin adapter is a VPN, the default-route adapter is not' ($LASTEXITCODE -eq 0) (($live | Select-String 'Describe|default route|FAIL|Error' | Select-Object -First 12) -join ' | ')
  Stop-Fswin $f
  Check $s 'fswin removed its adapter on stop' (-not (Get-NetAdapter -Name 'port1897' -ErrorAction SilentlyContinue)) ''

  # ---------- DoH server unreachable (the Proton VPN incident) ----------
  $s = 'doh-unreachable'
  $f = Start-Fswin $s @('-dns', 'doh', '-doh-ips', '192.0.2.1,198.51.100.1')
  $name = Rand 'unreach'
  $ans = Resolve $name
  Note $s 'Windows sees' $ans
  $ev = Wait-DnsEvent $name 120
  Check $s 'the failed lookup is recorded' ([bool]$ev) ($ev | ConvertTo-Json -Compress)
  if ($ev) {
    Check $s 'the DNS log says the server never replied' ($ev.error -match 'no reply from') $ev.error
    Note $s 'latency' "$($ev.latencyMs) ms"
  }
  $st = Api '/api/status'
  Check $s 'status counts the failure' ($st.dns.failed -ge 1) "failed $($st.dns.failed)"
  Check $s "firestack's dial error is in engine.log" (LogHas $f 'i/o timeout|timed out|timeout') ''
  Stop-Fswin $f

  # ---------- DoH blocked by Windows Firewall ----------
  $s = 'doh-firewalled'
  $fwOn = @(Get-NetFirewallProfile | Where-Object Enabled).Count -gt 0
  New-NetFirewallRule -DisplayName 'sim-block-doh' -Direction Outbound -Program $fswin -RemoteAddress 1.1.1.1, 1.0.0.1 -Protocol TCP -RemotePort 443 -Action Block | Out-Null
  $f = Start-Fswin $s @('-dns', 'doh')
  $name = Rand 'fw'
  $null = Resolve $name
  $ev = Wait-DnsEvent $name 120
  if ($fwOn) {
    Check $s 'the blocked lookup fails with a reason' ($ev -and $ev.error) ($ev | ConvertTo-Json -Compress)
  } else {
    Note $s 'Windows Firewall is off on this runner; result only' ($ev | ConvertTo-Json -Compress)
  }
  Stop-Fswin $f
  Remove-NetFirewallRule -DisplayName 'sim-block-doh'

  # ---------- another VPN's catch-all DNS rule ----------
  $s = 'other-vpn'
  Add-DnsClientNrptRule -Namespace '.' -NameServers '10.2.0.1' -DisplayName 'Sim VPN' -Comment 'Force all DNS requests via Sim VPN'
  $f = Start-Fswin $s @('-dns', 'doh', '-nrpt')
  $st = Api '/api/status'
  Check $s 'status reports the other VPN' ((@($st.conflicts) -join ';') -match 'Sim VPN') ((@($st.conflicts) -join '; '))
  Check $s 'engine log warns about it' (LogHas $f 'warning: another VPN sends all DNS elsewhere') ''
  Note $s 'NRPT policy with both rules' ((Get-DnsClientNrptPolicy | ForEach-Object { "$($_.Namespace) -> $($_.NameServers)" }) -join '; ')
  try {
    $sys = Resolve-DnsName example.com -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object Type -eq 'A' | ForEach-Object IPAddress
    Note $s 'a normal Windows lookup with both rules' ($sys -join ',')
  } catch { Note $s 'a normal Windows lookup with both rules' "error: $($_.Exception.Message)" }
  Stop-Fswin $f
  $left = @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'port1897' -or $_.DisplayName -eq 'port1897' })
  Check $s "fswin removed its own NRPT rule on stop" ($left.Count -eq 0) "$($left.Count) left"
  Remove-SimRules

  # ---------- a plain DNS upstream that misbehaves ----------
  $hostIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -in 'Dhcp', 'Manual' -and $_.IPAddress -notlike '169.254.*' -and $_.InterfaceAlias -ne 'port1897' } | Select-Object -First 1).IPAddress
  $cases = @(
    @{ s = 'servfail'; addr = '127.0.0.1:5353'; mode = 'servfail'; want = 'answered SERVFAIL' },
    @{ s = 'refused-hostip'; addr = "${hostIP}:5354"; mode = 'refused'; want = 'answered REFUSED' },
    @{ s = 'nxdomain'; addr = '127.0.0.1:5355'; mode = 'nxdomain'; want = '' },
    @{ s = 'drop'; addr = '127.0.0.1:5356'; mode = 'drop'; want = 'no reply from' }
  )
  foreach ($c in $cases) {
    $s = $c.s
    $fakes += Start-FakeDns $c.addr $c.mode
    $f = Start-Fswin $s @('-dns', 'proxy', '-dns-proxy', $c.addr)
    $name = Rand $s
    $ans = Resolve $name
    Note $s 'Windows sees' $ans
    $ev = Wait-DnsEvent $name 90
    $st = Api '/api/status'
    if ($c.want) {
      Check $s "the DNS log says '$($c.want)'" ($ev -and $ev.error -match [regex]::Escape($c.want)) ($ev | ConvertTo-Json -Compress)
      Check $s 'status counts it as failed' ($st.dns.failed -ge 1) "failed $($st.dns.failed)"
    } else {
      Check $s 'NXDOMAIN is an answer, not a failure' ($ev -and -not $ev.error -and $st.dns.failed -eq 0) "event $($ev | ConvertTo-Json -Compress); failed $($st.dns.failed)"
    }
    Check $s 'fakedns received the query' ([bool](Select-String -Path (Join-Path $Out "fakedns-$($c.mode).log") -Pattern 'sim-' -Quiet)) ''
    Stop-Fswin $f
  }
} catch {
  Check 'script' 'ran to the end' $false "$($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
} finally {
  foreach ($p in $fakes) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  Get-Process fswin -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  & $fswin -cleanup | Out-Null
  Remove-SimRules
}

$md = @('## fswin simulation on Windows', '', '| Scenario | Check | Result | Detail |', '|---|---|---|---|')
foreach ($r in $results) {
  $d = ($r.Detail -replace '\|', '\|' -replace "`r?`n", ' ')
  if ($d.Length -gt 300) { $d = $d.Substring(0, 300) + '…' }
  $md += "| $($r.Scenario) | $($r.Check) | $($r.Result) | $d |"
}
$md | Set-Content (Join-Path $Out 'summary.md')
if ($env:GITHUB_STEP_SUMMARY) { $md | Add-Content $env:GITHUB_STEP_SUMMARY }
$failed = @($results | Where-Object Result -eq 'FAIL').Count
Write-Host "`n$($results.Count) checks, $failed failed"
if ($failed) { exit 1 }
