# Copyright (c) 2026 RethinkDNS and its authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Long and heavy traffic through the tunnel on a real Windows machine (a
# GitHub runner): the engine runs in DNS-only mode, so the runner keeps its
# own connection, and one host route sends a speed-test server's address
# through the AuroraVPN adapter. Everything to that address then goes app ->
# Wintun -> gVisor -> firestack -> the network, as every app's traffic does
# in full mode. Checked:
#   one slow download that lasts about 2.5 minutes (a long-lived connection)
#   64 downloads at once
#   100 MB up
#   1 GiB down on one connection, every byte
#   the engine is still up, answering, and its memory did not run away
# A server that does not answer without the tunnel either (a check first)
# skips the checks instead of failing them: the server is not ours.
# Every check is recorded; the script exits 1 if any check failed.
#
#   pwsh tools/sim/tunnel-soak.ps1 -Dist dist -Out sim-out

param(
  [string]$Dist = 'dist',
  [string]$Out = 'sim-out'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$fswin = (Resolve-Path (Join-Path $Dist 'fswin.exe')).Path
$api = '127.0.0.1:47897'
$tokFile = Join-Path $Out 'soak-api-token'
$token = 'soak' + [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($tokFile, $token)
$hdr = @{ Authorization = "Bearer $token" }
$hostName = 'speed.cloudflare.com'
$results = [Collections.Generic.List[object]]::new()

function Check([string]$what, [bool]$ok, [string]$detail = '') {
  $r = if ($ok) { 'PASS' } else { 'FAIL' }
  $results.Add([pscustomobject]@{ Check = $what; Result = $r; Detail = $detail })
  Write-Host "[$r] $what $(if ($detail) { "-- $detail" })"
}

function Note([string]$what, [string]$detail) {
  $results.Add([pscustomobject]@{ Check = $what; Result = 'INFO'; Detail = $detail })
  Write-Host "[INFO] $what -- $detail"
}

function Api([string]$path, [string]$method = 'GET') {
  Invoke-RestMethod -Uri "http://$api$path" -Headers $hdr -Method $method -TimeoutSec 5
}

# curl pinned to $pin (host:port:ip); prints "<http code> <bytes down> <bytes up> <seconds>"
function Curl([string]$pin, [string[]]$extra) {
  $w = '%{http_code} %{size_download} %{size_upload} %{time_total}'
  $o = & curl.exe -s -o NUL --resolve $pin --max-time 900 -w $w @extra
  $f = "$o".Trim() -split ' '
  [pscustomobject]@{ Code = $f[0]; Down = [int64]$f[1]; Up = [int64]$f[2]; Seconds = [double]$f[3]; Raw = "$o" }
}

function IPv4([string]$name) {
  (Resolve-DnsName $name -Type A -Server 1.1.1.1 | Where-Object IPAddress | Select-Object -First 1).IPAddress
}

# The one big file: 1 GiB from Tele2's public test-file server, on one
# connection (Cloudflare's speed test stops answering one machine after
# about 750 MB, seen on the runner, which is not the tunnel's doing).
$bigHost = 'speedtest.tele2.net'
$bigSize = 1073741824

$f = $null
$routes = @()
try {
  $ip = IPv4 $hostName
  $bigIp = IPv4 $bigHost
  Note 'test servers' "$hostName = $ip, $bigHost = $bigIp"
  $cf = "${hostName}:443:$ip"
  $big = "${bigHost}:80:$bigIp"

  # without the tunnel first: are the servers there at all?
  $base = Curl $cf @("https://$hostName/__down?bytes=10000000")
  if ($base.Code -ne '200' -or $base.Down -ne 10000000) {
    Note 'skipped' "$hostName does not answer without the tunnel either: $($base.Raw)"
    return
  }
  Note 'without the tunnel' ("10 MB in {0:N1} s" -f $base.Seconds)
  $bigLen = (& curl.exe -sI --resolve $big --max-time 30 "http://$bigHost/1GB.zip" | Select-String -Pattern '^Content-Length:\s*(\d+)' | ForEach-Object { [int64]$_.Matches[0].Groups[1].Value } | Select-Object -First 1)
  $bigThere = $bigLen -eq $bigSize
  if (-not $bigThere) { Note '1 GiB file' "skipped: $bigHost does not offer it without the tunnel either (Content-Length $bigLen)" }

  $log = Join-Path $Out 'soak.engine.log'
  $p = Start-Process -FilePath $fswin -ArgumentList @('-api', $api, '-token-file', $tokFile, '-logfile', $log, '-dns', 'doh') -PassThru -WindowStyle Hidden
  $f = $p
  $up = $false
  for ($i = 0; $i -lt 90 -and -not $up; $i++) {
    Start-Sleep -Milliseconds 500
    try { $null = Api '/api/status'; $up = $true } catch {}
  }
  Check 'the engine comes up' $up ''
  if (-not $up) { return }

  foreach ($a in @($ip, $bigIp) | Select-Object -Unique) {
    New-NetRoute -DestinationPrefix "$a/32" -InterfaceAlias 'AuroraVPN' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    $routes += $a
    $via = (Find-NetRoute -RemoteIPAddress $a | Where-Object InterfaceAlias | Select-Object -First 1).InterfaceAlias
    Check "$a is reached through the tunnel" ($via -eq 'AuroraVPN') "via $via"
  }
  $mem0 = (Get-Process -Id $p.Id).WorkingSet64

  # one connection that lasts: 30 MB at 200 KB/s, about 2.5 minutes
  $r = Curl $cf @('--limit-rate', '200K', "https://$hostName/__down?bytes=30000000")
  Check 'a 2.5-minute download on one connection completes' ($r.Code -eq '200' -and $r.Down -eq 30000000) ("{0:N0} bytes in {1:N0} s, HTTP {2}" -f $r.Down, $r.Seconds, $r.Code)

  # 64 at once
  $urls = 1..64 | ForEach-Object { "https://$hostName/__down?bytes=1000000&n=$_" }
  $args64 = @('--parallel', '--parallel-max', '64') + ($urls | ForEach-Object { @('-o', 'NUL', $_) })
  $codes = & curl.exe -s --resolve $cf --max-time 300 -w '%{http_code}\n' @args64
  $good = @($codes | Where-Object { $_ -eq '200' }).Count
  Check '64 downloads at once all complete' ($good -eq 64) "$good/64; codes: $(($codes | Group-Object | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')"

  # 100 MB up
  $file = Join-Path $env:RUNNER_TEMP 'soak-up.bin'
  $buf = [byte[]]::new(1MB)
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $fs = [IO.File]::Create($file)
  for ($i = 0; $i -lt 100; $i++) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
  $fs.Close()
  $r = Curl $cf @('-X', 'POST', '--data-binary', "@$file", "https://$hostName/__up")
  Check '100 MB up through the tunnel' ($r.Code -eq '200' -and $r.Up -eq 104857600) ("{0} bytes, HTTP {1}, {2:N0} s" -f $r.Up, $r.Code, $r.Seconds)
  Remove-Item $file -ErrorAction SilentlyContinue

  # 1 GiB down on one connection, every byte
  if ($bigThere) {
    $r = Curl $big @("http://$bigHost/1GB.zip")
    Check '1 GiB down through the tunnel on one connection, every byte' ($r.Code -eq '200' -and $r.Down -eq $bigSize) ("{0:N0} of {1:N0} bytes in {2:N0} s ({3:N0} Mbit/s), HTTP {4}" -f $r.Down, $bigSize, $r.Seconds, ($r.Down * 8 / 1e6 / [math]::Max($r.Seconds, 1)), $r.Code)
  }

  # still up, and what it costs
  $st = $null
  try { $st = Api '/api/status' } catch {}
  Check 'the engine is still up and answering' ($null -ne $st -and -not $p.HasExited) ''
  if ($st) { Note 'traffic counted by the engine' ("{0:N0} MB down, {1:N0} MB up" -f ($st.traffic.rx / 1e6), ($st.traffic.tx / 1e6)) }
  $mem1 = (Get-Process -Id $p.Id).WorkingSet64
  Check 'its memory stays bounded (< 400 MB)' ($mem1 -lt 400MB) ("{0:N0} MB -> {1:N0} MB" -f ($mem0 / 1MB), ($mem1 / 1MB))
  $panics = @(Select-String -Path $log -Pattern 'panic|fatal error' -ErrorAction SilentlyContinue).Count
  Check 'no panic in the engine log' ($panics -eq 0) "$panics"
} catch {
  Check 'ran to the end' $false "$_"
} finally {
  foreach ($a in $routes) { Remove-NetRoute -DestinationPrefix "$a/32" -InterfaceAlias 'AuroraVPN' -Confirm:$false -ErrorAction SilentlyContinue }
  if ($f) {
    try { $null = Api '/api/stop' 'POST' } catch {}
    if (-not $f.WaitForExit(45000)) { Stop-Process -Id $f.Id -Force -ErrorAction SilentlyContinue }
    & $fswin -cleanup | Out-Null
  }
  $failed = @($results | Where-Object Result -eq 'FAIL').Count
  $md = @('## Long and heavy traffic through the tunnel', '', '| Check | Result | Detail |', '|---|---|---|') + ($results | ForEach-Object { "| $($_.Check) | $($_.Result) | $(($_.Detail -replace '\|', '\|' -replace "`r?`n", ' ')) |" })
  if ($env:GITHUB_STEP_SUMMARY) { $md -join "`n" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY }
  Write-Host "$($results.Count) checks, $failed failed"
  if ($failed) { exit 1 }
}
