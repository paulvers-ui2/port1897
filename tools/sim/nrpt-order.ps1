# Copyright (c) 2026 RethinkDNS and its authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Which of two catch-all (".") NRPT rules does Windows' DNS Client apply?
# Runs on a CI runner (admin) only: it writes two rules under the registry
# key the engines use, in both creation orders, nudges the DNS Client as the
# engines do, and reports the server the policy names. Both rules are
# removed again. Nothing else is changed.
#
#   pwsh tools/sim/nrpt-order.ps1

$ErrorActionPreference = 'Stop'
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
$low = '{00000000-0000-4000-8000-000000000001}'
$high = '{FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFE}'

function Rule([string]$key, [string]$server, [string]$name) {
  $p = Join-Path $base $key
  New-Item -Path $p -Force | Out-Null
  New-ItemProperty -Path $p -Name Version -PropertyType DWord -Value 2 -Force | Out-Null
  New-ItemProperty -Path $p -Name Name -PropertyType MultiString -Value @('.') -Force | Out-Null
  New-ItemProperty -Path $p -Name GenericDNSServers -PropertyType String -Value $server -Force | Out-Null
  New-ItemProperty -Path $p -Name ConfigOptions -PropertyType DWord -Value 8 -Force | Out-Null
  New-ItemProperty -Path $p -Name Comment -PropertyType String -Value $name -Force | Out-Null
  New-ItemProperty -Path $p -Name DisplayName -PropertyType String -Value $name -Force | Out-Null
  New-ItemProperty -Path $p -Name IPSECCARestriction -PropertyType String -Value '' -Force | Out-Null
}

function Clear-Rules { foreach ($k in $low, $high) { Remove-Item -Path (Join-Path $base $k) -Recurse -Force -ErrorAction SilentlyContinue } }

# the engines' nudge: flush, then ipconfig /registerdns, waited for
function Nudge {
  Clear-DnsClientCache
  & "$env:SystemRoot\System32\ipconfig.exe" /registerdns | Out-Null
  Clear-DnsClientCache
}

function Applied {
  $deadline = (Get-Date).AddSeconds(10)
  do {
    $s = @(Get-DnsClientNrptPolicy | Where-Object Namespace -eq '.' | ForEach-Object { $_.NameServers }) -join ','
    if ($s) { return $s }
    Start-Sleep -Milliseconds 200
  } while ((Get-Date) -lt $deadline)
  return '(none)'
}

$out = @()
try {
  Clear-Rules; Nudge
  foreach ($trial in 1..2) {
    # low key first, then high key
    Clear-Rules; Nudge
    Rule $low '10.9.9.1' 'Low key'
    Nudge; $a1 = Applied
    Rule $high '10.9.9.2' 'High key'
    Nudge; $a2 = Applied
    $out += "trial $trial, low created first: after low $a1; after high too $a2"
    # high key first, then low key
    Clear-Rules; Nudge
    Rule $high '10.9.9.2' 'High key'
    Nudge; $b1 = Applied
    Rule $low '10.9.9.1' 'Low key'
    Nudge; $b2 = Applied
    $out += "trial $trial, high created first: after high $b1; after low too $b2"
  }
  # the same two rules with PowerShell's own cmdlet for the second one, as
  # the e2e script adds the other VPN's
  Clear-Rules; Nudge
  Rule $high '10.9.9.2' 'High key'
  Nudge
  Add-DnsClientNrptRule -Namespace '.' -NameServers '10.9.9.3' -DisplayName 'Cmdlet rule' -Comment 'Cmdlet rule'
  $cmdKey = (Get-DnsClientNrptRule | Where-Object DisplayName -eq 'Cmdlet rule').Name
  $c = Applied
  $out += "cmdlet rule $cmdKey added after the high-key rule: $c"
  Get-DnsClientNrptRule | Where-Object DisplayName -eq 'Cmdlet rule' | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
} finally {
  Clear-Rules
  Nudge
}
$out | ForEach-Object { Write-Host "NRPT ORDER: $_" }
if ($env:GITHUB_STEP_SUMMARY) { (@('## NRPT rule order', '') + ($out | ForEach-Object { "- $_" })) | Add-Content $env:GITHUB_STEP_SUMMARY }
