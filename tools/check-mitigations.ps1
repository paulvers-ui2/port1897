# Copyright (c) 2026 RethinkDNS and its authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Checks that each exe or dll has Windows' exploit mitigations against memory
# corruption on, from its PE header:
#   ASLR      DYNAMIC_BASE, and relocations kept: loaded at a random address
#   64-bit    HIGH_ENTROPY_VA: ASLR with the full 64-bit address space (for
#             64-bit files; a 32-bit one has no use for it)
#   DEP       NX_COMPAT: data (stack, heap) is never executable
#   CFG       GUARD_CF: indirect calls only to known targets (reported; Go
#             does not emit it, Electron and Wintun do)
# Go builds the first three by default (-buildmode=pie on Windows); this
# keeps every release that way. Exit code 1 if one is missing.
param([Parameter(Mandatory)][string[]]$Path)

$failed = 0
foreach ($f in $Path) {
  $b = [IO.File]::ReadAllBytes((Resolve-Path $f))
  $pe = [BitConverter]::ToInt32($b, 0x3C)
  if ($b[$pe] -ne 0x50 -or $b[$pe + 1] -ne 0x45) { Write-Host "FAIL $f`: not a PE file"; $failed++; continue }
  $coff = $pe + 4
  $relocsStripped = ([BitConverter]::ToUInt16($b, $coff + 18) -band 0x0001) -ne 0
  $pe64 = [BitConverter]::ToUInt16($b, $coff + 20) -eq 0x20b # OptionalHeader.Magic: PE32+
  $dll = [BitConverter]::ToUInt16($b, $coff + 20 + 70) # OptionalHeader.DllCharacteristics
  $has = [ordered]@{
    'ASLR'    = (($dll -band 0x0040) -ne 0) -and -not $relocsStripped
    '64-bit'  = (($dll -band 0x0020) -ne 0) -or -not $pe64
    'DEP'     = ($dll -band 0x0100) -ne 0
  }
  $cfg = ($dll -band 0x4000) -ne 0
  $missing = @($has.Keys | Where-Object { -not $has[$_] })
  $line = ($has.Keys | ForEach-Object { "$_ $(if ($has[$_]) { 'on' } else { 'OFF' })" }) -join ', '
  if ($missing) { $failed++; Write-Host "FAIL $f`: $line, CFG $(if ($cfg) { 'on' } else { 'off' })" }
  else { Write-Host "ok   $f`: $line, CFG $(if ($cfg) { 'on' } else { 'off' })" }
}
if ($failed) { exit 1 }
