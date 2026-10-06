/*
   RansomGuard — LockBit 3.0 Detection Rule
   Author: RansomGuard Project
   Date: 2026-10-05
   Family: LockBit 3.0
   Severity: CRITICAL
*/

rule LockBit3_Behavioral {
    meta:
        author = "RansomGuard Project"
        family = "ransomware.lockbit3.windows"
        description = "Detects LockBit 3.0 ransomware Windows payload"
        severity = "critical"
        score = 100
        mitre = "T1486"
    strings:
        $h0 = { 64 A1 30 00 00 00 8B B0 A4 00 00 00 8B B8 A8 00 00 00 83 FE 05 75 05 83 FF 01 }
        $h1 = { 02 F1 2A F1 ?? ?? ?? ?? D3 CA 03 D0 }
        $h2 = { 3C 2B 75 04 B0 78 EB 0E 3C 2F 75 04 B0 69 EB 06 3C 3D }
        $h3 = { 33 C0 40 40 8D 0C C5 01 00 00 00 83 7D ?? 00 75 04 F7 D8 }
        $h4 = { C1 C0 09 33 ?? 8D 04 ?? C1 C0 0D 33 ?? C1 C8 0E 83 6C 24 ?? 01 }
        $h5 = { 3D B2 EB AA D4 74 07 3D C0 18 20 01 75 }
        $h6 = { B9 0D 66 19 00 ?? ?? ?? ?? F7 E1 ?? ?? ?? ?? 05 5F F3 6E 3C }
        $h7 = { 3D 75 BA 0E 64 75 ?? 83 C7 02 66 83 3F 20 74 F7 }
        $h8 = { 3D 75 80 91 76 74 0E 3D 1B A4 04 00 74 07 3D 9B B4 84 0B 75 }
    condition:
        (uint16(0) == 0x5A4D) and
        (3 of ($h*))
}