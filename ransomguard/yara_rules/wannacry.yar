/*
   RansomGuard — WannaCry Detection Rule
   Author: RansomGuard Project (based on Florian Roth's public rule)
   Date: 2026-10-04
   Family: WannaCry / WanaCrypt0r
   Severity: CRITICAL
   Reference: https://mobile.ransomware.live/yara/wannacry/WannaCry_Ransomware_2.yar
*/

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry Ransomware"
        author = "RansomGuard Project (based on Florian Roth rule)"
        family = "ransomware.wannacry"
        severity = 10
        mitre = "T1486"
    strings:
        $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
        $x2 = "taskdl.exe" fullword ascii
        $x3 = "tasksche.exe" fullword ascii
        $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
        $x5 = "WNcry@2ol7" fullword ascii
        $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $x7 = "mssecsvc.exe" fullword ascii
        $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
        $s1 = "C:\\%s\\%s" fullword ascii
        $s4 = "msg/m_portuguese.wnry" fullword ascii
        $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
        $s6 = "\\\\172.16.99.5\\IPC$" fullword wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 10000KB and
        (1 of ($x*) and 1 of ($s*) or 3 of them)
}