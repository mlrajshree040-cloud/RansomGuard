/*
   RansomGuard — LYNX Ransomware Detection Rule
   Author: RansomGuard Project (based on DNSC public rule)
   Date: 2026-10-04
   Family: LYNX Ransomware
   Severity: CRITICAL
   Reference: https://www.dnsc.ro/citeste/alerta-lynx-ransomware-indicators-of-compromise-iocs
*/

rule Ransomware_LYNX_1 {
    meta:
        description = "Detects LYNX ransomware"
        author = "RansomGuard Project (based on DNSC rule)"
        family = "ransomware.lynx"
        severity = 10
        mitre = "T1486"
    strings:
        $s1 = "[+] Successfully decoded readme!" fullword ascii
        $s2 = "[-] Failed to get service information for %s: %s" fullword wide
        $s3 = "--file C:\\temp.txt,D:\\temp2.txt" fullword ascii
        $s4 = "--file C:\\temp.txt" fullword ascii
        $s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
        $s10 = "[%s] Try to stop processes via RestartManager" fullword wide
        $s11 = "[%s] Kill processes and services" fullword wide
        $s12 = "Load hidden drives (will corrupt boot loader)" fullword ascii
        $s13 = "README.txt" fullword wide
        $s16 = "Try to stop processes via RestartManager" fullword ascii
        $s17 = "Kill processes/services" fullword ascii
        $s18 = "--stop-processes " fullword ascii
        $s19 = "--stop-processes" fullword wide
        $s20 = "[%s] Encrypt network shares" fullword wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 500KB and
        (8 of them)
}