/*
   RansomGuard — Generic Ransomware Behavior Rules
   Author: RansomGuard Project
   Date: 2026-10-04
   Description: Detects generic ransomware indicators
*/

rule Ransomware_RansomNote_Strings {
    meta:
        description = "Detects common ransom note phrases"
        severity = "high"
        family = "generic"
        mitre = "T1486"
    strings:
        $phrase1 = "your files have been encrypted" nocase
        $phrase2 = "your data has been encrypted" nocase
        $phrase3 = "all your files have been encrypted" nocase
        $phrase4 = "pay bitcoin" nocase
        $phrase5 = "send bitcoin" nocase
        $phrase6 = "decrypt your files" nocase
        $phrase7 = "recover your files" nocase
        $phrase8 = "decryption key" nocase
        $phrase9 = "contact us on" nocase
        $phrase10 = "proof of decryption" nocase
        $phrase11 = "how to buy bitcoin" nocase
        $phrase12 = "your documents, photos, databases" nocase
        $phrase13 = "pay the ransom" nocase
        $phrase14 = "ransom note" nocase
        $phrase15 = "tor browser" nocase
    condition:
        uint16(0) == 0x5A4D or   // PE file
        3 of them
}

rule Ransomware_CryptoAPI_Strings {
    meta:
        description = "Detects cryptographic API usage typical of ransomware"
        severity = "medium"
        family = "generic"
        mitre = "T1486"
    strings:
        $api1 = "CryptEncrypt" ascii wide
        $api2 = "CryptGenKey" ascii wide
        $api3 = "CryptImportKey" ascii wide
        $api4 = "CryptAcquireContext" ascii wide
        $api5 = "CryptDeriveKey" ascii wide
        $cng1 = "BCryptEncrypt" ascii wide
        $cng2 = "BCryptGenerateSymmetricKey" ascii wide
        $cng3 = "BCryptImportKeyPair" ascii wide
        $cng4 = "BCryptOpenAlgorithmProvider" ascii wide
        $algo1 = "AES-256" ascii wide nocase
        $algo2 = "ChaCha20" ascii wide
        $algo3 = "RSA-2048" ascii wide nocase
        $algo4 = "RSA-4096" ascii wide nocase
        $algo5 = "Salsa20" ascii wide
        $file_op1 = "FindFirstFileW" ascii
        $file_op2 = "FindNextFileW" ascii
        $file_op3 = "MoveFileExW" ascii
        $file_op4 = "SetFileAttributesW" ascii
        $file_op5 = "WriteFile" ascii
    condition:
        (2 of ($api*) or 2 of ($cng*)) and
        (2 of ($file_op*)) and
        (1 of ($algo*))
}

rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Detects commands used to delete shadow copies (backup destruction)"
        severity = "critical"
        family = "generic"
        mitre = "T1490"
    strings:
        $shadow1 = "vssadmin delete shadows" nocase
        $shadow2 = "vssadmin.exe delete shadows" nocase
        $shadow3 = "wmic shadowcopy delete" nocase
        $shadow4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $shadow5 = "bcdedit /set {default} recoveryenabled no" nocase
        $shadow6 = "wbadmin delete catalog" nocase
        $shadow7 = "wbadmin delete systemstatebackup" nocase
        $shadow8 = "diskshadow.exe" nocase
    condition:
        any of them
}

rule Ransomware_Security_Process_Kill {
    meta:
        description = "Detects attempts to kill security software (typical of ransomware)"
        severity = "high"
        family = "generic"
        mitre = "T1562"
    strings:
        $kill1 = "taskkill /IM MsMpEng.exe" nocase
        $kill2 = "taskkill /IM kavsvc.exe" nocase
        $kill3 = "taskkill /IM avp.exe" nocase
        $kill4 = "taskkill /IM mcshield.exe" nocase
        $kill5 = "taskkill /IM sqlserver.exe" nocase
        $kill6 = "taskkill /IM vmware" nocase
        $kill7 = "net stop WinDefend" nocase
        $kill8 = "sc stop WinDefend" nocase
    condition:
        any of them
}