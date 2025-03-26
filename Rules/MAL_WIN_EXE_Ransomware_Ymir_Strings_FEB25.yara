
rule MAL_WIN_EXE_Ransomware_Ymir_Strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a new ransomware targeting Windows OS known as Ymir based on strings"
    credit = "@Now_on_VT for notification of the malware sample"
    source = "https://securelist.com/new-ymir-ransomware-found-in-colombia/114493/"
    filehash = "cb88edd192d49db12f444f764c3bdc287703666167a4ca8d533d51f86ba428d8"
    
  strings:
    $exclude1 = "$recycle.bin" ascii fullword
    $exclude2 = "config.msi" ascii fullword
    $exclude3 = "program files (x86)" ascii fullword
    $exclude4 = "programdata" ascii fullword
    $exclude5 = "perflogs" ascii fullword
    $exclude6 = "x64dbg" ascii fullword

    $compile1 = "GCC: (GNU) 9.2-win32 20191008" ascii fullword
    $compile2 = "GCC: (GNU) 9.3-win32 20200320" ascii fullword
    
    $git = "https://github.com/qTox/qTox/releases/download/v1.17.6/setup-qtox-x86_64-release.exe"

    $pdf = "INCIDENT_REPORT.pdf" ascii fullword

    $ext = "6C5oy2dVr6" ascii wide fullword

    $pwrshll1 = "powershell -w h -c Start-Sleep -Seconds 5" 
    $pwrshll2 = "Remove-Item -Force -Path"
    
  condition:
    uint16(0) == 0x5a4d
    and ($git or $pdf or $ext)
    and all of ($pwrshll*)
    and 3 of ($exclude*)
    and any of ($compile*)
    and filesize < 3MB
}
