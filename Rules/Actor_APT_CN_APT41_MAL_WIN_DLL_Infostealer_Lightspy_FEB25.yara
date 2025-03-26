import "pe"

rule Actor_APT_CN_APT41_MAL_WIN_DLL_Infostealer_Lightspy_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects an information gathering utility known which is a Windows DLL known as Lightspy that is attributed to APT41"
    source = "https://www.securityweek.com/lightspy-ios-spyware-operation-expands-to-windows/"
    credit = "@Now_on_VT for notifying the malware sample being available on VirusTotal https://x.com/Now_on_VT/status/1887064609359544613"
    filehash = "37a1ffaba2e3ea9a7b2aa272b0587826cc0b5909497d3744ec8c114b504d2544"
  
  strings:
    $wide1 = "explorer.exe" wide fullword
    $wide2 = "\\temp\\db.sqlite" wide fullword
    $wide3 = "\\db.sqlite" wide fullword
    $wide4 = "\\db.sqlite-shm" wide fullword
    $wide5 = "\\db.sqlite-wal" wide fullword
    $wide6 = "\\temp\\config.json" wide fullword

    $str1 = "C:\\Program Files (x86)\\Common Files\\SSL"
    $str2 = "C:\\Program Files (x86)\\OpenSSL\\lib\\engines-3"
    $str3 = "C:\\Program Files (x86)\\OpenSSL\\lib\\ossl-modules"
    $str4 = "D:\\CFILES\\Projects\\WinSSL\\openssl-3.0.2-temp_32\\crypto\\err\\err_local.h"
    $str5 = "DROP TABLE '%q'.'%q_node'"
    $str6 = "DROP TABLE '%q'.'%q_rowid'"
    $str7 = "DROP TABLE '%q'.'%q_parent'"

    $signal1 = "signal.dll" ascii fullword
    $signal2 = "signal" ascii fullword
    $signal3 = "%AppData%\\Signal" wide fullword
    $signal4 = "%AppData%\\Signal\\config.json" wide fullword

  condition:
    ((pe.pdb_path contains "G:\\xmh_miqu_key\\xmh\\密取\\")
    or
    (pe.exports("Start")
    and 3 of ($wide*)
    and 5 of ($str*)
    and 2 of ($signal*)))
    and filesize < 3MB
    
}
