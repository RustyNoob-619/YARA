import "pe"

rule MAL_WIN_EXE_AntiAV_Powerrun_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Windows Security Control Disabling Tool known as PowerRun that was observed to be used by Abyss ransomware"
    source = "https://www.sygnia.co/blog/abyss-locker-ransomware-attack-analysis/"
    filehash = "5f9dfd9557cf3ca96a4c7f190fc598c10f8871b1313112c9aea45dc8443017a2"
  
  strings:
    $autoit1 = "AutoIt" wide fullword
    $autoit2 = "/AutoIt3ExecuteLine" wide fullword
    $autoit3 = "/AutoIt3ExecuteScript" wide fullword
    $autoit4 = "Software\\AutoIt v3\\AutoIt" wide fullword
  
    $wide1 = "HKEY_LOCAL_MACHINE" wide fullword
    $wide2 = "HKEY_CLASSES_ROOT" wide fullword
    $wide3 = "HKEY_CURRENT_CONFIG" wide fullword
    $wide4 = "HKEY_CURRENT_USER" wide fullword
    $wide5 = "HKEY_USERS" wide fullword

  condition:
    pe.imphash() == "58f9531839fd9806cc1341c1500fe433"
    and pe.signatures[0].thumbprint == "f5e71628a478a248353bf0177395223d2c5a0e43" //Sordum Software
    and 2 of ($autoit*)
    and 2 of ($wide*)
    and filesize < 1MB
    
}
