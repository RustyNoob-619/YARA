import "pe"

rule Actor_APT_CN_APT41_MAL_WIN_EXE_Infostealer_Lightspy_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects an information gathering utility known which is a Windows executable known as Lightspy that is attributed to APT41"
    source = "https://www.securityweek.com/lightspy-ios-spyware-operation-expands-to-windows/"
    credit = "@Now_on_VT for notifying the malware sample being available on VirusTotal https://x.com/Now_on_VT/status/1886079788307173426"
    filehash = "ccfd6ef35c718e2484b3727035d162b667f4b56df43324782d106f50ed1e3bcc"
  
  strings:
    $wide1 = "explorer.exe" wide fullword
    $wide2 = "WhatsApp.exe" wide fullword
    $wide3 = "\\temp\\settings.db" wide fullword
    $wide4 = "\\temp\\settings.db-shm" wide fullword
    $wide5 = "\\temp\\settings.db-wal" wide fullword
    $wide6 = "Desktop capture" wide fullword

    $whatsapp1 = "C:\\cygwin\\data\\sandcastle\\boxes\\trunk-git-whatsapp-" ascii
    $whatsapp2 = "whatsapp_directx_utils.cpp" ascii 
    $whatsapp3 = "whatsapp_swap_chain.cpp" ascii 
    $whatsapp4 = "whatsapp.net" ascii

  condition:
    ((pe.pdb_path contains "G:\\xmh_miqu_key\\xmh\\密取\\")
    or
    (4 of ($wide*)
    and 2 of ($whatsapp*)))
    and filesize < 11MB
    
}
