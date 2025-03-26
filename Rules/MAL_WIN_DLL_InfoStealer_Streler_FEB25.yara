import "pe"

rule MAL_WIN_DLL_InfoStealer_Streler_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects an infostealer called Streler Stealer based on PE properties and strings"
    source = "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2025-02-10-IOCs-for-StrelaStealer-activity.txt"
    filehash = "0e8e0a57a3cc02c8666378463e1bde1697c3e6bb14e5b773f644e06ea05ab41c"
  
  strings:
    $dll1 = ".dll"
    $dll2 = "DllRegisterServer"
    $regex = /DllRegisterServer\n[a-zA-Z]{1024}/

  condition:
    pe.exports("DllRegisterServer") 
    and pe.sections[4].name == ".00cfg"
    and all of them
    and filesize < 1MB
}
