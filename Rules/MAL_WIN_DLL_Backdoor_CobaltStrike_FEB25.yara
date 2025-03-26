import "pe"

rule MAL_WIN_DLL_Backdoor_CobaltStrike_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Cobalt Strike DLLs with the watermark ==> malware_config:0x50ee04f5"
    credit = "@smica83 for sharing the malware sample"
    source = "https://x.com/smica83/status/1885420988042514707"
    filehash = "2a0711ff1abedfb0b9aa624d734389606a5b945900cf60b79e88ec44724d3341"
  
  condition:
    (pe.imphash() == "3313599cb95cc22c1d1c3c1a380a574a" or pe.pdb_path == "F:\\Windows\\Immersive\\ControlPanelSettings\\UIRibbon\\x64\\Release\\UIRibbon.pdb")
    or (pe.locale(0x0419) //Russian
    and pe.exports("DllCanUnloadNow")
    and pe.exports("DllGetClassObject")
    and pe.exports("DllRegisterServer")
    and pe.exports("DllUnregisterServer"))
    and filesize < 20MB
}
