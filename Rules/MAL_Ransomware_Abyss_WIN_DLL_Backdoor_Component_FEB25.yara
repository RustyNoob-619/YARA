import "pe"

rule MAL_Ransomware_Abyss_WIN_DLL_Backdoor_Component_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Windows Backdoor used by Abyss Ransomware based on anomaly in PE properties"
    source = "https://www.sygnia.co/blog/abyss-locker-ransomware-attack-analysis/"
    filehash = "05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da"
    
  condition:
    pe.number_of_signatures == 0 
    and pe.imphash() == "698fa83da166edb916866ef085b426d9"
    and pe.version_info["ProductName"] == "Windows Service Wrapper"
    and pe.version_info["InternalName"] == "WinSW.dll"
    and filesize > 15MB
    // Contains an embedded DOS executable in the resources
}


