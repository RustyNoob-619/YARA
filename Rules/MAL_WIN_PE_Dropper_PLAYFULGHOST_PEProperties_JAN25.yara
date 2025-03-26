
import "pe"

rule MAL_WIN_PE_Dropper_PLAYFULGHOST_PEProperties_JAN25
{
  meta:
    author = "Rustynoob619"
    description = "Detects installers used to distribute PLAYFULLGHOST via SEO poisoning impersonating letsvpn VPN Software"
    reference = "https://www.googlecloudcommunity.com/gc/Community-Blog/Finding-Malware-Unveiling-PLAYFULGHOST-with-Google-Security/ba-p/850676"
    filehash = "ea6ecd69cf96eefa353fca6f20a8b0d5fe43d1a7927b9bf919182900c90a89fc"
  
  condition:
    ((pe.version_info["FileDescription"] == "letsvpn-latest Installer"
    and pe.version_info["InternalName"] == "letsvpn-latest")
    or pe.version_info["InternalName"] == "Copyright (C) 2024 MonKeyDu")
    and pe.pdb_path == "C:\\ReleaseAI\\win\\Release\\stubs\\x86\\ExternalUi.pdb"
    and pe.language(0x0004) //Chinese Simplified Language
    and pe.imphash() == "608505ff1e7e27ff4a42ea9c4e9f4192"
    and filesize > 10MB
    and filesize < 25MB
}


