import "pe"

rule Actor_APT_CN_APT41_MAL_WIN_DLL_Backdoor_PoisonPlug_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects an advanced modular backdoor known as Poison Plug that is used by APT41 in multiple cyber espionage operations"
    source = "https://cloud.google.com/blog/topics/threat-intelligence/scatterbrain-unmasking-poisonplug-obfuscator"
    filehash = "60678e352f3c849e36413f5de51b5eeca1180840c818f9ece0a0da803eb205a5"
    
  condition:
    (pe.signatures[0].thumbprint == "8b9aa1ffdad6b6ea8a3919be2790be549451002d" //En Masse Entertainment
    or 
    for 250 export in pe.export_details:
    (export.name startswith "??" and (export.name endswith "@Z" or export.name endswith "XZ")))
    and filesize < 500KB
}


