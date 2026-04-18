
rule Actor_APT_RU_HydraSaiga_MAL_WIN_DOC_Dropper_Unknown_Strings_Mar26
{
    meta:
        rule_id = "cc209fd7-f383-4cda-a4e9-49494d8cc5c8"
        date = "10-03-2026"
        author = "Rustynoob619"
        description = "Detects malicious docs containing VBA macros used by Russian APT HydraSaiga based on observed strings"
        source = "https://www.vmray.com/hydra-saiga-covert-espionage-and-infiltration-of-critical-utilities/#elementor-toc__heading-anchor-3"
        filehash = "f78dad5a95bb01f14c822addc8e4ec17b3c95b7e42f27f68f678fb43a9e56d63"

    strings:
        $exec1 = "AutoOpen" ascii fullword 
        $exec2 = "CreateObject" ascii fullword

        $vba1 = "NewMacros" ascii 
        $vba2 = "VBE7.DLL" ascii
        $vba3 = "Module=NewMacros" ascii 

        $susp1 = "uGxaxIDnwsdD" ascii wide
        $susp3 = "guIqffZomDviGP" ascii wide
        $susp4 = "JyUthxEfeUQwOZF" ascii wide
        
        $spec1 = "CMG=\"999B708074807480748074P" ascii wide
        $spec2 = "DPB=\"1D1FF48CFC11FD11FD11" ascii wide

    condition:
        (uint32(0) == 0x04034b50 or uint32(0) == 0xe011cfd0) 
        and any of ($exec*)
        and any of ($vba*)
        and (2 of ($susp*) or any of ($spec*))
        and filesize < 250KB 
         
}
