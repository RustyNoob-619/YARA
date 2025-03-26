
import "pe"

rule Actor_APT_DPRK_Kimsuky_MAL_WIN_DLL_Backdoor_BetaSeed_Mar25
{
    meta:
        rule_id = "f7920fd9-4f09-4500-a846-5c2306e784f5"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects a Backdoor known as BetaSeed used by DPRK APT Kimsuky"
        source = "https://asec.ahnlab.com/ko/59209/"
        filehash = "97df5304f53fec6a5d2d2bd75b9310a3747b681520fe45d2961bc4df86e556d7"

    condition:
        ((pe.pdb_path == "C:\\Users\\niki\\Downloads\\Troy\\Dll\\..\\_Bin\\Dll.pdb")
        or 
        (pe.imphash() == "903c6b2aff746b02e8cfc7087de5f0f4" //Needs Validation
        and pe.exports("UpdateSystem")))
        and filesize < 3MB

}