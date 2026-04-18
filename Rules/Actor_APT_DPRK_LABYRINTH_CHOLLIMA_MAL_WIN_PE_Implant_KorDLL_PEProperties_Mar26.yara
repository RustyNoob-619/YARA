import "pe"

rule Actor_APT_DPRK_LABYRINTH_CHOLLIMA_MAL_WIN_PE_Implant_KorDLL_PEProperties_Mar26
{
    meta:
        rule_id = "55c57bc3-28f6-4043-b9f2-d28b2015cb9f"
        date = "28-03-2026"
        author = "Rustynoob619"
        description = "Detects KorDLL malware used by DPRK APT LABYRINTH CHOLLIMA based on PE Properties"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "73edc54abb3d6b8df6bd1e4a77c373314cbe99a660c8c6eea770673063f55503"

    condition:
        uint16(0) == 0x5a4d
        and pe.locale(0x0412)
        and pe.number_of_exports < 5
        and pe.exports("SecuritySetting")
        and filesize < 500KB

}
