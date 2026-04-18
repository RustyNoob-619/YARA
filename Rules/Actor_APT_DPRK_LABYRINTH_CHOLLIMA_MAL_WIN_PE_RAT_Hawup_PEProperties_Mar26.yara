import "pe"

rule Actor_APT_DPRK_LABYRINTH_CHOLLIMA_MAL_WIN_PE_RAT_Hawup_PEProperties_Mar26
{
    meta:
        rule_id = "1da0c483-0494-416c-a9e2-bae0fbdd61bf"
        date = "29-03-2026"
        author = "Rustynoob619"
        description = "Detects Hawup RAT used by DPRK APT LABYRINTH CHOLLIMA based on PE Properties"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "453d8bd3e2069bc50703eb4c5d278aad02304d4dc5d804ad2ec00b2343feb7a4"

    condition:
        uint16(0) == 0x5a4d
        and pe.imports("OLEAUT32.dll", "SystemTimeToVariantTime")
        and pe.imports("USERENV.dll", "CreateEnvironmentBlock")
        and pe.imports("WS2_32.dll", "ioctlsocket")
        and pe.imports("PSAPI.DLL", "EnumProcessModules")
        and pe.imports("USER32.dll", "GetSystemMetrics")
        and filesize < 500KB

}
