import "pe"

rule Actor_APT_DPRK_PRESSURE_CHOLLIMA_MAL_WIN_PE_Implant_GhostShip_PEProperties_Apr26
{
    meta:
        rule_id = "3953afef-8801-417d-86bc-faaf8d1d2583"
        date = "01-04-2026"
        author = "Rustynoob619"
        description = "Detects GhostShip malware used by DPRK APT PRESSURE CHOLLIMA based on PE Properties"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "56e51244e258c39293463c8cf02f5dddb085be90728fab147a60741cf014aa4d"
    
    condition:
        uint16(0) == 0x5a4d
        and pe.imports("NETAPI32.dll", "NetUseAdd")
        and pe.imports("MPR.dll", "WNetOpenEnumW")
        and pe.exports("AsyncLoadDB")
        and pe.exports("ServiceMain")
        and filesize < 10MB
}
