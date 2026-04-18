import "pe"

rule Actor_APT_DPRK_PRESSURE_CHOLLIMA_MAL_WIN_PE_Implant_MataNet_PEProperties_Mar26
{
    meta:
        rule_id = "a66875a0-1128-4813-9fbb-859a53e5a493"
        date = "31-03-2026"
        author = "Rustynoob619"
        description = "Detects MataNet malware used by DPRK APT PRESSURE CHOLLIMA based on PE Properties"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "357c9daf6c4343286a9a85a27bc25defdc056877ce1be2943d2e8ede3bce022c"
    
    condition:
        uint16(0) == 0x5a4d
        and pe.imports("CRYPT32.dll", "CertFreeCertificateContext")
        and pe.exports("ServiceCheck")
        and pe.exports("ServiceMain")
        and pe.exports("SvcCtrlHandler")
        and filesize < 5MB
}
