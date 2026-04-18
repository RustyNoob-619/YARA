import "pe"

rule Actor_APT_DPRK_Konni_MAL_WIN_PE_Multiple_PEProperties_Mar26
{
    meta:
        rule_id = "7e4b3d22-9253-4ce4-b796-d9467c63fb9f"
        date = "14-03-2026"
        author = "Rustynoob619"
        description = "Detects malware used by DPRK APT Konni based on known PE import hashes"
        source = "https://www.genians.co.kr/en/blog/threat_intelligence/kakaotalk"
        filehash1 = "aa51573f9abcd4a1ec4a61ee7e5811c0279e015ea22bdb787780d67ce7153a57"
        filehash2 = "798af20db39280f90a1d35f2ac2c1d62124d1f5218a2a0fa29d87a13340bd3e4"
        filehash3 = "ac92d4c6397eb4451095949ac485ef4ec38501d7bb6f475419529ae67e297753"

    condition:
        uint16(0) == 0x5a4d
        and pe.imphash() == "0efd6cb0c6e770fe9c94ebe37a1fcc56"
        and filesize < 5MB

}
