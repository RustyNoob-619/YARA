rule Actor_APT_DPRK_GOLDEN_CHOLLIMA_MAL_LNX_ELF_Implant_HTTPHelper_Strings_Apr26
{
    meta:
        rule_id = "2e2704b6-d303-4a3e-a535-df8481162c94"
        date = "03-04-2026"
        author = "Rustynoob619"
        description = "Detects HTTPHelper malware used by DPRK APT GOLDEN CHOLLIMA based on ELF Telfhash"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "ff32bc1c756d560d8a9815db458f438d63b1dcb7e9930ef5b8639a55fa7762c9"

    condition:
        uint32(0) == 0x464c457f
        and elf.telfhash() == "T1F211EB06A83D8AA946E24D648C150BD3109BDB76A572EA18FF94DED054AF446F118C8F"
        and filesize < 5MB
}
