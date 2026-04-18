import "elf"

rule Actor_APT_CN_APT41_MAL_LNX_ELF_Backdoor_Winnti_Strings_Apr26
{
    meta:
        rule_id = "de6c9acc-2915-40d3-aa81-7ca7df8a4bd9"
        date = "07-04-2026"
        author = "Rustynoob619"
        description = "Detects an ELF backdoor known as Winnti used by Chinese APT41 based on ELF Telfhash"
        source = "https://intel.breakglass.tech/post/apt41-winnti-elf-backdoor-cloud-credential-harvester-alibaba-typosquat"
        filehash = "0fca9dae54a7a55f0805a864e9d2911d727a6e274f4ddc9b5673078130e0f9e1"

    condition:
        uint32(0) == 0x464c457f
        and elf.telfhash() == "T10AF00242FE3EAF0511F24C708CF457E65083A14364355B05EF64DED0483EA07E36891E"
        and filesize < 5MB
}
