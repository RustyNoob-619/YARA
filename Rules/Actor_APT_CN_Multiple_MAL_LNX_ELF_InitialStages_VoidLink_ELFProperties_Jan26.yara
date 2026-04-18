import "elf"

rule Actor_APT_CN_Multiple_MAL_LNX_ELF_InitialStages_VoidLink_ELFProperties_Jan26
{
    meta:
        rule_id = "353d6da4-4e96-4f1a-9280-db6b8b3753ca"
        date = "20-01-2026"
        author = "Rustynoob619"
        description = "Detects stages 1 and 2 which drop VoidLink Linux Backdoor used by Chinese Nexus Threat Actors based on TELFHash"
        source = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        filehash = "13025f83ee515b299632d267f94b37c71115b22447a0425ac7baed4bf60b95cd"

    condition:
        uint32be(0) == 0x7f454c46
        and (elf.telfhash() == "t12db0120802d820326b9094d00e5e2e0d315501c58b0d2d0850844300514cf18251e03c" 
        or elf.telfhash() == "t150b0120c730203b5d781d07b078413062ca014810616d4c842414304199832cb30c1b3")
        and filesize < 250KB

}
