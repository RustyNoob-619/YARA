import "elf"

rule Actor_APT_DPRK_PRESSURE_CHOLLIMA_MAL_LNX_ELF_Implant_Scuzzyfuss_Multiple_Mar26
{
    meta:
        rule_id = "18439d1f-6f62-4411-ae56-9a076bb8c1e1"
        date = "30-03-2026"
        author = "Rustynoob619"
        description = "Detects Scuzzyfuss malware used by DPRK APT PRESSURE CHOLLIMA based on observed strings and ELF Telfhash"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "b9f6a9d4f837f5b8a5dc9987a91ba44bc7ae7f39aa692b5b21dba460f935a0ae"

    strings:
        $spec1 = ".local.onion" ascii
        $spec2 = "chacha20poly1305" ascii
    
    condition:
        uint32(0) == 0x464c457f
        and elf.telfhash() == "T1A001760D2D380BCAD8499E099D1946E67463DB142823DB09FF02ED882DFD400F6299AE"
        and all of ($spec*)
        and filesize < 5MB
}
