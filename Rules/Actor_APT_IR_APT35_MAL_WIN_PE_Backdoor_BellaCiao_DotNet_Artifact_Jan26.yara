import "dotnet"

rule Actor_APT_IR_APT35_MAL_WIN_PE_Backdoor_BellaCiao_DotNet_Artifact_Jan26
{
    meta:
        rule_id = "e17a994a-6401-4512-a3a1-103a1f2dd538"
        date = "30-01-2026"
        author = "Rustynoob619"
        description = "Detects BellaCiao backdoor used by Iranian APT35 (Charming Kitten) based on the DotNet TypeLib ID"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "2dbdd538546dcd636cc7870026322d8e7564929fd946f7145a42fc619db7cdc3"

    condition:
        uint16(0) == 0x5a4d
        and (
            dotnet.typelib == "83bf03f4-34f8-47ae-ac89-aae5129184ac"
            or dotnet.guids[0] == "ee99bd2b-23a4-4ed2-884e-d26ad621b628"
        )
        and filesize < 100KB

}
