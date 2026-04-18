import "lnk"

rule Actor_APT_CN_MustangPanda_MAL_WIN_LNK_Artifacts_1_Mar26
{
    meta:
        rule_id = "615c409c-a026-497a-a7f0-01d6718939e6"
        date = "19-03-2026"
        author = "Rustynoob619"
        description = "Detects LNK files used by Chinese APT Mustang Panda"
        source = "https://dreamgroup.com/plugx-diplomacy-mustang-panda-campaign/"
        filehash = "e79d19d68d307c12413f8549aafa4a56776002dd04601e36e0125b2e6d56ff94"

    condition:
        uint32be(0) == 0x4c000000
        and (
            lnk.icon_location == ".\\WindowssSystem326Shell32.pdf"
            )
        and filesize < 50KB

}
