import "lnk"

rule Actor_APT_Unknown_CamelClone_MAL_WIN_LNK_Loader_HOPINGANT_Strings_Mar26
{
    meta:
        rule_id = "35a6fc81-f8d0-4aa3-9183-37db1db4eebf"
        date = "18-03-2026"
        author = "Rustynoob619"
        description = "Detects LNK loader used to deploy HOPINGANT which is part of operation CamelClone"
        source = "https://www.seqrite.com/blog/operation-camelclone-multi-region-espionage-campaign-targets-government-and-defense-entities-amidst-regional-tensions/"
        filehash = "92962bfa6df48ec0f13713c437af021f4138dc5a419bc92bc8a376d625a6519a"

    condition:
        uint32be(0) == 0x4c000000
        and (
            (lnk.cmd_line_args contains "Invoke-WebRequest" and lnk.cmd_line_args endswith "-OutFile $f;./f.js;\"") or
            lnk.tracker_data.machine_id == "desktop-jm38b85" or
            lnk.drive_serial_number == 0x44466ABA
            )
        and filesize < 50KB

}
