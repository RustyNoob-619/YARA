import "lnk"

rule Actor_APT_PK_SideCopy_MAL_WIN_LNK_Loader_Unknown_LNKProperties_Jan26
{
    meta:
        rule_id = "bbe9eaa2-a544-4f3e-b613-d87f5329c897"
        date = "23-01-2026"
        author = "Rustynoob619"
        description = "Detects LNK files used by Pakistan APT SideCopy based on LNK properties"
        source = "https://x.com/PrakkiSathwik/status/1991453048523382885"
        filehash = "e5a87d76be18ac47dd410cede8960ffde2f6105e7bf9a50ca682a4f5dc3535ef"
        credit = "Thanks to @PrakkiSathwik for sharing the file hashes and intel"

    condition:
        uint32be(0) == 0x4C000000
        and lnk.cmd_line_args startswith "/c m^s^i^e^x^e^"
        and (
            lnk.tracker_data.machine_id == "lab1-c" or 
            lnk.tracker_data.machine_id == "team-alpha" or 
            lnk.tracker_data.machine_id == "desktop-tmsj8ut"
        )
        and filesize < 10KB
}
