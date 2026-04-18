rule Actor_APT_WesternAsia_UNG0801_MAL_WIN_PDF_Dropper_Unknown_Strings_Jan26
{
    meta:
        rule_id = "908bdc32-35ba-4ce4-959e-f4a5c57a5382"
        date = "14-01-2026"
        author = "Rustynoob619"
        description = "Detects Malicious PDFs used by UNG0801 based on Author ID"
        source = "https://malware.news/t/ung0801-tracking-threat-clusters-obsessed-with-av-icon-spoofing-targeting-israel/102767"
        filehash = "e422c2f25fbb4951f069c6ba24e9b917e95edb9019c10d34de4309f480c342df"

    strings:
        $id1 = "7xnid3yrpbejwky4911q1iudi"
        $id2 = "AEFE7BCF-CA45-4D89-B6CD-8AAEC63A3A92"
        $id2 = "CF7BFEAE45CA894DB6CD8AAEC63A3A92"

        $timezone = {(43 72 65 61 74 69 6f 6e | 4d 6f 64) 44 61 74 65 28 44 3a [14] 2b 30 33 27 33 30 27 29}
        
    condition:
        uint32be(0) == 0x25504446
        any of ($id*)
        and $timezone
        and filesize < 5MB

}
