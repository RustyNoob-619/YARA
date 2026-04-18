import "pe"

rule Actor_APT_IN_SideWinder_MAL_WIN_DLL_Stealer_Unknown_PEProperties_Mar26
{
    meta:
        rule_id = "45064689-5e96-4384-9b3f-db6d3069cdb1"
        date = "04-03-2026"
        author = "RustyNoob619"
        description = "Detects a Rust based keylogger DLL used by Indian APT SideWinder based on PE imports and rich signatures"
        source = "https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh/"
        filehash = "4f1628821c13cc27fd4134301cc93a1ad32b2a3f7066c3d90f7ba89e02180754"

    condition:
        uint16(0) == 0x5a4d
        and 
        (
            (pe.imphash() == "5a6540455d80ed239b52640f22d38d29" or
            pe.imphash() == "bb2856c96e0753660afaf053dd563493")
            and
            (
                pe.rich_signature.version(30729) == 6 and
                (
                    pe.rich_signature.toolid(0x101, 35207) == 2 and 
                    pe.rich_signature.toolid(0x103, 35207) == 3 and 
                    pe.rich_signature.toolid(0x104, 35207) == 7 and
                    pe.rich_signature.toolid(0x105, 35207) == 16
                )
                or 
                (
                    pe.rich_signature.toolid(0x101, 34918) == 2 and 
                    pe.rich_signature.toolid(0x103, 34918) == 3 and 
                    pe.rich_signature.toolid(0x104, 34918) == 7 and
                    pe.rich_signature.toolid(0x105, 34918) == 16
                )
            )
        )
        and filesize < 500KB 

}
