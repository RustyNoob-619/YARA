rule Actor_APT_IN_SideWinder_MAL_WIN_DLL_Stealer_Unknown_Multiple_Mar26
{
    meta:
        rule_id = "31d3bca0-1dff-4848-ac6d-a0ec16143b69"
        date = "06-03-2026"
        author = "RustyNoob619"
        description = "Detects a Rust based keylogger DLL used by Indian APT SideWinder based on observed strings and PE exports"
        source = "https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh/"
        filehash = "4f1628821c13cc27fd4134301cc93a1ad32b2a3f7066c3d90f7ba89e02180754"

    strings:
        $rust1 = "rustc"
        $rust2 = "cargo"

        $src1 = "src\\cp.rs"
        $src2 = "src\\ls.rs"
        $src3 = "src\\key.rs"
        $src4 = "src\\lib.rs"
        $src5 = "src\\shell.rs"
        $src6 = "src\\check.rs"
        $src7 = "src\\download.rs"
        $src8 = "src\\portscan.rs"
        $src9 = "src\\move_file.rs"
        $src10 = "src\\polymorph.rs"

        $log1 = "=== KEYLOGGER SUMMARY ===" ascii
        $log2 = "[ENTER][TAB]" ascii fullword
        $log3 = "[BACK][ESC][LEFT][UP][RIGHT][DOWN][DEL][HOME][END][PGUP][PGDN]" ascii fullword
        
    condition:
        uint16(0) == 0x5a4d
        and any of ($rust*)
        and any of ($log*)
        and 6 of ($src*)
        and for 10 export in pe.export_details:
        (export.name startswith "SL" or export.name startswith "SystemFunction")
        and filesize < 500KB 

}
