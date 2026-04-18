
rule Actor_APT_IN_SideWinder_MAL_WIN_DLL_Stealer_Unknown_Artifacts_1_Mar26
{
    meta:
        rule_id = "72933144-4c63-4170-bf0d-0fa4edc0867a"
        date = "05-03-2026"
        author = "RustyNoob619"
        description = "Detects a Rust based keylogger DLL used by Indian APT SideWinder based on observed artifacts"
        source = "https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh/"
        filehash = "4f1628821c13cc27fd4134301cc93a1ad32b2a3f7066c3d90f7ba89e02180754"

    strings:
        $guid1 = "8125dc46-4859-4c6d-a96b-d844258dc66d" ascii wide
        $guid2 = "8acdd28-3daa-4861-b6ab-ef3f1e5df441" ascii wide
        $user = "C:\\Users\\pakis\\.cargo\\registry\\src\\" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and (
            any of ($guid*)
            or #user > 10
            )
        and filesize < 1MB 

}
