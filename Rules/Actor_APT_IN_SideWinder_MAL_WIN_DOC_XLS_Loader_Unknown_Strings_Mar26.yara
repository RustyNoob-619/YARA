rule Actor_APT_IN_SideWinder_MAL_WIN_DOC_XLS_Loader_Unknown_Strings_Mar26
{
    meta:
        rule_id = "9ff03925-a252-4100-b8ea-e6e1cb526774"
        date = "02-03-2026"
        author = "RustyNoob619"
        description = "Detects Excel docs potentially used by Indian APT SideWinder based on observed strings"
        source = "https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh/"
        filehash = "1946315d645d9a8c5114759b350ec4f85dba5f9ee4a63d74437d7a068bff7752"

     strings:
        $exec = "Workbook_Open" ascii wide

        $dev = ".workers.dev" ascii wide

        $net = "MSXML2.ServerXMLHTTP.6.0" ascii wide

        $shell = "ShellWindowsExec" ascii wide

        $path = "C:\\ProgramData\\"

        $file1 = ".exe" ascii wide
        $file2 = ".dll" ascii wide
        $file3 = ".pdf" ascii wide
    
    condition:
        uint32be(0) == 0xD0CF11E0
        and $exec 
        and $dev 
        and $net
        and $shell
        and $path 
        and any of ($file*)
        and filesize < 2MB 

}
