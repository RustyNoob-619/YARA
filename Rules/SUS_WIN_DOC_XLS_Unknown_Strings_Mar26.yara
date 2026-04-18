rule SUS_WIN_DOC_XLS_Unknown_Strings_Mar26
{
    meta:
        rule_id = "796fc1bf-a88e-48d1-acf9-cae9dd8856c1"
        date = "01-03-2026"
        author = "RustyNoob619"
        description = "Detects suspicious Excel files with network connectivity capabilities which are common with downloaders"
        filehash = "1946315d645d9a8c5114759b350ec4f85dba5f9ee4a63d74437d7a068bff7752"

    strings:
        $exec1 = "Auto_Open" ascii wide
        $exec2 = "Workbook_Open" ascii wide
        $exec3 = "Document_Open" ascii wide

        $net1 = "URLDownloadToFile" ascii wide
        $net2 = "WinHttp" ascii wide
        $net3 = "msxml2.xmlhttp" ascii wide
        $net4 = "ServerXMLHTTP" ascii wide
        $net5 = "Msxml2Download" ascii wide

        $shell1 = "Shell.Application" ascii wide
        $shell2 = "WScript.Shell" ascii wide
        $shell3 = "ShellWindowsExec" ascii wide
        $shell4 = "ShellExecute" ascii wide

        $file1 = ".exe" ascii wide
        $file2 = ".dll" ascii wide
        $file3 = ".pdf" ascii wide
    
    condition:
        uint32be(0) == 0xD0CF11E0
        and any of ($exec*)
        and any of ($net*)
        and any of ($shell*)
        and any of ($file*)
        and filesize < 2MB 

}
