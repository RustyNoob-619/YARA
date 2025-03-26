import "pe"

rule MAL_WIN_PE_Loader_Guloader_PDBPath_Mar25
{
    meta:
        rule_id = "fd0b69cf-24c3-4841-b401-6ec709263515"
        date = "24-03-2025"
        author = "RustyNoob619"
        description = "Detects Windows malware associated with the specified PDB Path. Malware attribution stats Amadey/Guloader/Lumma"
        source = "https://x.com/ViriBack/status/1903973216193773820"
        filehash = "24ebbd5c8625e4819eaafb2f7350be565cc1048fcef9eb4ea86921f261b88ddb"

    strings:
        $cmd = "cmd.exe /c" ascii
        $vbs = ".vbs" ascii

        $str1 = "rundll32.exe"
        $str2 = "wextract_cleanup%d"
        $str3 = "%s /D:%s"

    condition:
        pe.pdb_path == "wextract.pdb"
        and $cmd
        and $vbs
        and any of ($str*)
        and filesize < 1MB

}

//publicKeyToken="6595b64144ccf1df"

