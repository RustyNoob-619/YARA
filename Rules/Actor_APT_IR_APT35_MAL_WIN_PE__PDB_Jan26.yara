import "pe"

rule Actor_APT_IR_APT35_MAL_WIN_PE__PDB_Jan26
{
    meta:
        rule_id = "87f97461-db69-4269-949f-29b343034c53"
        date = "29-01-2026"
        author = "Rustynoob619"
        description = "Detects potential malware related to Iranian APT35 (Charming Kitten) based on various PDB paths"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "1624e5273b921188a2382a7808657ace4e6bb5823e4ea6d55aa0d1ca3a780be0"

    condition:
        uint16(0) == 0x5a4d
        and (
            pe.pdb_path == "C:\\Users\\summer\\Documents\\Visual Studio 2005\\Projects\\MicrosoftAgentServices\\MicrosoftAgentServices\\obj\\Debug\\MicrosoftAgentServices.pdb"
            or pe.pdb_path == "Z:\\BellaCiao\\More Targets\\Tr(Turkey)\\Eposta\\Backdoor\\ShellDropper 2\\MicrosoftAgentServices\\obj\\Release\\Microsoft Monitoring Exchange Services.pdb"
            or pe.pdb_path startswith "C:\\Users\\summer"
            or pe.pdb_path startswith "Z:\\BellaCiao\\"
            or pe.pdb_path startswith "C:\\Users\\soso_win\\Desktop\\"
            or pe.pdb_path startswith "E:\\targets\\IL\\2112\\"
            or pe.pdb_path startswith "E:\\targets\\ae\\dubai-police\\"
            or pe.pdb_path startswith "F:\\targets\\EG\\TE\\"
            or pe.pdb_path contains "\\More Targets\\Tr(Turkey)\\"
            or pe.pdb_path contains "\\Backdoor\\ShellDropper\\MicrosoftAgentServices\\"
            or pe.pdb_path contains "\\backdoor\\ShellDropper\\MicrosoftAgentServices\\"
            or pe.pdb_path contains "\\Eposta\\Backdoor\\"
            or pe.pdb_path endswith "\\MicrosoftAgentServices\\obj\\Debug\\MicrosoftAgentServices.pdb"
            or pe.pdb_path endswith "\\MicrosoftAgentServices\\obj\\Release\\Microsoft Monitoring Exchange Services.pdb"
            or pe.pdb_path endswith "\\MicrosoftAgentServices\\bin\\Release\\WinUpdateService.pdb"
            or pe.pdb_path endswith "\\MicrosoftAgentServices\\obj\\Release\\WinUpdateService.pdb"
        )
        and filesize < 100KB

}
