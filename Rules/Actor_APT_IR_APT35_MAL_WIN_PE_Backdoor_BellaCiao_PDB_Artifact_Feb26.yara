import "pe"

rule Actor_APT_IR_APT35_MAL_WIN_PE_Backdoor_BellaCiao_PDB_Artifact_Feb26
{
    meta:
        rule_id = "0ab30d67-aaf9-4114-86df-120d82710fab"
        date = "28-01-2026"
        author = "Rustynoob619"
        description = "Detects BellaCiao backdoor used by Iranian APT35 (Charming Kitten) based on the PDB path"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "2dbdd538546dcd636cc7870026322d8e7564929fd946f7145a42fc619db7cdc3"

    condition:
        uint16(0) == 0x5a4d
        and (
            pe.pdb_path == "C:\\Users\\summer\\Documents\\Visual Studio 2005\\Projects\\MicrosoftAgentServices\\MicrosoftAgentServices\\obj\\Debug\\MicrosoftAgentServices.pdb"
            or pe.pdb_path == "Z:\\BellaCiao\\More Targets\\Tr(Turkey)\\Eposta\\Backdoor\\ShellDropper 2\\MicrosoftAgentServices\\obj\\Release\\Microsoft Monitoring Exchange Services.pdb"
            or pe.pdb_path startswith "C:\\Users\\summer"
            or pe.pdb_path startswith "Z:\\BellaCiao\\"
            or pe.pdb_path contains "\\More Targets\\Tr(Turkey)\\"
            or pe.pdb_path contains "\\Eposta\\Backdoor\\"
            or pe.pdb_path endswith "\\MicrosoftAgentServices\\obj\\Debug\\MicrosoftAgentServices.pdb"
            or pe.pdb_path endswith "\\MicrosoftAgentServices\\obj\\Release\\Microsoft Monitoring Exchange Services.pdb"
        )
        and filesize < 100KB

}
