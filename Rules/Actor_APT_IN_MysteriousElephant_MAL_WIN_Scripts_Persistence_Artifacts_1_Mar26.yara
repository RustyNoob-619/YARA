rule Actor_APT_IN_MysteriousElephant_MAL_WIN_Scripts_Persistence_Artifacts_1_Mar26
{
    meta:
        rule_id = "aca543c5-cda0-4650-afc5-32e69e157b59"
        date = "21-03-2026"
        author = "Rustynoob619"
        description = "Detects files (scripts) used by Indian APT Mysterious Elephant based on unique persistence mechanism"
        source = "https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/"
        filehash = "e194b89af6d5968f04af914885166d1e69845061d274d9ca8e9ddefd4e43888e"

    strings:
        $echo = "@echo 0ff"

        $cmd = "schtasks /CREATE /TN RegistryBackupTask /f /sc minute /mo 5 /tr \"conhost --headless cmd /c curl -o"

    condition:
        $echo at 0
        and $cmd
        and filesize < 25KB

}
