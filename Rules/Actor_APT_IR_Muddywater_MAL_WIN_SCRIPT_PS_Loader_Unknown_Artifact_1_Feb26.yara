rule Actor_APT_IR_Muddywater_MAL_WIN_SCRIPT_PS_Loader_Unknown_Artifact_1_Feb26
{
    meta:
        rule_id = "90c1da40-e60c-40a7-b106-54b9ca9543db"
        date = "26-02-2026"
        author = "Rustynoob619"
        description = "Detects PowerShell scripts used by Iran APT Muddywater based on custom encryption keys used"
        source = "https://www.esentire.com/blog/muddywater-apt-tsundere-botnet-etherhiding-the-c2"
        filehash = "7ab597ff0b1a5e6916cad1662b49f58231867a1d4fa91a4edf7ecb73c3ec7fe6"

    strings:
        $ps1 = "CreateDecryptor" ascii
        $ps2 = "TransformFinalBlock" ascii
        $ps3 = "FromBase64String" ascii

        $key = "iW06Rp1urCAH5d26NZHHZL6ehy57J4MVvkM3T/alhuU=" ascii
        $iv = "lTKi4AViF/tqc1+6HGprfw==" ascii

    condition:
        all of ($ps*)
        and ($key or $iv)
        and filesize < 3MB
}
