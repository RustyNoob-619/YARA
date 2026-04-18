
rule Actor_APT_RU_HydraSaiga_MAL_WIN_PE_Artifacts_1_Mar26
{
    meta:
        rule_id = "e880dec8-5df3-484c-9a83-d9cf279045d8"
        date = "09-03-2026"
        author = "Rustynoob619"
        description = "Detects malicious docs used by Russian APT HydraSaiga based on observed encoded artifacts"
        source = "https://www.vmray.com/hydra-saiga-covert-espionage-and-infiltration-of-critical-utilities/#elementor-toc__heading-anchor-3"
        filehash = "a44827d002d7d1a74963b80e6af8a7257977f44c89caff66f126b7d1cad1fd11"

    strings:
        $str1 = "7919870168:AAHFQxY7khUH2nxB" base64 wide
        $str2 = "7919870168:AAHFQxY7khUH2nxB" base64wide
        $str3 = "7919870168:AAHFQxY7khUH2nxB" base64
        $str4 = "x0sO4jRG6W12k" base64 wide
        $str5 = "x0sO4jRG6W12k" base64wide
        $str6 = "x0sO4jRG6W12k" base64
        $str7 = "$lastID = 123" base64 wide
        $str8 = "$lastID = 123" base64wide
        $str9 = "$lastID = 123" base64

        $pdb = "C:\\Users\\Admin\\source\\repos\\ConsoleApplication3\\x64\\Release\\ConsoleApplication3.pdb"

    condition:
        uint16(0) == 0x5a4d 
        and any of them
        and filesize < 500KB

}
