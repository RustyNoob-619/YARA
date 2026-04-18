import "pe"

rule Actor_APT_IR_MuddyWater_MAL_WIN_PE_Loader_StageComp_Multiple_Apr26
{
    meta:
        rule_id = "a8494f78-b53e-4a00-b89b-6883f4d318c0"
        date = "18-04-2026"
        author = "Rustynoob619"
        description = "Detects StageComp loader used by Iran APT MuddyWater based on multiple attributues"
        source = "https://www.jumpsec.com/guides/chainshell-muddywater-russian-criminal-infrastructure/"
        filehash = "a92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0"

    strings:
        $str1 = "Donald Gay1" ascii fullword
        $str2 = "Donald Gay0" ascii fullword
        $str3 = "{\"client_id\":\"%s\",\"status\":\"%s\",\"error_code\":\"%s\"}" ascii fullword
        $str4 = "{\"client_id\":\"%s\",\"computer_name\":\"%s\",\"username\":\"%s\",\"domain\":\"%s\"}" ascii fullword
        $str5 = "EXIT_%lu" ascii fullword
        $str6 = "RUN_%lu" ascii fullword
        $str7 = "\"approved\": true" ascii fullword
        $str8 = "\"retry\": true" ascii fullword

        $wide1 = "/status" wide fullword
        $wide2 = "\\Downloads" wide fullword
        $wide3 = "StageClient/2.0" wide fullword
        $wide4 = "/register" wide fullword
        $wide5 = "/check" wide fullword
        $wide6 = "cmd.exe /c ping 127.0.0.1" wide fullword
        $wide7 = "nul && del /f /q \"%s" wide fullword

    condition:
        uint16(0) == 0x5a4d
        and ((
            pe.imphash() == "9963ebabcee092908eac2414f7c4661a"
            or pe.pdb_path == "C:\\Users\\Public\\ConsoleApplication1\\Release\\ConsoleApplication1.pdb"
            or pe.signatures[0].thumbprint == "b674578d4bdb24cd58bf2dc884eaa658b7aa250c"
        )
        or (
            4 of ($str*) and
            4 of ($wide*)
        ))
        and filesize < 500KB

}
