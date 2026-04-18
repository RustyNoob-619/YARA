rule Actor_APT_IR_APT35_MAL_WIN_PE_Backdoor_BellaCiao_Strings_Jan26
{
    meta:
        rule_id = "8314cecf-df0d-4732-8e8d-2eb7620bf42d"
        date = "31-01-2026"
        author = "Rustynoob619"
        description = "Detects BellaCiao backdoor used by Iranian APT35 (Charming Kitten) based on observed strings"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "2dbdd538546dcd636cc7870026322d8e7564929fd946f7145a42fc619db7cdc3"
    
    strings:
        $func1 = "FromBase64String" ascii fullword
        $func2 = "System.IO" ascii fullword
        $func3 = "MicrosoftAgentServices" ascii fullword
        $func4 = "RandomString" ascii fullword

        $wide1 = "D:\\Inetpub\\Devsite\\anon_enter\\City4u\\errorpages.aspx" wide
        $wide2 = "D:\\Inetpub\\Devsite\\anon_enter\\City4u\\Global.aspx" wide
        $wide3 = "c:\\inetpub\\wwwroot\\aspnet_client\\" wide
        $wide4 = "c:\\inetpub\\wwwroot\\aspnet_client\\system_web\\" wide

        $bs64str1 = "A Webshell which utilizes PowerShell." base64wide
        $bs64str2 = "hello dear !" base64wide
        $bs64str3 = "execution.Visible = false" base64wide

    condition:
        uint16(0) == 0x5a4d
        and (
            (any of ($wide*))
            or 
            ((all of ($func*))
            and (2 of ($bs64str*)))
        )
        and filesize < 100KB
}
