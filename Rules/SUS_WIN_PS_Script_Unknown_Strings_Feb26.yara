rule SUS_WIN_PS_Script_Unknown_Strings_Feb26
{
    meta:
        rule_id = "ffea732e-87d1-4187-849e-260590353c5c"
        date = "03-02-2026"
        author = "Rustynoob619"
        description = "Detects suspicious PowerShell scripts used as a reverse shell based on observed strings"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "0cafc73963276747be09b682ec0f2862bc0e020d93b7441f423912df9b14fce7"
    
    strings:
        $str1 = "[System.Net.IPHostEntry]" ascii wide
        $str2 = "[System.Net.Dns]" ascii wide
        $str3 = "GetHostEntry" ascii wide
        $str4 = "start-process cmd.exe" ascii wide
        $str5 = "-WindowStyle Hidden" ascii wide
        $str6 = "AddressList[0]" ascii wide
    
        $pair = "-P 443 -C -R 127.0.0.1" ascii wide

        $str1b64 = "-P 443 -C -R 127.0.0.1" base64
        $str2b64 = "AddressList[0]" base64
        $str3b64 = "-WindowStyle Hidden" base64
        $str4b64 = "start-process cmd.exe" base64
        $str5b64 = "GetHostEntry" base64
        $str6b64 = "[System.Net.IPHostEntry]" base64
        $str7b64 = "[System.Net.Dns]" base64
        
    condition:
        $pair
        and 4 of ($str*)
        and filesize < 100KB
}
