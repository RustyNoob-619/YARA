
rule MAL_HTML_ClickFix_Strings_Mar25
{
      meta:
            rule_id = "57db090a-401a-46f3-837c-b0c64dee19c2"
            author = "RustyNoob619"
            description = "Detects ClickFix HTML file used in phishing emails to download next stage payloads"
            source = "https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2"
            filehash = "51796effe230d9eca8ec33eb17de9c27e9e96ab52e788e3a9965528be2902330"

      strings:
            $header = {3c 21 44 4f 43 54 59 50 45 20 68 74 6d 6c 3e} //HTML Doc Type

            $str1 = "<title>Opening file...</title>" ascii fullword
            $str2 = "hidden-content" ascii 
            $str3 = "click" nocase ascii 
            $str4 = "error" nocase ascii

            $bs64 = "base64"ascii

            $encoding = {?? [100 - 300] 3d 3d} //Detects Possible Base64 Encoding based on string lengths

            $pwrshll1 = "powershell" base64
            $pwrshll2 = "powershell" nocase ascii wide

            $shrpnt1 = "sharepoint" base64
            $shrpnt2 = "sharepoint" nocase ascii wide
           

      condition:
            $header at 0
            and 2 of ($str*)
            and $bs64 and $encoding
            and any of ($pwrshll*)
            and any of ($shrpnt*)
            and filesize < 50KB

}