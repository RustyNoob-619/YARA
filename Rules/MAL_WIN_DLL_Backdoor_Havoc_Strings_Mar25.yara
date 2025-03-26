
rule MAL_WIN_DLL_Backdoor_Havoc_Strings_Mar25
{
      meta:
            rule_id = "4ff6cdba-91b1-4fc4-bbe6-c8cf18beaa28"
            date = "23-03-2025"
            author = "RustyNoob619"
            description = "Detects Havoc C2 implant using SharePoint and Microsoft Graph API for C2 comms based on observed strings"
            source = "https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2"
            filehash = "cc151456cf7df7ff43113e5f82c4ce89434ab40e68cd6fb362e4ae4f70ce65b3"

      strings:
            $havoc = "demon.x64.dll" ascii fullword

            $str1 = "client_id=" ascii fullword
            $str2 = "client_secret=" ascii fullword
            $str3 = "grant_type=client_credentials" ascii fullword
            $str4 = "\"driveId\":\"" ascii fullword
            $str5 = "\"access_token\":\"" ascii fullword
            $str6 = "\"id\":\"" ascii fullword
            $str7 = "/v1.0/sites/%ls/drive/root:/%ls:/content" wide fullword
            $str8 = "/v1.0/drives/%S/items/%S/content" wide fullword

            $mcrft1 = "graph.microsoft.com" wide fullword
            $mcrft2 = "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default" ascii fullword

            $auth1 = "Authorization: Bearer" wide fullword
            $auth2 = "/oauth2/v2.0/token" ascii fullword

            $ioc = "hao771.sharepoint.com"ascii

            $usragnt = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" wide fullword 

      condition:
            uint16(0) == 0x5a4d 
            and $havoc 
            and (($ioc or $usragnt)
            or
            (any of ($auth*) 
            and any of ($mcrft*)
            and 4 of ($str*)))
            and filesize < 250KB 

}