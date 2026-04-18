
rule Actor_APT_DPRK_APT37_MAL_WIN_PE_Implant_RESTLEAF_Strings_Mar26
{
    meta:
        rule_id = "2184c6bd-484b-49c9-a8f3-c93fa33b8f68"
        date = "13-03-2026"
        author = "Rustynoob619"
        description = "Detects RESTLEAF loader used by APT37 (Inky Squid) based on observed strings"
        source = "https://www.zscaler.com/blogs/security-research/apt37-adds-new-capabilities-air-gapped-networks"
        filehash = "cf2e3f46b26bae3d11ab6c2957009bc1295b81463dd67989075592e81149c8ec"

    strings:
        $str1 = "/AAA.bin" ascii fullword
        $str2 = "'lion' Folder Creating..." ascii fullword

        $func1 = "client_id" ascii fullword
        $func2 = "client_secret" ascii fullword
        $func3 = "redirect_uri" ascii fullword
        $func4 = "refresh_token" ascii fullword
        $func5 = "parent_id" ascii fullword
        $func6 = "resource_id" ascii fullword
        $func7 = "allow_download" ascii fullword
        $func8 = "request_user_data" ascii fullword
        $func9 = "download_url" ascii fullword

        $zoho1 = "Zoho WorkDrive" ascii
        $zoho2 = "Zoho-oauthtoken" ascii
        $zoho3 = "https://accounts.zoho.com/oauth/v2/token" ascii
        $zoho4 = "https://www.zohoapis.com/workdrive/api/v1" ascii
        $zoho5 = "----------ZohoBoundary12345" ascii 
        
    condition:
        uint16(0) == 0x5a4d
        and any of ($str*)
        and 5 of ($func*)
        and 2 of ($zoho*)
        and filesize < 1MB

}
