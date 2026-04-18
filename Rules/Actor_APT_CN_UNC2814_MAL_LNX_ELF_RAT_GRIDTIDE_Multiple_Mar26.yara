
rule Actor_APT_CN_UNC2814_MAL_LNX_ELF_RAT_GRIDTIDE_Multiple_Mar26
{
    meta:
        rule_id = "1041cf0d-ff99-47ec-8bfd-48627884dcd5"
        date = "10-03-2026"
        author = "Rustynoob619"
        description = "Detects a Linux GRIDTIDE backdoor used by a Chinese threat cluster UNC2814 based on observed strings and ELF properties"
        source = "https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign/"
        filehash = "ce36a5fc44cbd7de947130b67be9e732a7b4086fb1df98a5afd724087c973b47"

    strings:
        $sheets1 = "POST /v4/spreadsheets/%s/values:batchUpdate" ascii 
        $sheets2 = "POST /v4/spreadsheets/%s/values:batchClear" ascii
        $sheets3 = "GET /v4/spreadsheets/%s/values/%s" ascii

        $auth1 = "oauth2.googleapis.com" ascii
        $auth2 = "sheets.googleapis.com" ascii
        $auth3 = "oauth:grant-type:jwt-bearer" ascii

        $usragnt = "Google-HTTP-Java-Client/1.42.3 (gzip)" ascii

        $bs64 = "base64" ascii

        $str1 = "{\"ranges\":[\"a1:z1000\"]}" ascii fullword
        $str2 = "valueRenderOption=FORMULA HTTP/1.1" ascii fullword
        $str3 = "S-C-R-%d" ascii fullword
        
    condition:
        uint32be(0) == 0x7f454c46
        and (2 of ($str*) or (
            $usragnt
            and $bs64
            and any of ($sheets*)
            and any of ($auth*)
        ))
        and filesize < 2MB

}
