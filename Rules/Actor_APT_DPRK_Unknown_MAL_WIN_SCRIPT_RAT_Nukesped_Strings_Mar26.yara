
rule Actor_APT_DPRK_Unknown_MAL_WIN_SCRIPT_RAT_Nukesped_Strings_Mar26
{
    meta:
        rule_id = "eddc6b32-323a-41bb-9ec2-cd44111760d4"
        date = "08-03-2026"
        author = "Rustynoob619"
        description = "Detects Nukesped RAT used by DPRK operators based on unique strings"
        source = "https://x.com/RedDrip7/status/2029459268626465203"
        filehash = "a897fb39d3e62c760d998511913785e30bfb703caf89af13a80cb1b18e83dfd9"

    strings:
        $import1 = "import base64"
        $import2 = "b85decode"

        $str1 = "tXt3rqfmL3"
        $str2 = "Type = 'gold1'"
        $str3 = "Type = 'ZRsvn1k9'"
        $str4 = "Type = 'ZU1WJVq1'"
        $str5 = "Type = 'ahNjWa2'"
        $str6 = "Type = 'kjGlMT0'"

    condition:
        all of ($import*)
        and any of ($str*)
        and filesize < 100KB 

}
