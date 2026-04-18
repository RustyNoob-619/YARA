rule Actor_APT_DPRK_Unknown_MAL_Script_JS_RAT_Unknown_Strings_Feb26
{
      meta:
            rule_id = "96fd2b7e-355e-43fc-a581-6ebda388b761"
            date = "22-02-2026"
            author = "Rustynoob619"
            description = "Detects cluster of obfuscated JS Scripts that are likely developed by a DPRK Nexus group"
            filehash = "eefe39fe88e75b37babb37c7379d1ec61b187a9677ee5d0c867d13ccb0e31e30"

      strings:
            $str1 = "Promise" ascii wide
            $str2 = "['_V']" ascii wide
            $str3 = "['_R']" ascii wide
            $str4 = "atob" ascii wide

            condition:
                all of them
                and filesize < 100KB
}
