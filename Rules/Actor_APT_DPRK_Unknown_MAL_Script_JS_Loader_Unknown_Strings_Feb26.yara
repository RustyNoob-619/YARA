rule Actor_APT_DPRK_Unknown_MAL_Script_JS_Loader_Unknown_Strings_Feb26
{
      meta:
            rule_id = "dbcf26b3-7b8c-447d-97ad-43de0d6e42e6"
            date = "21-02-2026"
            author = "Rustynoob619"
            description = "Detects cluster of JS Scripts that are likely developed by a DPRK Nexus group"
            filehash = "be21bf4ad94c394202e7b52a1b461ed868200f0f03b3c8544984e9765c23e1e0"

      strings:
            $hex = {676c6f62616c2e5f56203d202743352d62656e6566697427} //global._V = 'C5-benefit'

            $js1 = "global.r" ascii
            $js2 = "global._V" ascii

            $var1 = "C5-benefit" ascii
            $var2 = "C250617A" ascii
            $var3 = "CHQG3L42MMQ" ascii
            $var4 = {68 74 74 70 3a 2f 2f 22 20 2b 20 ?? 20 2b 20 22 3a (32 37 30 31 37 | 44 44 43)} //IP:Port pattern

            $str1 = "crypto" ascii
            $str2 = "socket" ascii
            $str3 = "hostname" ascii
            $str4 = "axios" ascii
            $str5 = "form-data" ascii

            condition:
                  $hex
                  or (
                        any of ($js*)
                        and any of ($var*)
                        and any of ($str*)
                  )
                  and filesize < 75KB
}
