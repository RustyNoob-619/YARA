
import "pe"

rule Actor_APT_CN_FishMonger_MAL_WIN_DLL_Loader_SodaMaster_PEProperties_Mar25
{
      meta:
            rule_id = "71197f1b-406c-4bf1-a5fe-3ac05a3ed417"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects a loader called SodaMaster used by the Chinese APT Fish Monger"
            source = "https://www.welivesecurity.com/en/eset-research/operation-fishmedley/"
            filehash = "47f1db4b2f90d92dceb9c572fe889a042ae45ec16abaccc117b2b0bac7b2ea9d"

      strings:
            $str1 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" ascii 
            $str2 = "\\logins.json" ascii fullword
            $str3 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii fullword
            $str4 = "encryptedUsername" ascii fullword
            $str5 = "encryptedPassword" ascii fullword

      condition:
            pe.exports("MMDB_aget_value")
            and pe.exports("MMDB_lookup_string")
            and pe.exports("MMDB_open")
            and pe.exports("getAllAuthData")
            and 2 of them
            and filesize < 500KB 
}