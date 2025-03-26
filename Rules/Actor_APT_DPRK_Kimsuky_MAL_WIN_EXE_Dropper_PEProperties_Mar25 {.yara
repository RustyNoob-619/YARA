
import "pe"

rule Actor_APT_DPRK_Kimsuky_MAL_WIN_EXE_Dropper_PEProperties_Mar25
{
    meta:
        rule_id = "74014840-86d4-4938-85bc-e39e5cce27d4"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects a Signed Dropper Executable"
        source = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        filehash = "f8ab78e1db3a3cc3793f7680a90dc1d8ce087226ef59950b7acd6bb1beffd6e3"

    strings:
        $str1 = "[SLEEP]" wide fullword
        $str2 = "[CTRL]" wide fullword
        $str3 = "[JUNJA]" wide fullword
        $str4 = "[FINAL]" wide fullword
        $str5 = "[HANJA]" wide fullword
        $str6 = "[EXEC]" wide fullword
        $str7 = "[SANP]" wide fullword
        $str8 = "[MDCHG]" wide fullword

        $spec1 = "limsjo" wide fullword
        $spec2 = "\\NXTPKIENTS.exe" wide fullword


    condition:
        pe.signatures[0].thumbprint == "30db7d678045e44d882d7652ba6aaa6593c02328" //D2innovation Co.,LTD
        and pe.imphash() == "6d1a6e157cb22b9fb75e1d61b4881eb5" //Needs Validation
        and 5 of ($str*)
        and any of ($spec*)
        and filesize < 25MB

}