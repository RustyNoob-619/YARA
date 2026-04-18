
rule Actor_APT_RU_Turla_MAL_WIN_DLL_Loader_KazuarV3_Strings_Jan26
{
    meta:
        rule_id = "882c5b82-4638-4d58-8971-08ea0eb6e8b4"
        date = "24-01-2026"
        author = "Rustynoob619"
        description = "Detects Kazuar V3 loader used by Russian APT Turla based on strings"
        source = "https://r136a1.dev/2026/01/14/command-and-evade-turlas-kazuar-v3-loader/"
        credit = "@TheEnergyStory for the analysis and sharing of the malware hashes"
        filehash = "69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4"

    strings:
        $GCC = "GCC: (MinGW-W64 x86_64-msvcrt-posix-seh, built by Brecht Sanders) 12.2.0" ascii fullword

        $wide1 = "{D6BCEDD7-8E53-4769-9826-24954C975AAC}" wide fullword
        $wide2 = "{045CE7DB-2160-4067-BB86-0D54E20FA95D}" wide fullword
        $wide3 = "{5806CA31-7A57-4125-AC69-4D597BD5FE38}" wide fullword
        $wide4 = "jayb.dadk" wide fullword
        $wide5 = "pkrfsu.ldy" wide fullword
        $wide6 = "kgjlj.sil" wide fullword

    condition:
        uint16(0) == 0x5a4d
        and $GCC
        and any of ($wide*)
        and filesize < 250KB
}
