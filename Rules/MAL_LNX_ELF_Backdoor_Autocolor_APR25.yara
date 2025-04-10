import "elf"

rule MAL_LNX_ELF_Backdoor_Autocolor_APR25
{
    meta:
        rule_id = "a31dd4f1-e9b1-466b-a982-8aa2f613db66"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects ELF backdoor known as Auto-Color"
        source = "https://unit42.paloaltonetworks.com/new-linux-backdoor-auto-color/"
        filehash = "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43"

    strings:
        $str1 = "auto-color" fullword
        $str2 = "%s/auto-color" fullword

    condition:
        elf.telfhash() == "t12a11a81b993d07a889a65d35ed2507e38087d23aa062e714ff54eec0645f446f12ce8f"
        and any of them
        and filesize < 250KB
}
