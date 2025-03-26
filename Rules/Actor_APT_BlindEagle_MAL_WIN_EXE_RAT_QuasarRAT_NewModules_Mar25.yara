
rule Actor_APT_BlindEagle_MAL_WIN_EXE_RAT_QuasarRAT_NewModules_Mar25
{
      meta:
            rule_id = "b8926b7a-a0d8-4801-b2ef-42cdf5f93192"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects newer QuasarRAT malware variants based on new modules"
            credit = "@johnk3r for sharing the malware sample and attribution"
            source = "https://x.com/johnk3r/status/1903565136314462331"
            filehash = "72157acbb76515e2eb904d29afbf86a81a780525b177b0940d2ce26ad89df62f"

      strings:
            $module1 = "RDPOtraOp" wide fullword
            $module2 = "DobleSession" wide fullword
            $module3 = "InstallRPD2" wide fullword
            $module4 = "ExploC" wide fullword

            $str1 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Themes" wide fullword
            $str2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide fullword
            $str3 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" wide fullword
            $str4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\MozillaPlugins" wide fullword
            $str5 = "/SC DAILY /RI 5 /ST 10:10 /DU 00:10 /K /RL HIGHEST /TR" wide
            $str6 = "Antivirus" wide fullword
            $str7 = "Firewall" wide fullword
            $str8 = "Video Card (GPU)" wide fullword

            $func1 = "grabber_video" wide fullword
            $func2 = "grabber_snapshot" wide fullword

      condition:
            uint16(0) == 0x5a4d
            and 3 of ($module*)
            and any of ($func*)
            and 4 of ($str*)
            and filesize < 500KB

}

