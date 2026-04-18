rule Actor_APT_DPRK_Unknown_MAL_Script_PY_Stealer_Unknown_Strings_1_Feb26
{
      meta:
            rule_id = "7919137c-de06-43cc-800a-76c726b45fbd"
            date = "19-02-2026"
            author = "RustyNoob619"
            //Payload 1_2_1_1 OmniStealer
            description = "Detects cluster of Python Scripts that are likely developed by a DPRK Nexus group"
            filehash = "742016f01fa89be4d43916d5d2349c8d86dc89f096302501ec22b5c239685a20"

      strings:
            $bwr1 = "microsoft-edge" ascii
            $bwr2 = "google-chrome" ascii
            $bwr3 = "Brave-Browser" ascii

            $func1 = "socket.gethostname()" ascii
            $func2 = "getpass.getuser()" ascii
            $func3 = "platform.platform()" ascii

            $str1 = "1Password" ascii
            $str2 = "secretstorage" ascii
            $str3 = "networkWallet" ascii
            $str4 = "readPassword" ascii
            $str5 = "cookie_files" ascii
            $str6 = "login_files" ascii
            $str7 = "credit_cards" ascii
            $str8 = "masterPassword" ascii
            $str9 = "moz_cookies" ascii
            $str10 = "http-upload" ascii
            $str11 = "tg-upload" ascii

            $pass1 = "ProtonPass" ascii
            $pass2  = "MEGAPass" ascii
            $pass3  = "DualSafe" ascii
            $pass4  = "FreePasswordManager" ascii
            $pass5  = "GoogleAuth" ascii

            $params1 = "osx_key_user" ascii
            $params2 = "osx_key_service" ascii
            $params3 = "os_crypt_name" ascii
            $params4 = "windows_keys" ascii
            $params5 = "osx_cookies" ascii
            $params6 = "windows_cookies" ascii
            $params7 = "linux_cookies" ascii
            $params8 = "osx_logins" ascii
            $params9 = "windows_logins" ascii
            $params10 = "linux_logins" ascii

            $crpt1 = "Bitwarden" ascii
            $crpt2 = "NordPass" ascii
            $crpt3 = "Dashlane" ascii
            $crpt4 = "kwallet" ascii

            $pths1 = "/.config/chromium/" ascii
            $pths2 = "/.config/opera/" ascii
            $pths3 = "/.config/BraveSoftware/" ascii
            $pths4 = "/.config/microsoft-edge" ascii
            $pths5 = "/.config/vivaldi/" ascii
            $pths6 = "%APPDATA%\\\\*\\\\*\\\\*\\\\User Data*" ascii

            $walls1 = "Dogecoin/wallets.dat" ascii
            $walls2 = "Bitcoin/wallets" ascii
            $walls3 = "Electrum/wallets" ascii
            $walls4 = "Exodus/exodus.wallet" ascii
            $walls5 = "Monero/wallets" ascii

            $drv1 = "iCloud Drive" ascii
            $drv2 = "SkyDrive" ascii
            $drv3 = "OneDrive" ascii
            $drv4 = "My Drive" ascii
            $drv5 = "Dropbox" ascii
            $drv6 = "pCloud" ascii
            $drv7 = "Box" ascii
            $drv8 = "iCloud" ascii
            $drv9 = "SkyDrive" ascii
            $drv10 = "GoogleDrive" ascii
            $drv11 = "Dropbox" ascii
            $drv12 = "Mega" ascii

      condition:
            any of ($bwr*)
            and any of ($func*)
            and 5 of ($str*)
            and 2 of ($pass*)
            and 5 of ($params*)
            and 2 of ($crpt*)
            and 3 of ($pths*)
            and 2 of ($walls*)
            and 6 of ($drv*)
            and filesize < 250KB

}
