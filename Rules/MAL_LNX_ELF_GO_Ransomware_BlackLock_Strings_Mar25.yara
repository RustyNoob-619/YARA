
rule MAL_LNX_ELF_GO_Ransomware_BlackLock_Strings_Mar25
{
      meta:
            rule_id = "252bf88e-7974-4197-a459-338285eee667"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects a New ransomware called BlackLock written in GO"
            credit = "@MalGamy12 for discovery and sharing of the sample"
            source = "https://x.com/MalGamy12/status/1900355355634290796"
            filehash = "1da86aa04214111ec8b4a2f46e6450f41233da1110f0b32890d522285a2ae38b"

      strings:
            $lock = "lockedExt" ascii fullword

            $cipher = "golang.org/x/crypto/chacha20.NewUnauthenticatedCipher" ascii fullword

            $git = "github.com/hirochachacha/" ascii

            $func1 = "main.load_config" ascii fullword
            $func2 = "main.remote_main" ascii fullword
            $func3 = "main.local_main" ascii fullword
            $func4 = "main.load_config.func1" ascii fullword
            $func5 = "main.os_WriteFile" ascii fullword
            $func6 = "main.esxi_walkDir" ascii fullword
            $func7 = "main.esxi_time_Sleep" ascii fullword
            $func8 = "main.self_delete" ascii fullword
            $func9 = "main.progress_logger" ascii fullword
            $func10 = "main.wait_logger_and_exit" ascii fullword
            $func11 = "main.esxi_is_include_file" ascii fullword
            $func12 = "main.encode_local_file" ascii fullword
            $func13 = "main.local_drop_note" ascii fullword

            $path1 = "/root/enc/config.go" ascii fullword
            $path2 = "/root/enc/esxi.go" ascii fullword
            $path3 = "/root/enc/esxi_time_Sleep_amd64.go" ascii fullword
            $path4 = "/root/enc/linux.go" ascii fullword

      condition:
            uint32be(0) == 0x7f454c46 
            and $lock
            and $cipher
            and $git
            and 9 of ($func*)
            and 2 of ($path*)
            and filesize < 5MB 

}

