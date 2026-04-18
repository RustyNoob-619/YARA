rule Actor_APT_DPRK_Unknown_MAL_Script_PY_Stealer_Unknown_Strings_2_Feb26
{
      meta:
            rule_id = "2c2a60ce-55cf-40ab-92c4-7ee961b0d00c"
            date = "20-02-2026"
            author = "Rustynoob619"
            //Payload 1_2_1_1 OmniStealer
            description = "Detects cluster of Python Scripts that are likely developed by a DPRK Nexus group"
            filehash = "236ff897dee7d21319482cd67815bd22391523e37e0452fa230813b30884a86f"

      strings:
            $dot1 = ".onetoc2" ascii
            $dot2 = ".onenote" ascii
            $dot3 = ".one" ascii
            $dot4 = ".kbdx" ascii

            $func1 = "socket.gethostname()" ascii
            $func2 = "getpass.getuser()" ascii
            $func3 = "platform.platform()" ascii

            $pc1 = "pc_name" ascii
            $pc2 = "pc_info" ascii
            $pc3 = "pc_login" ascii

            $x1 = "metamask" ascii
            $x2 = "phantom" ascii
            $x3 = "exodus" ascii
            $x4 = "atomic" ascii
            $x5 = "bitcoin" ascii
            $x6 = "ethereum" ascii
            $x7 = "solana" ascii
            $x8 = "aptos" ascii
            $x9 = "electrum" ascii
            $x10 = "tronlin" ascii
            $x11 = "coinbase" ascii
            $x12 = "binance" ascii

            $y1 = "gitconfig" ascii
            $y2 = "tsconfig" ascii
            $y3 = "bootconfig" ascii
            $y4 = "pw-config" ascii

            $z1 = "cli_mode" ascii
            $z2 = "dev_mode" ascii
            $z3 = "cli_mode" ascii
            $z4 = "debug_mode" ascii

      condition:
            2 of ($dot*)
            and any of ($func*)
            and any of ($pc*)
            and 6 of ($x*)
            and 2 of ($y*)
            and 2 of ($z*)
            and filesize < 100KB
}
