import "elf"

rule MAL_ELF_Backdoor_GhostPenguin_Strings_Jan26
{
    meta:
        rule_id = "48581ea6-7ad8-48bf-8028-d1145ab0ad71"
        date = "22-01-2026"
        author = "Rustynoob619"
        description = "Detects GhostPenguin Linux backdoor based on ELF tlfhash or embedded strings"
        source = "https://www.trendmicro.com/en_us/research/25/l/ghostpenguin.html"
        filehash = "7b75ce1d60d3c38d7eb63627e4d3a8c7e6a0f8f65c70d0b0cc4756aab98e9ab7"

    strings:
        $GCC = "GCC: (GNU) 4.4.7 20120313 (Red Hat 4.4.7-23)" ascii fullword

        $cmd1 = "grep -v '%s'" ascii
        $cmd2 = "crontab -l" ascii 
        $cmd3 = "ping -c 1" ascii 
        $cmd4 = "rm -f %s" ascii 
        $cmd5 = "echo \"%d %d * * * %s\")" ascii

        $str1 = "127.0.0.1" ascii fullword
        $str2 = "%s/.temp" ascii fullword
        $str3 = "/bin/sh" ascii fullword
        $str4 = "/proc/self/exe" ascii fullword

        $func1 = "g_threadGetSessionIDFromServer" ascii
        $func2 = "g_threadDataReceiver" ascii
        $func3 = "g_threadRegisterSelfToServer" ascii
        $func4 = "g_threadHeartBeat" ascii
        $func5 = "g_threadDataSender" ascii
        $func6 = "GetIPAddrAndPortFromHostCfg" ascii

        $ioc1 = "www.iytest.com:5679" ascii fullword
        $ioc2 = "124.221.109.147:5679" ascii fullword
        $ioc3 = "65.20.72.101:53" ascii fullword

    condition:
        uint32be(0) == 0x7f454c46
        and (
            elf.telfhash() == "t15001970ae93d0bdc15a85c60d9288bc341c3c6339035aa25fb96cec0441e513f069c1f"
            or any of ($ioc*)
        )
        or (
            $GCC
            and 3 of ($cmd*) 
            and 2 of ($str*) 
            and 3 of ($func*)
        )
        and filesize < 250KB

}
