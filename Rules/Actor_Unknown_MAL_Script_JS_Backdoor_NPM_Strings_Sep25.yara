
rule Actor_Unknown_MAL_Script_JS_Backdoor_NPM_Strings_Sep25
{
    meta:
        rule_id = "bf9b9e7a-3020-40f3-b592-d1bfc92e7169"
        date = "09-09-2025"
        author = "RustyNoob619"
        description = "Detects Compromised NPM Malicious Packages Based on Observed Strings"
        source1 = "https://x.com/cyb3rops/status/1965121934427029564"
        source2 = "https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack"
        credits = "@cyb3rops for sharing the file sample"
        filehash = "16f6c756bc8ce5ef5d9aa1ded0f811ec0c9cee3d8f85cc151b8ca1df7b8a4337"
        Confidence = 50

    strings:
        $win_check = "typeof window" ascii
        $http = "XMLHttpRequest"ascii
        $exp = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" ascii

        $func1 = "checkethereumw()" ascii
        $func2 = "runmask()" ascii
        $func3 = "isActive" ascii
        $func4 = "forceShield" ascii
        $func5 = "getOriginalMethods" ascii

        $const1 = "ethereum" ascii
        $const2 = "bitcoinLegacy" ascii
        $const3 = "bitcoinSegwit" ascii
        $const4 = "tron" ascii
        $const5 = "solana" ascii
        
    condition:
        $win_check
        and $http
        and $exp
        and any of ($func*)
        and any of ($const*)
        and filesize < 100KB  
}

