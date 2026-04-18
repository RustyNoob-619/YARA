import "pe"

rule Actor_APT_CN_RudePanda_MAL_WIN_DLL_RAT_TOLLBOOTH_Multiple_Feb26
{
    meta:
        rule_id = "e8995ca0-12c2-47e4-903d-d999d61d1325"
        date = "05-02-2026" 
        author = "Rustynoob619"
        description = "Detects malicious IIS modules which enable C2 comms used by Chinese APT RudePanda based on strings and PE properties"
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash = "2e84ea5cef8a9a8a60c7553b5878a349a037cffeab4c7f40da5d0873ede7ff72"

    strings:
        $iis1 = "AVIISHttpModuleFactory@@" ascii fullword
        $iis2 = "AVIISHttpModule@@" ascii fullword
        $iis3 = "AVIISGlobalModule@@" ascii fullword

        $http1 = "seoConfigId=" ascii fullword
        $http2 = "referer=" ascii fullword
        $http3 = "window.location.href =" ascii
        $http4 = "rawHttpRequest ==" ascii
        $http5 = "Config File Path:" ascii fullword

        $param1 = "Cdn-Real-IP:" ascii fullword
        $param2 = "Cf-Connecting-IP:" ascii fullword
        $param3 = "X-Cluster-Client-IP:" ascii fullword
        $param4 = "Proxy-Client-IP:" ascii fullword
        $param5 = "True-Client-IP:" ascii fullword
        $param6 = "X-Real-IP:" ascii fullword
        $param7 = "Ali-Cdn-Real-IP:" ascii fullword
        $param8 = "X-Custom-Header:" ascii fullword

    condition:
        pe.imphash() == "dcf8cb0ce0e83bbdb1e58ef502c7661d"
        or (
            uint16(0) == 0x5a4d
            and pe.locale(0x0804) //Chinese Simplyfied Language
            and pe.imports("WINHTTP.dll","WinHttpConnect")
            and pe.exports("RegisterModule")
            and any of ($iis*)
            and any of ($http*)
            and 4 of ($param*)
            and filesize < 2MB
            )
}
