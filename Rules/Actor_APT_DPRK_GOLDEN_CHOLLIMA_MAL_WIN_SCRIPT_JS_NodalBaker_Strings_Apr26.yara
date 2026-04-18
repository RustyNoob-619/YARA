
rule Actor_APT_DPRK_GOLDEN_CHOLLIMA_MAL_WIN_SCRIPT_JS_NodalBaker_Strings_Apr26
{
    meta:
        rule_id = "460db6c2-9cad-414d-a9c4-cac0a0378ff8"
        date = "05-04-2026"
        author = "Rustynoob619"
        description = "Detects NodalBaker JavaScript used by DPRK APT GOLDEN CHOLLIMA based on observed strings"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "0518a163b90e7246a349440164d02d10f31d514a7e5cce842b6cf5b3a0cc1bfa"
    
    strings:
        $domain1 = "Amazon.com" ascii
        $domain2 = "Google.com" ascii
        
        $func1 = "function mid(length)" ascii
        $func2 = "Buffer.from(" ascii
        $func3 = "'base64').toString('utf8')" ascii
        $func4 = "setInterval(sess, 10000)" ascii

        $net1 = "hostname: Domain" ascii
        $net2 = "port: 443" ascii
        $net3 = "method: 'POST'" ascii


    condition:
        any of ($domain*)
        and 2 of ($func*)
        and 2 of ($net*)
        and filesize < 50KB
}
