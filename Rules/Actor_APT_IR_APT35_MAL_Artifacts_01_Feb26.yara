rule Actor_APT_IR_APT35_MAL_Artifacts_01_Feb26
{
    meta:
        rule_id = "b68b6588-923d-4ea7-83ec-84af043ccdca"
        date = "01-02-2026"
        author = "Rustynoob619"
        description = "Detects potential Iranian APT35 (Charming Kitten) related malware  based on unique embedded strings"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "2dbdd538546dcd636cc7870026322d8e7564929fd946f7145a42fc619db7cdc3"
    
    strings:
        $usr1 = "nihamasamora" ascii wide
        $pass1 = "niha@masamora!" ascii wide
        $pass2 = "Israel@123!" ascii wide
        $pass3 = "KazimAtes1977" ascii wide
        $pass4 = "1234qqqQQQ" ascii wide

        $ip1 = "212.175.168.58" ascii wide
        $ip2 = "103.57.251.153" ascii wide
        $domain1 = "msn-center.uk" ascii wide
        $domain2 = "twittsupport.com" ascii wide

        $usrbs64 = "nihamasamora" base64wide
        $pass1bs64 = "niha@masamora!" base64wide
        $pass2bs64 = "Israel@123!" base64
        $pass3bs64 = "KazimAtes1977" ascii wide
        $pass4bs64 = "1234qqqQQQ" ascii wide
        $ip1bs64 = "212.175.168.58" ascii wide
        $ip2bs64 = "103.57.251.153" ascii wide
        $dmn1bs64 = "msn-center.uk" base64
        $dmn2bs64 = "twittsupport.com" base64
        
    condition:
        any of them
        and filesize < 100KB

}
