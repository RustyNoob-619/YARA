


rule Actor_APT_DPRK_MAL_SCRIPT_JS_Loader_Unknown_Strings_Feb26
{
    meta:
        rule_id = "713af537-771f-44ee-b65c-1647d5ec9a84"
        date = "18-02-2026"
        author = "Rustynoob619"
        description = "Detects JavaScript used by DPRK operators to fetch the next stay payloads"
        filehash1 = "165324541c8f2d0a4bdac12fcf7ccc1738caf7e36bb11721186e0c560c4a8a69"
        filehash2 = "e1790a08ebf0402d49e826b6f773b3b6e55f3cb5a755bc2067dda2a0c2737503"

    strings:
        $js1 = "const" ascii
        $js2 = "async function" ascii

        $str1 = "hostname" ascii
        $str2 = "macs" ascii
        $str3 = "networkInterfaces" ascii
        $str4 = "filter" ascii
        $str5 = "instanceId" ascii
        $str6 = "errorMessage" ascii
        $str7 = "setInterval" ascii

        $hex1 = {65 78 63 65 70 74 69 6f 6e 49 64 3a 22 65 6e 76 ?? ?? ?? ?? ?? ?? 22}
        $hex2 = {27 73 74 61 74 75 73 27 2c 27 65 6e 76 ?? ?? ?? ?? ?? ?? 27}

        $uri = ":3000/api/errorMessage" ascii

        $mac = "00:00:00:00:00:00" ascii

    condition:
        all of ($js*)
        and 5 of ($str*)
        and (any of ($hex*) or $uri)
        and $mac
        and filesize < 25KB 

}
