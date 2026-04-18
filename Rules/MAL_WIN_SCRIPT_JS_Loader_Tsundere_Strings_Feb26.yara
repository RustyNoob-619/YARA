rule MAL_WIN_SCRIPT_JS_Loader_Tsundere_Strings_Feb26
{
    meta:
        rule_id = "73bdf5ee-eb8e-4d6d-bb12-414c22aa180a"
        date = "28-02-2026"
        author = "Rustynoob619"
        description = "Detects a JavaScript based loader used to execute Tsundere Bot based on observed strings"
        source = "https://www.esentire.com/blog/muddywater-apt-tsundere-botnet-etherhiding-the-c2"
        filehash = "df8b94f7b3399b005cb64e879cfe04bfc3ba1499cf98608c10e532dbb493fa8d"

    strings:
        $js1 = "require(\"fs\")" ascii
        $js2 = "require(\"crypto\")" ascii
        $js3 = "require(\"child_process\")" ascii

        $node = "node-v18.17.0-win-x64" ascii

        $depend = "ethers@6.13.2" ascii

        $base64  = "function" base64

        $cmd1 = "Set-ItemProperty -Path 'HKCU:\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run'" ascii 
        $cmd2 = "Set-ItemProperty -Path 'HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'" ascii 

        

    condition:
        all of ($js*)
        and $node
        and $depend
        and $base64
        and any of ($cmd*)
        and filesize < 100KB
}
