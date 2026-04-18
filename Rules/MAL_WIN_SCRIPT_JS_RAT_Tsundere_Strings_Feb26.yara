rule MAL_WIN_SCRIPT_JS_RAT_Tsundere_Strings_Feb26
{
    meta:
        rule_id = "a980f9f4-d9df-41b5-ad31-ce1b5fd600b4"
        date = "27-02-2026"
        author = "Rustynoob619"
        description = "Detects a JavaScript based Tsunere Bot malware based on observed strings"
        source = "https://www.esentire.com/blog/muddywater-apt-tsundere-botnet-etherhiding-the-c2"
        filehash = "dd87dfb302501e3cbe2e59fca9e14bfd53e65ed313c1b70e4d7daf68d86386ff"

    strings:
        $js1 = "require(\"ws\")" ascii
        $js2 = "require(\"crypto\")" ascii
        $js3 = "require(\"ethers\")" ascii

        $buildid = "f1c2d70b-0d6b-431a-b9d9-5cefb0affac1" ascii
        $contract = "0x2B77671cfEE4907776a95abbb9681eee598c102E" ascii
        $wallet = "0x002E9Eb388CBd72bad2e1409306af719D0DB15e4" ascii

        $rpc1= "https://eth.llamarpc.com" ascii
        $rpc2= "https://mainnet.gateway.tenderly.co" ascii
        $rpc3= "https://rpc.flashbots.net/fast" ascii
        $rpc4= "https://rpc.mevblocker.io" ascii
        $rpc5= "https://eth-mainnet.public.blastapi.io" ascii
        $rpc6= "https://ethereum-rpc.publicnode.com" ascii
        $rpc7= "https://rpc.payload.de" ascii
        $rpc8= "https://mainnet.eth.cloud.ava.do" ascii
        $rpc9= "https://eth.drpc.org" ascii
        $rpc10= "https://eth.merkle.io" ascii

        $cmd1 = "Get-WmiObject Win32_VideoController" ascii
        $cmd2 = "[System.Globalization.CultureInfo]::InstalledUICulture.Name" ascii
        $cmd3 = "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Cryptography\\\" /v MachineGuid" ascii
        $cmd4 = "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\" /v ProductName" ascii
        $cmd5 = "HKLM\\\\HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS\\" ascii

        $hex = {5b 22 68 79 22 2c 20 22 68 79 2d 41 4d 22 2c 20 22 61 7a 22 2c 20 22 62 65 22 2c 20 22 62 65 2d 42 59 22 2c 20 22 6b 6b 22 2c 20 22 6b 6b 2d 4b 5a 22 2c 20 22 6b 79 22 2c 20 22 6b 79 2d 4b 47 22 2c 20 22 72 75 22 2c 20 22 72 75 2d 42 59 22 2c 20 22 72 75 2d 4b 5a 22 2c 20 22 72 75 2d 4b 47 22 2c 20 22 72 75 2d 4d 44 22 2c 20 22 72 75 2d 52 55 22 2c 20 22 72 75 2d 55 41 22 2c 20 22 74 67 22 2c 20 22 75 6b 22 2c 20 22 75 6b 2d 55 41 22 2c 20 22 75 7a 22 5d} //Countries Exclussion Check

    condition:
        all of ($js*)
        and ($buildid or $contract or $wallet or $hex)
        or (
            6 of ($rpc*)
            and 3 of ($cmd*) 
        )
        and filesize < 100KB
}
