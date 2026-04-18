rule Actor_APT_CN_AmaranthDragon_MAL_SCRIPT_BAT_Loader_Unknown_Feb26
{
    meta:
        rule_id = "56d1a457-4589-4e76-80f4-539066d03f56"
        date = "2026-02-16"
        author = "Rustynoob619"
        description = "Detects a malicious batch loader used by Amaranth-Dragon (nexus of APT41)"
        source = "https://research.checkpoint.com/2026/amaranth-dragon-weaponizes-cve-2025-8088-for-targeted-espionage/"
        filehash = "8aacc30dac2ca9f41d7dd6d2913d94b0820f802bc04461ae65eb7cf70b53a8ab" 

    strings:
        $spec1 = "/scl/fi/csggj44n9255y3vsjhh0p/" ascii
        $spec2 = "rlkey=oaffvs9si6wkc6j4ccushn133" ascii 
    
        $file1 = "wsNativePush.exe" ascii
        $file2 = "wsUpgrade.dll" ascii
        $file3 = "wsNativePush.zip" ascii 
        
        $cmd1 = "bitsadmin /transfer"
        $cmd2 = "powershell -WindowStyle Hidden -NoLogo -NoProfile" ascii
        $cmd3 = "[IO.Compression.ZipFile]::ExtractToDirectory" ascii
        $cmd4 = "Add-Type -AssemblyName 'System.IO.Compression.FileSystem" ascii

    condition:
        (any of ($spec*))
        or (  
        any of ($file*)    
        and 2 of ($cmd*)
        )
        and filesize < 50KB 
}
