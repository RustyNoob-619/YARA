rule Actor_APT_IR_APT35_MAL_WIN_VBA_Script_Unknown_Strings_Feb26
{
    meta:
        rule_id = "00ff1c14-3df0-4d1b-a2a3-1bc3e91bf2fd"
        date = "02-02-2026"
        author = "Rustynoob619"
        description = "Detects a VBA script to deploy a custom webshell used by Iranian APT35 (Charming Kitten) based on strings"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "8594cd47765b25347e5334c8c5dac35dc7b8acff32fa03fc8df20fba61a8a912"
    
    strings:
        $str1 = "CreateObject(\"WSCRIPT.SHELL\")" ascii
        $str2 = "CreateObject(\"WSCRIPT.NETWORK\")" ascii
        $str3 = "CreateObject(\"Scripting.FileSystemObject\")" ascii
        $str4 = "objCmdExec.StdOut.ReadAll" ascii
        $str5 = "Response.Status" ascii 
        $str6 = "Response.End" ascii

        $uniq1 = "Function getCommandOutput(theCommand)" ascii fullword
        $uniq2 = "thisDir = getCommandOutput(\"cmd /c\"" ascii fullword
        $uniq3 = "If acceptLanguage <> \"\" Then" ascii fullword
        $uniq4 = "acceptLanguage = Request.ServerVariables(\"HTTP_ACCEPT_LANGUAGE\")" ascii fullword
        
    condition:
        2 of ($uniq*)
        and 4 of ($str*)
        and filesize < 25KB

}
