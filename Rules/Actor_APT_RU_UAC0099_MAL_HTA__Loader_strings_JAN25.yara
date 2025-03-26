rule Actor_APT_RU_UAC0099_MAL_HTA__Loader_strings_JAN25

{
  meta:
    author = "RustyNoob619"
    description = "Detects HTA file that executes next stage VBS script which is used in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash = "88b64a3eb0dc38e3f8288b977b1cd67af7d4ba959297ac48ef5f06bec3e77560"

  strings:
    $html= {3c 21 44 4f	43 54 59 50	45 20 68 74	6d 6c 3e 0a}

    $lnk = {4C 00 00 00 01 14 02 00}

    $vbsexec = "<SCRIPT language=\"VBScript\">" fullword

    $wscript = "createobject(\"WScript.Shell\")" ascii wide

    $base64 = "base64" nocase

    $pwrshll1 = "system.net.webclient" ascii wide
    $pwrshll2 = "powershell.exe" ascii wide 
    $pwrshll3 = "-exec bypass" ascii wide
    $pwrshll4 = "-w hidden -nop" ascii wide

    $vbspath1 = "set-content C:\\\\Users\\\\Public\\\\Documents\\\\"
    $vbspath2 = "set-content C:\\Users\\Public\\Documents\\"

    $schtsks = "schtasks.exe /create /TN ExplorerCoreUpdateTaskMachine /SC minute /mo 3 /tr"

    $usragnt = "Ds26GOZNxbTxlJY" ascii wide

    $c2url = "https://newyorktlimes.life/api/values"

  condition:
    ($html at 0 or $lnk at 0)
    and ($usragnt or $c2url)
    or 
    ($vbsexec
    and any of ($vbspath*)
    and $wscript
    and $base64
    and 2 of ($pwrshll*)
    and $schtsks)
    and filesize < 25KB
}



