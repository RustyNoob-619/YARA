
rule Actor_APT_CN_APT41_MAL_LNX_ELF_Backdoor_Speculoos_strings_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects old and new samples of ELF Backdoor known as Speculoos used by APT41 since 2020"
    credit = "@TuringAlex for identifying new malware samples with low detections"
    source1 = "https://x.com/TuringAlex/status/1896172610008047705"
    source2 = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
    filehash1 = "a73e50c83e9e7f791af4130ff1295b876f7389e8da90a23dff57d60ce33e1819"
    filehash2 = "99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28"
    
  strings:
    $compile1 = "GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-4)" ascii fullword
    $compile2 = "GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-44)" ascii fullword
    $compile3 = "GCC: (GNU) 4.2.1 20070831 patched [FreeBSD]" ascii fullword

    $fish1 = "FishDiskSimpleControl" ascii
    $fish2 = "FishDiskDownload" ascii
    $fish3 = "FishDiskUploadFile" ascii
    $fish4 = "FishServiceControl" ascii
    $fish5 = "FishProxyDisConnect" ascii
    $fish6 = "FishDiskUninstall"ascii
    $fish7 = "FishProxyConnect" ascii
    $fish8 = "FishDoShellCmd" ascii
    $fish9 = "FishSystemInfo" ascii
    $fish10 = "FishFileItem" ascii
    $fish11 = "FishDiskRename" ascii

  condition:
    uint32be(0) == 0x7f454c46
    and any of ($compile*)
    and any of ($fish*)
    and filesize < 750KB
}

