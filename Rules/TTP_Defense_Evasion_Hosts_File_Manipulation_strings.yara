rule TTP_Defense_Evasion_Hosts_File_Manipulation_strings
{
  meta:
    author = "RustyNoob619"
    description1 = "Detects Suspicious Files that use Hosts File Manipulation technique to block AI and Security Tools"
    description2 = "THis technique is currently seen across Skliter Ransomware, NjRAT & Redline"
    credit = "@MalGamy12 for sharing the file sample and the technique used"
    source = "https://x.com/MalGamy12/status/1893048519373529154"
    filehash1 = "aaa24bc17674950bd46c4ce60759b54b24a3d119df613db0faa4c2887243dfa7" //Skliter
    filehash2 = "94d98a4d27a326f269c7c470a370ad62389b14b81fb06e69037cb629598a4e1c" //NjRAT
    filehash3 = "48091df5d67daf41a0037b2889d602ddb5c2780bef0f3df078f8d22c55be149b" //Redline
    
  strings:
    $path = "C:/Windows/System32/drivers/etc/hosts" ascii wide fullword 

    $hex1 = {31 32 37 2e 30 2e 30 2e 31 20 20 20 [10-30] 2e 63 6f 6d 0a} //127.0.0.1   custom_domain_name

    $hex2 = {30 2e 30 2e 30 2e 30 20 [10-30] 2e 63 6f 6d 0a} //0.0.0.0   custom_domain_name

    $str1 = "127.0.0.1   www.malwarebytes.com" ascii wide fullword 
    $str2 = "127.0.0.1   www.emsisoft.com" ascii wide fullword 
    $str3 = "127.0.0.1   www.kaspersky.com" ascii wide fullword 
    $str4 = "127.0.0.1   www.trendmicro.com" ascii wide fullword 
    $str5 = "127.0.0.1   www.bitdefender.com" ascii wide fullword 
    $str6 = "127.0.0.1   www.avast.com" ascii wide fullword 
    $str7 = "127.0.0.1   www.acronis.com" ascii wide fullword 
    $str8 = "127.0.0.1   www.crowdstrike.com" ascii wide fullword 
    $str9 = "127.0.0.1   www.comodo.com" ascii wide fullword 
    $str10 = "127.0.0.1   www.norton.com" ascii wide fullword 
    $str11 = "127.0.0.1   www.mcafee.com" ascii wide fullword 
    $str12 = "127.0.0.1   www.avg.com" ascii wide fullword 
    $str13 = "127.0.0.1   www.eset.com" ascii wide fullword 
    $str14 = "127.0.0.1   www.webroot.com" ascii wide fullword 
    $str15 = "127.0.0.1   www.deepseek.com" ascii wide fullword 
    $str16 = "127.0.0.1   www.chatgpt.com" ascii wide fullword 

  condition:
    $path 
    and ((any of ($str*)) or (any of ($hex*)))
    and filesize < 25MB
}
