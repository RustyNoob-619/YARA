import "pe"

rule MAL_WIN_EXE_RemoteShell_RemCom_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Windows Remote Hacking Tool known as RemCom that was observed to be used by Abyss and Black Cat Ransomware"
    source1 = "https://www.sygnia.co/blog/abyss-locker-ransomware-attack-analysis/"
    source2 = "https://securityintelligence.com/posts/blackcat-ransomware-levels-up-stealth-speed-exfiltration/"
    filehash = "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
  
  strings:
    $str1 = "RemComSvc"
    $str2 = "RemCom_stderr" ascii fullword
    $str3 = "RemCom_stdin" ascii fullword
    $str4 = "RemCom_stdout" ascii fullword
    $str5 = "\\\\.\\pipe\\RemCom_communicaton" ascii fullword

  condition:
    ((pe.imphash() == "4749670ac3d28d6761142b0dcb4f5076")
    or 
    (uint16be(0) == 0x4d5a  
    and 2 of ($str*)))
    and filesize < 100KB
    
}

