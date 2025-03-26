rule MAL_LNX_ELF_LogTampering_SPAWNSLOTH_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Linux targeting backdoor known as SPAWNSLOTH based on observed strings"
    source = "https://blogs.jpcert.or.jp/ja/2025/02/spawnchimera.html"
    filehash1 = "47f7c7a137500ba6e1102e34d4c4239cd5970a685a7e5174ebe559988e9052cf"
    filehash2 = "749cf36adc5513c92c7acc836d20935e3c433f3c2d5641293e7a9c57c5ce22c2" 
    
  strings:
    $path1 = "/tmp/.liblogblock.so" ascii wide fullword 
    $path2 = "/home/jon/work/devices/pulse/"
    $ssh = "ssh-ed25519" ascii 

    $debug1 = "Invalid ELF class: 0x%x" ascii fullword
    $debug2 = "Invalid ELF header: 0x%02x,0x%02x,0x%02x,0x%02x" ascii fullword
    $debug3 = "64-bit target process isn't supported by 32-bit process." ascii fullword
    $debug4 = "failed to read a section header. (error: %s)" ascii fullword
    $debug5 = "failed to read a symbol table entry. (error: %s)" ascii fullword
    $debug6 = "failed to find %s%s%s in the .dynstr section." ascii fullword

    $str1 = "/bin/bash" ascii fullword
    $str2 = "/home/bin:/usr/bin:/bin:/usr/sbin:/sbin" ascii fullword
    $str3 = "/tmp/.dskey" ascii fullword
    $str4 = "/proc/self/exe" ascii fullword
    $str5 = "/proc/%d/maps" ascii fullword
    $str6 = "/proc/%u/" ascii fullword
    $str7 = "/home/perl5/bin/perl"
    
  condition:
    uint32be(0) == 0x7f454c46 //ELF Header
    and (any of ($path*) 
    or 
    ($ssh 
    and 4 of ($debug*)
    and 4 of ($str*)))
    and filesize < 2MB
}

//Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
