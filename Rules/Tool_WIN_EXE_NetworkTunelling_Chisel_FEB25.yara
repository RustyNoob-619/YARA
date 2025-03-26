
rule tool_WIN_EXE_NetworkTunelling_Chisel_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a network tunnelling utility called Chisel based on strings"
    source = "https://www.microsoft.com/en-us/security/blog/2025/02/12/the-badpilot-campaign-seashell-blizzard-subgroup-conducts-multiyear-global-access-operation/"
    filehash = "b9ef2e948a9b49a6930fc190b22cbdb3571579d37a4de56564e41a2ef736767b"
  
  strings:
    $chisel1 = "github.com/jpillora/chisel/client" ascii fullword 
    $chisel2 = "github.com/jpillora/chisel/server" ascii fullword 
    $chisel3 = "https://github.com/jpillora/chisel" ascii fullword
    $chisel4 = "server - runs chisel in server mode" ascii fullword
    $chisel5 = "client - runs chisel in client mode" ascii fullword
    $chisel6 = "The chisel process is listening for:" ascii fullword
    $chisel7 = "github.com/jpillora/chisel" ascii fullword
    $chisel8 = "Usage: chisel server [options]" ascii fullword
    $chisel9 = "Usage: chisel [command] [--help]" ascii fullword
    $chisel10 = "ssh -o ProxyCommand='chisel client chiselserver stdio:%h:%p' \\" ascii fullword

  condition:
    uint16(0) == 0x5a4d 
    and 3 of them
    and filesize < 10MB
}
