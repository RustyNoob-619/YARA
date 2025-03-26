
import "pe"

rule Actor_APT_RU_UAC0212_MAL_WIN_PE_EMPIREPAST_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects EMPIREPAST malware that was used by UAC-0212 which is a sub-cluster of Sandworm"
    credit = "https://cert.gov.ua/article/6282517"
    filehash = "4a302c0ed3c47231bc7c34cf2d41bc0ceb60d9c7b0023df015f75a58853f43d2"
  
  strings:
    $domain = "protectconnections.com" ascii fullword
    $cmd = "cmd.exe" ascii fullword

  condition:
    (pe.imphash() == "39f2a397d177ea36c4f18a77ec235b92" or pe.imphash() == "4ef6effa4a8b91ddb7f3658b682f2d73"
    or pe.exports("DoUpdateInstanceEx") or $domain)
    and $cmd
    and pe.number_of_signatures == 1
    and filesize < 500KB
}




