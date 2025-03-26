import "pe"

rule SUS_WIN_PACKER_Themida_PE_Sections_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Themida Packer based on the section name in the PE file"
    credit = "@ShanHolo for sharing the malware sample and infection chain"
    source = "https://x.com/ShanHolo/status/1893595833330700725"
    filehash = "36cdb54c76cc9457a56c1f3731cb757f101442e7a569972ddb5ac207847255b5"
    
  strings:
    $themida = ".themida" ascii wide fullword
    
  condition:
    ($themida or 
    (for any section in pe.sections:
    (section.name == ".themida")))
    and filesize < 25MB
}


