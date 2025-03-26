import "pe"

rule MAL_WIN_EXE_Dropper_Unknown_CodeSignCert_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Malware based on code signing certificates used in a major vishing campaign against multiple entities in Germany"
    credit = "@DTCERT for sharing the campaign information and malware sample hash"
    source = "https://x.com/DTCERT/status/1890384162818802135"
    filehash = "247e6a648bb22d35095ba02ef4af8cfe0a4cdfa25271117414ff2e3a21021886"
    
  condition:
    pe.signatures[0].thumbprint == "9f24096b07d3ac87e48db7d37cc70f269ae643a3" or 
    pe.signatures[0].thumbprint == "32a9b43eb22374ae870d5ac1c5357889cdf1c9e8" or 
    pe.signatures[0].thumbprint == "80a9bc77ce11da98e9e54f1e545c6c5b806c518a"
    and filesize < 1MB
}
