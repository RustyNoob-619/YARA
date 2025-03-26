import "pe"

rule MAL_WIN_EXE_Dropper_Unknown_ImportHash_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Malware  based on PE import hash used in a major vishing campaign against multiple entities in Germany"
    credit = "@DTCERT for sharing the campaign information and malware sample hash"
    source = "https://x.com/DTCERT/status/1890384162818802135"
    filehash = "247e6a648bb22d35095ba02ef4af8cfe0a4cdfa25271117414ff2e3a21021886"
    
  condition:
    pe.imphash() == "5a755e29193339e4eafe8862e60c0345"
    and filesize < 1MB
}


