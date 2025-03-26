import "pe"

rule MAL_WIN_EXE_Dropper_Unknown_PDBPath_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Malware based on the PDB path used in a major vishing campaign against multiple entities in Germany"
    credit = "@DTCERT for sharing the campaign information and malware sample hash"
    source = "https://x.com/DTCERT/status/1890384162818802135"
    filehash = "247e6a648bb22d35095ba02ef4af8cfe0a4cdfa25271117414ff2e3a21021886"
    
  condition:
    pe.pdb_path == "D:\\a\\1\\s\\x64\\Release\\Desktops64.pdb"
    and filesize < 1MB
}


