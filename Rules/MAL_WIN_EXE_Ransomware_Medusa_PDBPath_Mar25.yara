 
import "pe"
 
rule MAL_WIN_EXE_Ransomware_Medusa_PDBPath_Mar25
{
    meta:
        rule_id = "c58cde32-c6a1-4cc2-9620-81ce7189ffd0"
        date = "25-03-2025"
        author = "Bridewell CTI"
        description = "Detects Windows Targeting Ransomware called Medusa based on the the PDB artifact"
        source = "https://any.run/malware-trends/medusa/"
        filehash = "3a6d5694eec724726efa3327a50fad3efdc623c08d647b51e51cd578bddda3da"
 
    strings:
        $str1 = "\\Windows.old\\" wide fullword
        $str2 = "\\PerfLogs\\" wide fullword
        $str3 = "\\MSOCache\\" wide fullword
        $str4 = "encrypt %d %ls %ld" wide fullword
        $str5 = "cmd /c ping localhost -n 3 > nul" ascii fullword
        $str6 = "powershell -executionpolicy bypass -File %s" ascii fullword
 
    condition:
        pe.pdb_path == "G:\\Medusa\\Release\\gaze.pdb"
        and 3 of them
        and filesize < 1MB
}
