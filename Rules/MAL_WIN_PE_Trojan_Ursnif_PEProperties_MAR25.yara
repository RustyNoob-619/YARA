
import "pe"

rule MAL_WIN_PE_Trojan_Ursnif_PEProperties_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Russian banking trojan known as Ursnif based on PE properties"
    source = "https://www.acronis.com/en-gb/cyber-protection-center/posts/ursnif-the-banking-trojan/"
    filehash = "2b09154b498e9959f5efbcfa768dcdc2394dc527b2785e1ce68bc8a33c6804b8"
   
  condition:
    (pe.pdb_path == "E:\\cpp\\out\\exe\\out1.pdb" or pe.imphash() == "cbd27382b1456bbb0e653efd2c3d3924")
    and pe.locale(0x0419) // Russian Language 
    and pe.imports("SHLWAPI.dll", 155)
    and pe.imports("KERNEL32.dll", "GetCurrentProcess")
    and pe.imports("KERNEL32.dll", "GetProcAddress")
    and pe.imports("KERNEL32.dll", "VirtualAlloc")
    and pe.imports("KERNEL32.dll", "LoadLibraryA")
    and pe.imports("KERNEL32.dll", "LoadLibraryExW")
    and filesize < 1MB
}


