import "pe"

rule Actor_UNC4393_MAL_Dropper_KNOTWRAP_PEProperties_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects KNOTWRAP which is a memory-only dropper that can execute an additional payload in memory used by UNC4393 (BlackBasta)"
    source = "https://cloud.google.com/blog/topics/threat-intelligence/unc4393-goes-gently-into-silentnight"
    filehash1 = "b32daf27aa392d26bdf5faafbaae6b21cd6c918d461ff59f548a73d447a96dd9"
    filehash2 = "9716f952a0ea4eb9b4765002a0b096b0f03487387f0a42941f344fc4c61f8abe"
   
  condition:
    ((pe.pdb_path startswith "E:\\cpp\\git7\\")
    or 
    (for 10 resource in pe.resources:
    (resource.type_string == "C\x00O\x00D\x00E\x00")
    and pe.version_info["InternalName"] == "RibbonGadgets"
    and pe.version_info["FileVersion"] contains "1, 0, 0"))
    and filesize < 10MB
}

