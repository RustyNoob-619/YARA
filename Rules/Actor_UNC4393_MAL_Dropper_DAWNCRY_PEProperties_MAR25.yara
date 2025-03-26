
import "pe"

rule Actor_UNC4393_MAL_Dropper_DAWNCRY_PEProperties_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects DAWNCRY which is a memory-only dropper that decrypts an embedded resource into memory used by UNC4393"
    source = "https://cloud.google.com/blog/topics/threat-intelligence/unc4393-goes-gently-into-silentnight"
    filehash = "021921800888bc174c40c2407c0ea010f20e6d32c596ed3286ebfe7bd641dd79"
    
  strings:
    $key = {65 69 55 56 79 72 79 67 6C 3E 58 45 2A 5E 71 78 45 59 69 49 56 56 61 38 34 4C} //Hardcoded Key
    
    
  condition:
    (pe.pdb_path == "SophosFSTelemetry.pdb" or $key)
    and filesize < 1MB
}
