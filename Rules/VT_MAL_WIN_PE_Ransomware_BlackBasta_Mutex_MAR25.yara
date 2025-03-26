import "vt"

rule VT_MAL_WIN_PE_Ransomware_BlackBasta_Mutex_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects BlackBasta ransomware based on a specific Mutex that is created or opened"
    source = "https://cloud.google.com/blog/topics/threat-intelligence/unc4393-goes-gently-into-silentnight"
    filehash = "2ff24ec42290c87bcce05a935e9e2d8206dddf43fd4778b9e5ccce05248d1d90"
   
  condition:
    (for any mutex in vt.behaviour.mutexes_created : 
      (mutex == "ofijweiuhuewhcsaxs.mutex"))
    or
    (for any mutex in vt.behaviour.mutexes_opened: 
      (mutex == "ofijweiuhuewhcsaxs.mutex"))
}


