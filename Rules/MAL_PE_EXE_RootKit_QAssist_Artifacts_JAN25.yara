import "pe"

rule MAL_PE_EXE_RootKit_QAssist_Artifacts_JAN25
{
  meta:
    author = "Rustynoob619"
    description = "Detects QAssist rootkit dropped by PLAYFULGHOST for added functionality"
    reference = "https://www.googlecloudcommunity.com/gc/Community-Blog/Finding-Malware-Unveiling-PLAYFULGHOST-with-Google-Security/ba-p/850676"
    filehash = "6cce28b275d5ec20992bb13790976caf434ab46ddbfd5cfd431d33424943122b"
  
  strings:
    $qassist1 = "QAssist" fullword 
    $qassist2 = "\\Device\\QAssist" wide fullword
    $qassist3 = "\\Device\\QAssist" wide fullword

    $hid1 = "Hid_State" wide fullword
    $hid2 = "Hid_StealthMode"wide fullword
    $hid3 = "Hid_HideFsDirs" wide fullword
    $hid4 = "Hid_HideFsFiles" wide fullword
    $hid5 = "Hid_HideRegKeys" wide fullword
    $hid6 = "Hid_HideRegValues" wide fullword
    $hid7 = "Hid_IgnoredImages" wide fullword
    $hid8 = "Hid_ProtectedImages" wide fullword

    $rgstr1 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet" wide fullword
    $rgstr2 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001" wide fullword
    $rgstr3 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002" wide fullword

  condition:
    pe.number_of_signatures > 0
    and ((pe.pdb_path endswith "QAssist.pdb"
    and pe.pdb_path contains "hidden-master")
    or 
    (any of ($qassist*)
    and 5 of ($hid*)
    and any of ($rgstr*))) 
    and filesize < 500KB
}