import "pe"

rule SUS_WIN_PE_VulnDriver_WIN_SYS_Procexp_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Vulnerable Windows Driver that was exploited by Abyss ransomware, Agent Tesla and Fin7"
    source1 = "https://www.sygnia.co/blog/abyss-locker-ransomware-attack-analysis/"
    source2 = "https://www.sentinelone.com/labs/fin7-reboot-cybercrime-gang-enhances-ops-with-new-edr-bypasses-and-automated-attacks/"
    source3 = "https://x.com/SBousseaden/status/1592949091184611329"
    filehash = "d76c74fc7a00a939985ae515991b80afa0524bf0a4feaec3e5e58e52630bd717"
  
  strings:
    $wide1 = "\\DosDevices\\PROCEXP152" wide fullword
    $wide2 = "\\Device\\PROCEXP152" wide fullword
    $wide3 = "IoValidateDeviceIoControlAccess" wide fullword
    $wide4 = "IoCreateDeviceSecure" wide fullword
    $wide5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class" wide fullword

  condition:
    ((pe.imphash() == "192407b9613ece36cb3e3bc2b2ad984c" or pe.imphash() == "d122c1eaa50839be14c31876d0d4e0be" or pe.pdb_path == "D:\\a\\1\\s\\sys\\x64\\Release\\ProcExpDriver.pdb")
    or
    (pe.signatures[0].issuer contains "Microsoft Windows Third Party Component CA 2012"
    and pe.version_info["InternalName"] == "procexp.sys"
    and 3 of ($wide*)))
    and filesize < 100KB
    
}
