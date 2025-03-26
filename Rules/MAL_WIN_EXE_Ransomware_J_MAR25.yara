
import "pe"

rule MAL_WIN_EXE_Ransomware_J_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Windows ransomware known as J based on PE properties and readable strings"
    credit = "@PaduckLee for sharing the malware sampleand attribution"
    source = "https://x.com/PaduckLee/status/1896911417980412093"
    filehash = "3fef5c7fa519f5384de6f61c954ead6dfd4da727005bfec954dc801bd120a938"
    
  strings:
    $art1 = "(o o) boo" ascii fullword
    $art2 = "\\   \\" ascii fullword 

    $onion = "https://w4d5aqmdxkcsc2xwcz7w7jo6wdmvmakgy3y6mfmdtzmyvxe77cjkfbad.onion"

    $extension = "all files on your system has extension .j" ascii

    $loc = "C:\\ProgramDataC:\\Users\\DefaultC:\\Users\\PublicC:\\$Recycle.BinC:\\WindowsHELLO_README.txt"

    $rust1 = "rustc" ascii 
    $rust2 = "cargo" ascii

    $cmd1 = "cmdvssadmin.exedeleteshadows/all/quiet/C" ascii fullword
    $cmd2 = "*wordpad*notepad*sql*cmd.exe/cpowershell-command \"Get-VM" ascii
    $cmd3 = "Stop-VM -Force\"taskkill/f" ascii 
    $cmd4 = "vc*firefox*tbirdconfig*mydesktopqos*ocomm*dben50*sqbcoreservice*excel*infopath*msaccess*mspu*onenote*outlook*powerpnt*steam*thebat*thunderbird*visio*winword" ascii
    
  condition:
    uint16(0) == 0x5a4d
    and ((pe.imphash() == "90803b542435eb267bbf54521c4b8e5b" 
    or pe.pdb_path == "C:\\Users\\root\\Desktop\\Trojan\\locker\\target\\x86_64-pc-windows-msvc\\release\\deps\\crypt.pdb"
    or $onion or $extension or $loc or (all of ($art*)))
    or
    (any of ($rust*) and 2 of ($cmd*)))  
    and filesize < 2MB
}



