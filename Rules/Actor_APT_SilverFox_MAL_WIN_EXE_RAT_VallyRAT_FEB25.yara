import "pe"

rule Actor_APT_Silver_Fox_MAL_WIN_EXE_RAT_VallyRAT_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Remote Access Trojen known as ValleyRAT that is written in C++ and complied in Chinese based on strings and PE properties"
    source = "https://www.morphisec.com/blog/rat-race-valleyrat-malware-china/?utm_content=323764605&utm_medium=social&utm_source=twitter&hss_channel=tw-2965779277"
    filehash1 = "968b976167b453c15097667b8f4fa9e311b6c7fc5a648293b4abd75d80b15562"
    filehash2 = "850770f7386b87dac25dfd58c96e59bd0745697dcf7141e77777db49951a9568"

  strings:
    $wide1 = "%s\\shell\\open\\command" wide fullword
    $wide2 = "localhost" wide fullword
    $wide3 = "%4d.%2d.%2d-%2d:%2d:%2d" wide fullword
    $wide4 = "%s %d %d %d %d" wide fullword 
    $wide5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide fullword
    $wide6 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000" wide
    
    $antiav1 = "UnThreat.exe" wide fullword 
    $antiav2 = "K7TSecurity.exe" wide fullword 
    $antiav3 = "ad-watch.exe" wide fullword 
    $antiav4 = "PSafeSysTray.exe" wide fullword 
    $antiav5 = "BitDefender" wide fullword 
    $antiav6 = "vsserv.exe" wide fullword 
    $antiav7 = "remupd.exe" wide fullword 
    $antiav8 = "rtvscan.exe" wide fullword 
    $antiav9 = "ashDisp.exe" wide fullword 
    $antiav10 = "avcenter.exe" wide fullword 
    $antiav11 = "TMBMSRV.exe" wide fullword 
    $antiav12 = "knsdtray.exe" wide fullword 
    $antiav13 = "egui.exe" wide fullword 
    $antiav14 = "Mcshield.exe" wide fullword 
    $antiav15 = "f-secure.exe" wide fullword 
    $antiav16 = "AYAgent.aye" wide fullword 
    $antiav17 = "SPIDer.exe" wide fullword 
    $antiav18 = "QUHLPSVC.EXE" wide fullword 
    $antiav19 = "baiduSafeTray.exe" wide fullword 
    $antiav20 = "KSafeTray.exe" wide fullword 
    $antiav21 = "ZhuDongFangYu.exe" wide fullword 
    $antiav22 = "360Safe.exe" wide fullword 
    // Add to the TTPs ruleset if any are missing

    $antivm1 = "VMwareService.exe" wide fullword 
    $antivm2 = "VMwareTray.exe" wide fullword 
    $antivm3 = "VMwareUser.exe" wide fullword 
    // Create a new TTPs rule for AntiVM processes
    
  condition:
    (pe.imphash() == "6676d6dfd2063d93860eb7a1ce2bd577" or pe.pdb_path == "C:\\Users\\谷堕\\Desktop\\2022远程管理gfi\\cangku\\WinOsClientProject\\x64\\Release-exe\\")
    or 
    (2 of ($wide*)
    and 10 of ($antiav*)
    and any of ($antivm*))
    and filesize < 500KB
    
}
