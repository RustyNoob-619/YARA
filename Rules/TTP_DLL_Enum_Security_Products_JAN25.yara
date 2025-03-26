rule TTP_DLL_Enum_Security_Products_JAN25
{
  meta:
    author = "Rustynoob619"
    description = "Detects Windows executables that attempt to enumerate security product file names for defense evasion"
    example_filehash = "78f86c3581ae893e17873e857aff0f0a82dcaed192ad82cd40ad269372366590"
  
  strings:
  
    $secprdct1 = "ZhuDongFangYu.exe" nocase ascii wide fullword
    $secprdct2 = "360sd.exe" nocase ascii wide fullword
    $secprdct3 = "kxetray.exe" nocase ascii wide fullword
    $secprdct4 = "KSafeTray.exe" nocase ascii wide fullword
    $secprdct5 = "QQPCRTP.exe" nocase ascii wide fullword
    $secprdct6 = "HipsDaemon.exe" nocase ascii wide fullword
    $secprdct7 = "BaiduSd.exe" nocase ascii wide fullword
    $secprdct8 = "baiduSafeTray.exe" nocase ascii wide fullword
    $secprdct9 = "KvMonXP.exe" nocase ascii wide fullword
    $secprdct10 = "RavMonD.exe" nocase ascii wide fullword
    $secprdct11 = "QUHLPSVC.EXE" nocase ascii wide fullword
    $secprdct12 = "QuickHeal" nocase ascii wide fullword
    $secprdct13 = "mssecess.exe" nocase ascii wide fullword
    $secprdct14 = "cfp.exe" nocase ascii wide fullword
    $secprdct15 = "SPIDer.exe" nocase ascii wide fullword
    $secprdct16 = "DR.WEB" nocase ascii wide fullword
    $secprdct17 = "acs.exe" nocase ascii wide fullword
    $secprdct18 = "Outpost" nocase ascii wide fullword
    $secprdct19 = "V3Svc.exe" nocase ascii wide fullword
    $secprdct20 = "AYAgent.aye" nocase ascii wide fullword
    $secprdct21 = "avgwdsvc.exe" nocase ascii wide fullword
    $secprdct22 = "AVG" nocase ascii wide fullword
    $secprdct23 = "f-secure.exe" nocase ascii wide fullword
    $secprdct24 = "F-Secure" nocase ascii wide fullword
    $secprdct25 = "avp.exe" nocase ascii wide fullword
    $secprdct26 = "Mcshield.exe" nocase ascii wide fullword
    $secprdct27 = "egui.exe" nocase ascii wide fullword
    $secprdct28 = "NOD32" nocase ascii wide fullword
    $secprdct29 = "knsdtray.exe" nocase ascii wide fullword
    $secprdct30 = "TMBMSRV.exe" nocase ascii wide fullword
    $secprdct31 = "avcenter.exe" nocase ascii wide fullword
    $secprdct32 = "ashDisp.exe" nocase ascii wide fullword
    $secprdct33 = "rtvscan.exe" nocase ascii wide fullword
    $secprdct34 = "remupd.exe" nocase ascii wide fullword
    $secprdct35 = "vsserv.exe" nocase ascii wide fullword
    $secprdct36 = "BitDefender" nocase ascii wide fullword
    $secprdct37 = "PSafeSysTray.exe" nocase ascii wide fullword
    $secprdct38 = "ad-watch.exe" nocase ascii wide fullword
    $secprdct39 = "K7TSecurity.exe" nocase ascii wide fullword
    $secprdct40 = "UnThreat.exe" nocase ascii wide fullword
    $secprdct41 = "UnThreat" nocase ascii wide fullword
    $secprdct42 = "HipsTray.exe" nocase ascii wide fullword
    $secprdct43 = "MsMpEng.exe" nocase ascii wide fullword // not in the sample
    $secprdct44 = "360tray.exe" nocase ascii wide fullword
    $secprdct45 = "360Safe.exe" nocase ascii wide fullword
    $secprdct46 = "kscan.exe" nocase ascii wide fullword
    $secprdct47 = "kxescore.exe" nocase ascii wide fullword
    $secprdct48 = "kwsprotect64.exe" nocase ascii wide fullword
    $secprdct49 = "QQRepair.exe" nocase ascii wide fullword
    $secprdct50 = "QQPCTray.exe" nocase ascii wide fullword
    $secprdct51 = "QQPCRealTimeSpeedup.exe" nocase ascii wide fullword
    $secprdct52 = "QQPCPatch.exe" nocase ascii wide fullword
    $secprdct53 = "QMPersonalCenter.exe" nocase ascii wide fullword
    $secprdct54 = "QMDL.exe" nocase ascii wide fullword
    $secprdct55 = "HipsMain.exe" nocase ascii wide fullword
    $secprdct56 = "Comodo" nocase ascii wide fullword
    $secprdct57 = "avpui.exe" nocase ascii wide fullword
    $secprdct58 = "egui.exe" nocase ascii wide fullword
    $secprdct59 = "Ad-watch" nocase ascii wide fullword

    $secprdct60 = "Fiddler" nocase ascii wide fullword
    $secprdct61 = "Wireshark" nocase ascii wide fullword
    $secprdct62 = "Metascan" nocase ascii wide fullword
    $secprdct63 = "TaskExplorer" nocase ascii wide fullword
    $secprdct64 = "Malwarebytes" nocase ascii wide fullword
    $secprdct65 = "TCPEye" nocase ascii wide fullword
    $secprdct66 = "CurrPorts" nocase ascii wide fullword
    $secprdct67 = "ApateDNS" nocase ascii wide fullword

  condition:
    uint16(0) == 0x5a4d
    and any of them
}
