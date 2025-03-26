import "pe"

rule Actor_APT_Silver_Fox_MAL_WIN_FirstStage_DLL_RAT_VAllyRAT_2_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects first stage DLL that contributes to deployment of ValleyRAT based on strings and PE properties"
    source = "https://www.morphisec.com/blog/rat-race-valleyrat-malware-china/?utm_content=323764605&utm_medium=social&utm_source=twitter&hss_channel=tw-2965779277"
    filehash = "7c2a1b09617566ff9e94d0b1c15505213589f7fd3b445b334051d9574e52e0f5"

  strings:
    $pydll = "python27.dll" ascii fullword

    $antiav1 = "MpCmdRun.exe" wide fullword 
    $antiav2 = "SecurityHealthSystray.exe" wide fullword 
    $antiav3 = "NisSrv.exe" wide fullword 
    $antiav4 = "MsMpEng.exe" wide fullword 
    $antiav5 = "SophosFileScanner.exe" wide fullword 
    $antiav6 = "SophosFS.exe" wide fullword 
    $antiav7 = "360Safe.exe" wide fullword 
    $antiav8 = "ZhuDongFangYu.exe" wide fullword 
    $antiav9 = "SSPService.exe" wide fullword 
    $antiav10 = "SophosNetFilter.exe" wide fullword 
    $antiav11 = "SEDService.exe" wide fullword 
    $antiav12 = "hmpalert.exe" wide fullword 
    $antiav13 = "McsAgent.exe" wide fullword 
    $antiav14 = "McsClient.exe" wide fullword 
    $antiav15 = "ekrn.exe" wide fullword 
    $antiav16 = "eguiProxy.exe" wide fullword 
    $antiav17 = "efwd.exe" wide fullword 
    $antiav18 = "bdagent.exe" wide fullword 
    $antiav19 = "bdvsnf.exe" wide fullword 
    $antiav20 = "updatesrv.exe" wide fullword 
    $antiav21 = "mfevtps.exe" wide fullword 
    $antiav22 = "delegate.exe" wide fullword
    $antiav23 = "Launch.exe" wide fullword
    $antiav24 = "mcapexe.exe" wide fullword
    $antiav25 = "McInstruTrack.exe" wide fullword
    $antiav26 = "MMSSHOST.exe" wide fullword
    $antiav27 = "ProtectedModuleHost.exe" wide fullword
    $antiav28 = "McUICnt.exe" wide fullword
    $antiav29 = "NortonSecurity.exe" wide fullword
    $antiav30 = "nsWscSvc.exe" wide fullword

  condition:
    (pe.imphash() == "bb25c54bc967c6ef4b6ba783c400cc56")
    or 
    ($pydll and 15 of ($antiav*)
    and pe.exports("Py_Main")
    and pe.exports("MputSetBoolRpc")
    and pe.exports("MputAddToAverageDWORDRpc")
    and pe.exports("MpUpdateStart")
    and pe.exports("MpTelemetryUpload")
    and pe.exports("MpTelemetryInitialize")
    and pe.exports("MpScanStart")
    and pe.exports("MpManagerVersionQuery")
    and pe.exports("MpConfigSetValue")
    and pe.exports("MpCleanStart")
    and pe.exports("MpConfigIteratorEnum")
    and pe.exports("MpDebugExportFunctions")
    and pe.exports("MpGetEngineVersion"))
    and filesize < 500KB
    
}

