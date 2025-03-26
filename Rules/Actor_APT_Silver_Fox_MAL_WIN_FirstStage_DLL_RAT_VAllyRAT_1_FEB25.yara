import "pe"

rule Actor_APT_Silver_Fox_MAL_WIN_FirstStage_DLL_RAT_VAllyRAT_1_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects first stage DLL that contributes to deployment of ValleyRAT based on strings and PE properties"
    source = "https://www.morphisec.com/blog/rat-race-valleyrat-malware-china/?utm_content=323764605&utm_medium=social&utm_source=twitter&hss_channel=tw-2965779277"
    filehash = "1db77692eaf4777f69ddf78c52424d81834572f1539ccea263d86a46f28e0cea"

  strings:
    $antiav1 = "NSIS.exe" ascii fullword 
    $antiav2 = "Calc.exe" ascii fullword 
    $antiav3 = "QMDL.exe" ascii fullword  
    $antiav4 = "QQPCRTP.exe" ascii fullword  
    $antiav5 = "QQPCTray.exe" ascii fullword  
    $antiav6 = "360rp.exe" ascii fullword  
    $antiav7 = "EXCEL.exe" ascii fullword  
    $antiav8 = "360sdupd.exe" ascii fullword  
    $antiav9 = "360huabao.exe" ascii fullword  
    $antiav10 = "DSMain.exe" ascii fullword  
    $antiav11 = "360sd.exe" ascii fullword  
    $antiav12 = "DumpUper.exe" ascii fullword  
    $antiav13 = "FireFox.exe" ascii fullword  
    $antiav14 = "xdict.exe" ascii fullword  
    $antiav15 = "360Safe.exe" ascii fullword  
    $antiav16 = "360tray.exe" ascii fullword  
    $antiav17 = "360Tray.exe" ascii fullword  
    $antiav18 = "360LogCenter.exe" ascii fullword  
    $antiav19 = "LiveUpdate360.exe" ascii fullword  
    $antiav20 = "ZhuDongFangYu.exe" ascii fullword  
    // Add to the TTPs ruleset if any are missing

    $pdb = "C:\\Users\\Administrator\\Desktop\\KinndigitDll\\x64\\Release\\KinndigitDll.pdb" 
    
  condition:
    (pe.imphash() == "4e0b86deaf8a9726a4336a59cdcc1c95")
    or 
    ($pdb and 10 of ($antiav*)
    and pe.exports("Cronet_Buffer_Create")
    and pe.exports("Cronet_EngineParams_Create")
    and pe.exports("Cronet_HttpHeader_name_get")
    and pe.exports("Cronet_Executor_SetClientContext")
    and pe.exports("Cronet_Runnable_Run")
    and pe.exports("Cronet_TTNetParams_device_id_set")
    and pe.exports("Cronet_TTNetParams_domain_httpdns_set")
    and pe.exports("Cronet_UploadDataProvider_GetClientContext")
    and pe.exports("Cronet_UrlRequestCallback_CreateWith")
    and pe.exports("Cronet_UploadDataSink_OnReadSucceeded")
    and pe.exports("Cronet_UrlRequestParams_Create")
    and pe.exports("Cronet_UrlResponseInfo_http_status_text_get")
    and pe.exports("Cronet_WSClientConnectionParams_appToken_set")
    and pe.exports("Cronet_WSClient_StartConnection")
    and pe.exports("Cronet_WSClient_ConfigConnection")
    and pe.exports("Cronet_WSClientConnectionParams_network_set"))
    and filesize < 1MB
    
}
