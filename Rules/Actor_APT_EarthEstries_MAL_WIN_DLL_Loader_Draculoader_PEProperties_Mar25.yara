
import "pe"

rule Actor_APT_EarthEstries_MAL_WIN_DLL_Loader_Draculoader_PEProperties_Mar25 
{
    meta:
        rule_id = "8e6549fc-e3c9-47f6-858a-7943377754b6"
        date = "23-03-2025"
        author = "RustyNoob619"
        description = "Detects a Loader used to execute the HemiGate Backdoor used by APT Earth Estries"
        credit = "@Now_on_VT for notification of the malware sample"
        source = "https://www.trendmicro.com/en_gb/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html"
        filehash1 = "a8dd0ca6151000de33335f48a832d24412de13ce05ea6f279bf4aaaa2e5aaecb"
        filehash2 = "eeb3d2e87d343b2acf6bc8e4e4122d76a9ad200ae52340c61e537a80666705ed"

    condition: 
        (pe.imphash() == "c619772c353f1b1a5915bab7545e93af" or pe.imphash() == "dab27e70f769257f4fc266114ae8aa9e")
        and 
        ((pe.exports("DumpWriteA")
        and pe.exports("DumpWriteW")
        and pe.exports("TraceWriteA")
        and pe.exports("TraceWriteW"))
        or
        pe.exports("K7ScanUI_RunScanner"))
        and filesize < 250KB 
}

