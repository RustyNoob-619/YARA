
import "pe"

rule MAL_WIN_DLL_Backdoor_PlugX_PEProperties_Mar25
{
      meta:
            rule_id = "e1faef9d-ed36-4838-a2aa-c5b2f36a6044"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects PlugX malware based on PE Properties"
            credit = "@Cyberteam008 for sharing Intel"
            source = "https://x.com/Cyberteam008/status/1901817451274539274"
            filehash = "080386f5dc89d42d7c1e684ca371b57ea4f7df85a6ea05acaa364247e3f8d390"

      condition:
            uint16(0) == 0x5a4d 
            and pe.imphash() == "1c360ac995f7e64035db01130cf698ef"
            and pe.exports("GetArphaCrashReport")
            and pe.exports("GetArphaUtils")
            and pe.exports("SetWindowLocalDump")
            and filesize < 25KB 

}