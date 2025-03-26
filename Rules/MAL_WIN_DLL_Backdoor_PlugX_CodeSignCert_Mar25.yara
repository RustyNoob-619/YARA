
import "pe"

rule MAL_WIN_DLL_Backdoor_PlugX_CodeSignCert_Mar25
{
      meta:
            rule_id = "34f7a7d2-6fd2-48af-8212-d9b85cbd53e5"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects PlugX malware based on a Chinese Code Sign Certificate"
            credit = "@Cyberteam008 for sharing Intel"
            source = "https://x.com/Cyberteam008/status/1901817451274539274"
            filehash = "080386f5dc89d42d7c1e684ca371b57ea4f7df85a6ea05acaa364247e3f8d390"

      condition:
            uint16(0) == 0x5a4d 
            and pe.signatures[0].thumbprint == "bf92b5f71e11a67dfb2b0979a5aca47adccad1cf" //深圳市创想天空科技股份有限公司 Shenzhen Chuangxiang Sky Technology Co., Ltd.
            and filesize < 25KB 

}