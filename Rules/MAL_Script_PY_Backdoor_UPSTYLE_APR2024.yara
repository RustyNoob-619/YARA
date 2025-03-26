rule MAL_Script_PY_Backdoor_UPSTYLE_APR2024 {
    meta:
        Description = "Detects the UPSTYLE Python Backdoor used in the Zero-Day exploitation (CVE-2024-3400) against Palo Alto Devices"
        Author = "RustyNoob619"
        Credits = "@1ZRR4H for sharing the malware sample on Malware Bazaar"
        Reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
        File_Hash = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"

    strings:
        $python = "python3.6" 

        $lateimport = "import glob" fullword

        $base641 = "import base64" base64 
        $base642 = "import os,subprocess,time,sys" base64
        $base643 = "def start_process():" base64
        $base644 = "functioncode =" base64
        $base645 = "ZGVmIF9fbWFpbigpOg" base64 // def __main(): Base64 encoded twice
        
        
    condition:
        $python
        and 5 of ($base64*)
        and $lateimport in (filesize-75..filesize)
        and filesize < 100KB
        
 }
