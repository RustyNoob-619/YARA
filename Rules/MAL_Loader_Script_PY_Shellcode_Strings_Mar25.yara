
rule MAL_Loader_Script_PY_Shellcode_Strings_Mar25
{
      meta:
            rule_id = "b8744eb1-f463-494d-abcc-3693e55e78b2"
            author = "RustyNoob619"
            description = "Detects Python Scripts that can execute Shellcode based on observed strings"
            source = "https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2"
            filehash = "a5210aaa9eb51e866d9c2ef17f55c0526732eacb1a412b910394b6b51246b7da"

      strings:
            $pystr1 = "import sys" ascii
            $pystr2 = "import time" ascii
            $pystr3 = "import ctypes" ascii
            $pystr4 = "if __name__ == \"__main__\":" ascii fullword
            $pystr5 = "print" ascii
            $pystr6 = "return" ascii

            $str1 = "shellcode" nocase ascii
            $str2 = "payload" nocase ascii 
            $str3 = "bytecode" nocase ascii 
            $str4 = "execute" nocase ascii

            $funcs1 = "NtAllocateVirtualMemory" ascii
            $funcs2 = "NtWriteVirtualMemory" ascii
            $funcs3 = "PAGE_EXECUTE_READWRITE = 0x40" ascii
            $funcs4 = "GetCurrentProcess()" ascii

            $bytestr = "b\"\\x"
            
      condition:
            2 of ($pystr*)
            and 2 of ($str*)
            and any of ($funcs*)
            and #bytestr > 1000
            and filesize < 1MB

}