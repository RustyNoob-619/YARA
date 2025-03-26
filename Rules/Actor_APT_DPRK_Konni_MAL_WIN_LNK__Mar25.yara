
import "lnk"

rule Actor_APT_DPRK_Konni_MAL_WIN_LNK__Mar25
{
      meta:
            rule_id = "ea09a42f-e4fb-4d99-8961-3a7a2baaf0ad"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects malicious LNK files attempting to execute JavaScript and PowerShell using mshta.exe with suspicious paramters"
            credit = "@adqewrsf for sharing malware sample and attribution"
            source = "https://x.com/adqewrsf/status/1899106332143480993"
            filehash = "811d221a1340e64aa1736d9d4e8f80820a5a02fab3d0c9e454f3ed35cd717b81"

      condition:
            lnk.local_base_path endswith "mshta.exe"
            and (lnk.cmd_line_args startswith "javascript"
            and lnk.cmd_line_args contains "-ep bypass"
            and lnk.cmd_line_args contains "-Encoding"
            and lnk.cmd_line_args contains ".Shell"
            and lnk.cmd_line_args contains ".ps1")
            //and lnk.relative_path contains "" 
            //ጆ倷仝椭沤歽ᇢ㧓ⓒ廎ᖝǗ๤⭽⢥᷈窾栬⚡导᫪涐ǿ⽺盧䁹ᗩਖ潃崌呴⇞糬䝓┛▵⍃ӹݭ┾䡲摎丂⿼柿㒑ֳ澷厢卯崊䈡癔㏇Ὸᖹ䶩䆰ᯆ෰ൟ䞽罎㊊ℷ㦀୫⹈ă
            and filesize < 25KB
}