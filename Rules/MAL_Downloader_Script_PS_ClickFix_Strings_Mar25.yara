
rule MAL_Downloader_Script_PS_ClickFix_Strings_Mar25
{
      meta:
            rule_id = "1fd6e5b9-f969-470d-ba75-e0c894086a96"
            author = "RustyNoob619"
            description = "Detects a Dropper/Downloader PowerShell Script used to execute Python script as part of ClickFix Infection"
            source = "https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2"
            filehash = "989f58c86343704f143c0d9e16893fad98843b932740b113e8b2f8376859d2dd"

      strings:
            $sndbx1 = "$isSandbox" ascii
            $sndbx2 = "cmd.exe /c net group \"domain computers\" /domain" ascii

            $pwrshll1 = "Get-ItemProperty" ascii
            $pwrshll2 = "Select-Object" ascii
            $pwrshll3 = "Where-Object" ascii
            $pwrshll4 = "Remove-Item" ascii
            $pwrshll5 = "Start-Sleep" ascii
            $pwrshll6 = "Set-ItemProperty" ascii

            $py1 = "pythonw" ascii
            $py2 = "www.python.org" ascii

            $rgstr1 = "HKCU:\\Software\\Microsoft" ascii
            $rgstr2 = "zr_" ascii

            $url1 = "import urllib" ascii
            $url2 = "https://" ascii
      
      condition:
            any of ($pwrshll*)
            and any of ($sndbx*)
            and any of ($py*)
            and all of ($url*)
            and all of ($rgstr*)
            and filesize < 10KB

}