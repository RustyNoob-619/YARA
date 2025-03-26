
rule Actor_APT_SeashellBlizzard_HTML_ASPX_Webshell_LocalOlive_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a webshell called Local Olive that is written in ASPX that was used by Seashell Blizzard in a multi-year global access campaign"
    source = "https://www.microsoft.com/en-us/security/blog/2025/02/12/the-badpilot-campaign-seashell-blizzard-subgroup-conducts-multiyear-global-access-operation/"
    filehash = "c7379b2472b71ea0a2ba63cb7178769d27b27e1d00785bfadac0ae311cc88d8b"
  
  strings:
    $asp = "<asp:"

    $sus1 = "ProcessWindowStyle.Hidden"
    $sus2 = "RedirectStandardOutput = true"
    $sus3 = "UseShellExecute"
    $sus4 = "CreateNoWindow = true"

    $rule = "New-NetFirewallRule -DisplayName \"+a+\" -Direction inbound -Profile Any -Action Allow -LocalPort 250 -Protocol TCP"

    $pwrshll = "FileName=@\"Powe\" + @\"rShell\""

    $http1 = "HttpContext.Current.Request.Url.AbsoluteUri"
    $http2 = "Response.AddHeader(\"Co\"+\"ntent-Le\"+\"ngth\", file.Length.ToString())"
    
  condition:
    #asp >15
    and 2 of ($sus*)
    and any of ($http*)
    and $rule
    and $pwrshll
    and filesize < 25KB
}
