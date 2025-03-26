import "pe"

rule MAL_WIN_DLL_Infostealer_AmateraStealer_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects an information Stealer known as Amatera Stealer based on PE properties. The malware attribution is of low confidence"
    source = "https://x.com/solostalking/status/1867864181514600826"
    credit = "@solostalking for sharing the C2 IP address hosting the malware"
    filehash = "269bff650fc3be9402b628a224f54fc3f532c30c66cf8183f8249f056f579015"

  condition:
    (pe.version_info["ProductVersion"] == "131.120.0123.5678" or pe.imphash() == "eb678f492d288189c126ada2150b0234")
    and pe.number_of_exports > 100
    and filesize < 5MB
    
}
