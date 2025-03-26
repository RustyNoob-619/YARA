import "pe"

rule Actor_APT_CN_PlushDaemon_MAL_WIN_exe_downloader_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a executable acting as a downloader used by an unknown Chinese APT called PlushDaemon based on Code Sign Cert"
    source = "https://x.com/JAMESWT_MHT/status/1882423700412309927"
    filehash = "c44bb3cdee68d40920b9e36f80b9a3361520f17d6e470a56bd08f8c5b9054b10"
    credit = "@JAMESWT_MHT for sharing the malware sample and attribution"
    
  condition:
    pe.signatures[0].thumbprint == "9859aef2f2bfc51e3888e0658c2ea37bc86b4b33"
}


