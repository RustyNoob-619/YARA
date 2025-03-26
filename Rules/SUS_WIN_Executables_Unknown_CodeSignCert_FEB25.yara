import "pe"

rule SUS_WIN_Executables_Unknown_CodeSignCert_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects suspicious files signed with the Micro Hat Network Technology impersonating video chatting software"
    credit = "@SquiblydooBlog for sharing the malware sample hash and certificate info"
    source = "https://x.com/SquiblydooBlog/status/1890885261883519445"
    filehash = "cf84e79a40469e8b6e69975d0cb1d72fc5824930f4e5eefd2dce608f3604fbf8"
    
  condition:
    pe.signatures[0].thumbprint == "589d8a29339a343efe1dae8e44ede85b615be0fa" //Micro Hat Network Technology Co., Ltd.
    and filesize < 55MB
}


