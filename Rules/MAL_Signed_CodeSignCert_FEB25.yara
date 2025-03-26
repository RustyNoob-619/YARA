rule MAL_Signed_CodeSignCert_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects NetsupportRAT and Arechclient2 samples signed by MANH THAO NGUYEN COMPANY LIMITED"
    credit = "FirstName LastName @TwitterHandle for sharing the malware samples"
    source = "https://bazaar.abuse.ch/browse/tag/MANH%20THAO%20NGUYEN%20COMPANY%20LIMITED/"
    filehash = "0c913179c3a8db195a886f020f56d577e859220c9478190e630b6602f60478d6"
  
  condition:
    pe.signatures[0].thumbprint == "6e0ad87d848646c96ca254dcfafeea020cbd4a1c" //MANH THAO NGUYEN COMPANY LIMITED
}

//Code Sign Cert Info:
//Valid From
//12/05/2024
//Valid To
//12/06/2025