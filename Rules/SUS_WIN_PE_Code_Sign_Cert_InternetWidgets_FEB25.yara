
import "pe"

rule SUS_WIN_PE_Code_Sign_Cert_InternetWidgets_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects PE Files with invalid Code Sign Certs that are signed using Internet Widgits Pty Ltd"
    credit = "https://cert.gov.ua/article/6282517"
    filehash = "4a302c0ed3c47231bc7c34cf2d41bc0ceb60d9c7b0023df015f75a58853f43d2"
    
  condition:
    pe.number_of_signatures == 1
    and pe.signatures[0].issuer contains "O=Internet Widgits Pty Ltd"
}


