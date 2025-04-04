
import "pe"

rule SUS_WIN_EXE_Unknown_FakePutty_PEProperties_Mar25
{
    meta:
        rule_id = "21aa4193-70bd-4b0a-a6f4-c7c16ed594a0"
        date = "25-03-2025"
        author = "Bridewell CTI"
        description = "Detects a Windows Reverse Shell impersonating Putty Client with malware config properties of Meterpreter"
        source = "https://www.cisa.gov/sites/default/files/2025-03/aa25-071a-stopransomware-medusa-ransomware.pdf"
        filehash = "baa980ae253101066ae7e551a354116454e8697ff2154a907c9885770cdae4ae"

    condition:
        ((pe.imphash() == "69573714e11441683ea863c40a1c0d54")
        or 
        (pe.number_of_signatures == 0
        and pe.version_info["ProductName"] == "PuTTY suite"
        and pe.version_info["FileDescription"] == "SSH, Telnet, Rlogin, and SUPDUP client"
        and pe.version_info["LegalCopyright"] endswith "1997-2022 Simon Tatham."))
        and filesize < 3MB
}

//Malware Config: Meterpreter
//C2 IP: 185[.]254.]37[.]173
//C2 Port: 8443
//C2 URL:hxxps://185.254.37[.]173[:]8443/rqRiqrLmTT3KxsvErrdzOAHrWjroo32RNmWosMMtsBaUlOagrmU5XQPYqtDN8GinawtNpAGfUUXwAJQMs/
