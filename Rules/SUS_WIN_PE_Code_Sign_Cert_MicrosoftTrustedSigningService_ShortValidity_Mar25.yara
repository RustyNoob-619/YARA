
import "pe"

rule SUS_WIN_PE_Code_Sign_Cert_MicrosoftTrustedSigningService_ShortValidity_Mar25
{
      meta:
            rule_id = "e9f1f3be-928e-4f08-bb24-41286c0940cb"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects suspicious files with signed using Microsoft Trusted Signing service with short lived validity period"
            credit = "@malwrhunterteam for identifying malware sample and sharing intel"
            source = "https://www.bleepingcomputer.com/news/security/microsoft-trust-signing-service-abused-to-code-sign-malware/"
            filehash1 = "414eeb3607eacbef7111b91a6695cb44b5256051ef4948a5d60df4cdc98946db"
            filehash2 = "708c39e1249e5d40a9a33017d3d3f7cf8f3e6054adb2c2415cd1e4b686e9373e"

      condition:
            uint16(0) == 0x5a4d 
            and pe.signatures[0].issuer contains "Microsoft ID Verified"
            and (pe.signatures[0].not_after - pe.signatures[0].not_before < 275000) //Calculates Validity Period around 3 Days 

}
