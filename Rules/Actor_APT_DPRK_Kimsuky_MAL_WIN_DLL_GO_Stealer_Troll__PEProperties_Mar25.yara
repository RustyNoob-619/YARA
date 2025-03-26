
import "pe"

rule Actor_APT_DPRK_Kimsuky_MAL_WIN_DLL_GO_Stealer_Troll__PEProperties_Mar25
{
    meta:
        rule_id = "6257184d-703d-4f6b-9be1-e58f64919425"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects a Signed Stealer DLL written in GO known as Troll used by DPRK APT Kimsuky"
        source = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        filehash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"
    
    strings:
        $go = "golang.dll"

    condition:
        $go
        and pe.signatures[0].thumbprint == "30db7d678045e44d882d7652ba6aaa6593c02328" //D2innovation Co.,LTD
        and pe.imphash() == "6d86f70f74801f37e2db25edd59c53e9" //Needs Validation
        and filesize < 11MB

}