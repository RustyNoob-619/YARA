
rule Actor_UAC0184_TTP_PowerShell_Obfuscation_strings_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a PowerShell Obfuscation technique used by threat cluster UAC-0184"
    source1 = "https://www.linkedin.com/posts/idan-tarab-7a9057200_uac0184-cyberattack-threatresearch-ugcPost-7302710505834467329-E0gI/?utm_source=share&utm_medium=member_android&rcm=ACoAAAVx-dgBDxaF1I3qYrWwuOhh-o-hjwEOE04"
    source1 = "https://www.morphisec.com/blog/unveiling-uac-0184-the-remcos-rat-steganography-saga/"
    filehash1 = "9ed972e4bd181c65ca053dcf0220f4101a51387517b4c0c5f7ce6cf49895de27"
    filehash2 = "eb8da26034035f08946acb6fc127e3b2db884a024a61aea99397c46aedc70145"
    
  strings:
    $pwrshll1 = "WindowsPowerShell" ascii wide fullword
    $pwrshll2 = "powershell.exe" ascii wide fullword 
    $symbol = "''" wide

    $obsurl1 = {00 68 (00 74 | 00 74 00 27 00 27 | 00 27 00 27 00 74) (00 74 | 00 74 00 27 00 27 | 00 27 00 27 00 74) (00 70 | 00 70 00 27 00 27 | 00 27 00 27 00 70) (00 3a | 00 3a 00 27 00 27 | 00 27 00 27 00 3a) (00 2f | 00 2f 00 27 00 27 | 00 27 00 27 00 2f) (00 2f | 00 2f 00 27 00 27 | 00 27 00 27 00 2f)} // http with ''
    $obsurl2 = {00 68 00 27 00 27 00 74 00 27 00 27 00 74 00 70 00 3a 00 27 00 27 00 2f 00 2f 00 27 00 27 00} //h''t''tp:''//''
    
    $obszip1 = {00 7a (00 69 | 00 27 00 27 00 69| 00 69 00 27 00 27 ) 00 70} //zip with ''
    $obszip2 = {00 7a 00 27 00 27 00 69 00 27 00 27 00 70 00} //z''i''p
    $obszip3 = {00 7a 00 69 00 27 00 27 00 70} //zi''p
    

    $obsgcm1 = {00 67 (00 63 | 00 27 00 27 00 63| 00 63 00 27 00 27 ) 00 6d} //gcm g''
    $obsgcm2 = {00 67 00 27 00 27 00 63 00 27 00 27 00 6d 00} //g''c''m
    $obsgcm3 = {00 67 00 63 00 27 00 27 00 6d 00} //gc''m

    $obsstrt1 = {00 73 (00 74 | 00 74 00 27 00 27 | 00 27 00 27 00 74) (00 61 | 00 61 00 27 00 27 | 00 27 00 27 00 61) (00 72 | 00 72 00 27 00 27 | 00 27 00 27 00 72) 00 74} //start with ''
    $obsstrt2 = {00 73 00 74 00 27 00 27 00 61 00 72 00 27 00 27 00 74} //st''ar''t
    $obsstrt3 = {00 73 00 74 00 27 00 27 00 61 00 27 00 27 00 72 00 74} //st''a''rt
    
    $str1 = "-WindowStyle" ascii wide
    $str2 = "hidden" ascii wide
    $str3 = "-Path" ascii wide
    $str4 = "-uri" ascii wide
    $str5 = "echo" ascii wide
    $str6 = "-PathType" ascii wide
    $str7 = "Expand-Archive" ascii wide
    $str8 = "-DestinationPath" ascii wide

  condition:
    any of ($pwrshll*)
    and #symbol > 30
    and 3 of ($str*)
    and 3 of ($obs*)
    and filesize < 100KB
}

//rule TTP_UAC_0184_ObfuscatedPowerShell {
//    meta:
//        hash = "9ed972e4bd181c65ca053dcf0220f4101a51387517b4c0c5f7ce6cf49895de27"
//        reference = "https://www.linkedin.com/posts/idan-tarab-7a9057200_uac0184-cyberattack-threatresearch-ugcPost-7302710505834467329-E0gI/?utm_source=share&utm_medium=member_android&rcm=ACoAAAVx-dgBDxaF1I3qYrWwuOhh-o-hjwEOE04"
//    strings:
//        $reg1 = /g('')*c('')*m('')*\\s[^']*'/i
//        $reg2 = /i\**w\**r\**[^]*/i
//        $reg3 = /(\s)?[0-9]{1,3}''.[0-9]{1,3}''.[0-9]{1,3}''.[0-9]{1,3}''(\s)?/
//        $reg4 = /-uri h('')*t('')*t('')*p('')*[^']*'/
//   condition:
//        all of $reg*
//}