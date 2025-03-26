import "pe"

rule Actor_APT_RU_UAC0099_WIN_EXE_Unknown_JAN25
{
  meta:
    author = "RustyNoob619"
    description = "Detects UAC-0099 malicious RAR file samples that were used in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash1 = "8cc89a917ed89a8407aa1e5caa4af585f26946124cf1764e3b178261a27177af"
    filehash2 = "16f809cd9fb1a06f07bb947ea8b6a27f66cfca0947e29666c34ae7b35b6e471b"
    filehash3 = "fbc4fbb3c2926300ee820ff7044f35231c2a1aeeb74d1f49a6caaec7736739c6"
  
  strings: 
    $rar1 = "__rar_" fullword
    $rar2 = "RarSFX" fullword
    $rar3 = "RarHtmlClassName" fullword
    $rar4 = "Software\\WinRAR SFX" fullword
    $cmd1 = "Delete" fullword
    $cmd2 = "Silent" fullword
    $cmd3 = "Overwrite" fullword
    $cmd4 = "ProgramFilesDir" fullword
    $cmd5 = "Presetup" fullword
    $rgsr = "Software\\Microsoft\\Windows\\CurrentVersion" fullword
    $wide1 = "GETPASSWORD1" wide fullword
    $wide2 = "Extracting %s" wide fullword
    $wide3 = "Skipping %s"wide fullword
    
  condition:
    pe.imphash() == "87b324a67e18fb2e1d12308b06fa8d4f"
    and pe.locale(0x0419) // Russian Language 
    and pe.timestamp == 1165139580 // Compiled Time Stamp  3rd Dec 2006, 09:53
    and any of ($rar*)
    and $rgsr
    and 2 of ($cmd*)
    and any of ($wide*)
    and filesize < 125KB
}

