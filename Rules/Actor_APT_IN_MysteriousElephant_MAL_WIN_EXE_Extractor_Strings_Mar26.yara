rule Actor_APT_IN_MysteriousElephant_MAL_WIN_EXE_Extractor_Strings_Mar26
{
    meta:
        rule_id = "8bac50d3-c96c-43ed-9b4f-6a2cf85d32a6"
        date = "24-03-2026"
        author = "Rustynoob619"
        description = "Detects Storm Extractor tool used by Indian APT Mysterious Elephant based on multiple properties"
        source = "https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/"
        filehash = "b39a39ff30d1d92314e351d8573d533814ccfedb6240d71fcb60f8367778389b"

    strings:
        $dotnet1 = "_CorExeMain" ascii fullword
        $dotnet2 = "mscoree.dll" ascii fullword

        $str1 = "ToBase64String" ascii fullword
        $str2 = "CryptoStream" ascii fullword

        $folder1 = "Downloads" wide fullword 
        $folder2 = "Documents" wide fullword
      
        $path1 = "C:\\ProgramData\\file_hash.txt" wide fullword
        $path2 = "C:\\ProgramData\\USOShared" wide fullword

        $wide1 = "pdf,docx,txt,jpg,png,zip,rar,pptx,doc,xls,xlsx,pst,ost,ppt,axx,inp,apk" wide
        $wide2 = "WhatsAppDesktop" wide 
        
    condition:
        uint16(0) == 0x5a4d
        and any of ($dotnet*)
        and all of ($str*)
        and all of ($folder*)
        and any of ($path*)
        and any of ($wide*)
        and filesize < 500KB

}
