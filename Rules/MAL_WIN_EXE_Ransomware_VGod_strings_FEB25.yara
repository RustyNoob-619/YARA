rule MAL_WIN_EXE_Ransomware_VGod_strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Windows Targeting Ransomware called VGod based on observed strings"
    source = "https://www.cyfirma.com/research/vgod-ransomware/"
    filehash = "241c3b02a8e7d5a2b9c99574c28200df2a0f8c8bd7ba4d262e6aa8ed1211ba1f"
    
  strings:
    $wide1 = "powrprof.dll" wide fullword
    $wide2 = "bcryptprimitives.dll" wide fullword

    $str1 = "*godebug.value" fullword
    $str2 = "*godebugs.Info" fullword
    $str3 = "internal/godebug" fullword
    $str4 = "*godebug.setting" fullword

    $vgod1 = "Vgod-Ransomware" 
    $vgod2 = "-ldflags=\"-H=windowsgui -s -w -X 'Vgod-"
    $vgod3 = "Vgod-Ransomware/configuration.init" fullword
    $vgod4 = "Vgod-Ransomware/encryption.generateKey" fullword
    $vgod5 = "Vgod-Ransomware/encryption.generateNonce" fullword
    $vgod6 = "Vgod-Ransomware/encryption.EncryptFile" fullword
    $vgod7 = "Vgod-Ransomware/filewalker.EncryptDirectory" fullword
    $vgod8 = "/Vgod-Ransomware/Vgod-Ransomware/Encryptor/configuration/configuration.go" fullword

    $note1 = "[Wallpaper]::Set('-------------YOUR DATA IS ENCRYPTED --------------------"
    $note2 = "If you want to recover files write YOUR ID 25EC74S"
    $note3 = "send an email to our support vgod@ro.ru"
    $note4 = "Your personal DECRYPTION ID: 25EC74S"
    $note5 = "Unlocking your data is possible only with our software."
    $note6 = "All your files were encrypted and important data was copied to our storage"
    $note7 = "Contact Mail: vgod@ro.ru"
    $note8 = "In the header of the letter, indicate your ID and if you want attach 2-3 infected files to generate a private key and compile the decryptor"
    $note9 = "Files should not have important information and should not exceed the size of more than 5 MB"
    $note10 = "After receiving the ransom, we will send a recovery tool with detailed instructions within an hour and delete your files from our storages"
    $note11 = "--------- Attention ---------"
    $note12 = "Do not rename encrypted files."
    $note13 = "Do not try to decrypt your data using third party software, it may cause permanent data loss."
    $note14 = "If you refuse to pay the ransom, Important Data that contains personal confidential information or trade secrets will be sold to third parties interested in them."
    $note15 = "In any case, we will receive a payment, and your company will face problems in law enforcement and judicial areas."
    $note16 = "Don't be afraid to contact us. Remember, this is the only way to recover your data."
    
  condition:
    uint16(0) == 0x5a4d
    and 2 of ($vgod*)
    and 5 of ($note*)
    and any of ($str*)
    and any of ($wide*)
    and filesize < 3MB
}
