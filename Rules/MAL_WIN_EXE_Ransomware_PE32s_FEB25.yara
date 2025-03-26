import "pe"

rule MAL_WIN_EXE_Ransomware_PE32s_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Windows Targeting Ransomware known as pe32s"
    credit = "@PaduckLee for sharing the malware sample"
    source = "https://x.com/PaduckLee/status/1890635598454563191"
    filehash = "c6ddc9c2852eddf30f945a50183e28d38f6b9b1bbad01aac52e9d9539482a433"
    
  strings:
    $str1 = "README.txt" ascii fullword
    $str2 = "Lock file presentpe32lockfile.lockUltraFast Compeleted" ascii fullword
    $str3 = "What drive do you want to encrypt:" ascii fullword
    $str4 = "Pricing:" ascii fullword
    $str5 = "Single servers: $700 - $7000" ascii fullword
    $str6 = "Companies and Multiple Computers: $10,000 to more than 2btc and more, depending on the data size and company."
    $str7 = "Mail : bettercallarmin1@gmail.com" ascii fullword
    $str8 = "PE32-KEYNo key on aes_chain" ascii fullword
    $str9 = "pe32lockfile.lock" ascii fullword
    $str10 = "chat_idUSER: Armin" ascii fullword

    $note1 = "Greetings"
    $note2 = "Your files have been encrypted, and your sensitive data has been exfiltrated."
    $note3 = "To unlock your files and prevent public disclosure of data a payment is required."
    $note4 = "Please note that cost for file decryption and avoiding data publification is separate."
    $note5 = "To establish trust and provide assurance, we offer the following:"
    $note6 = "A decryption test for a few small files (less than 1-2 MB) that do not contain valuable information."
    $note7 = "Screenshot of other customers who have paid and received decryption. For larger payments you may also request information for individuals from your country"
    $note8 = "who have successfully decrypted their data as proof."
    
    $wide1 = "\\Device\\Afd\\Mio" wide fullword
    $wide2 = "\\\\?\\\\\\?\\UNC\\" wide fullword
    
  condition:
    ((pe.imphash() == "9448b7f2dfefd2cd32e6d9b27e1ca042" or pe.pdb_path == "encv2.pdb")
    or 
    (5 of ($note*)
    and 4 of ($str*)
    and any of ($wide*)))
    and filesize < 5MB
}

