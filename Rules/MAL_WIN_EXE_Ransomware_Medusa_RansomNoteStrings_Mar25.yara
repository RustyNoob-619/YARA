
rule MAL_WIN_EXE_Ransomware_Medusa_RansomNoteStrings_Mar25
{
    meta:
        rule_id = "17febe5b-6d71-4176-9fc9-c94851a75287"
        date = "25-03-2025"
        author = "Bridewell CTI"
        description = "Detects Windows Targeting Ransomware called Medusa based on the ransomware note strings"
        source = "https://github.com/ThreatLabz/ransomware_notes/blob/main/medusa/!!!READ_ME_MEDUSA!!!.txt"
        filehash = "Unknown"
 
    strings:
        $art1 = "$$\\      $$\\ $$$$$$$$\\ $$$$$$$\\  $$\\   $$\\  $$$$$$\\   $$$$$$\\" ascii wide
        $art2 = "$$$\\    $$$ |$$  _____|$$  __$$\\ $$ |  $$ |$$  __$$\\ $$  __$$\\" ascii wide
        $art2 = "$$$$\\  $$$$ |$$ |      $$ |  $$ |$$ |  $$ |$$ /  \\__|$$ /  $$ |" ascii wide
        $art2 = "$$\\$$\\$$ $$ |$$$$$\\    $$ |  $$ |$$ |  $$ |\\$$$$$$\\  $$$$$$$$ |" ascii wide
        $art2 = "$$ \\$$$  $$ |$$  __|   $$ |  $$ |$$ |  $$ | \\____$$\\ $$  __$$ |" ascii wide
        $art2 = "$$ |\\$  /$$ |$$ |      $$ |  $$ |$$ |  $$ |$$\\   $$ |$$ |  $$ |" ascii wide
        $art2 = "$$ | \\_/ $$ |$$$$$$$$\\ $$$$$$$  |\\$$$$$$  |\\$$$$$$  |$$ |  $$ |" ascii wide
        $art2 = "\\__|     \\__|\\________|\\_______/  \\______/  \\______/ \\__|  \\__|" ascii wide
        
        $note1 = "We have ENCRYPTED some your files." ascii wide
        $note2 = "While you are reading this message, it means you found your files and data has been ENCRYPTED by world's strongest ransomware." ascii wide
        $note3 = "MEDUSA DECRYPTOR and DECRYPTION KEYs, Data deletion, Keep silent in media." ascii wide
        $note4 = "This MEDUSA DECRYPTOR will restore your entire network, This will take less than 1 business day." ascii wide
        $note5 = "If you're not in main chile office, inform your supervisors and stay calm!" ascii wide

        $id1 = "http://medusaxko7jxtrojdkxo66j7ck4q5tgktf7uqsqyfry4ebnxlcbkccyd.onion/"ascii wide
        $id2 = "http://medusakxxtp3uo7vusntvubnytaph4d3amxivbggl3hnhpk2nmus34yd.onion/[snip]" ascii wide
        $id3 = "4AE245548F2A225882951FB14E9BF87EE01A0C10AE159B99D1EA62620D91A372205227254A9F" ascii wide
 
    condition:
        uint16(0) == 0x5a4d 
        and filesize < 3MB
        and (
            ((all of ($art*)) or (3 of ($note*)) or (any of ($id*)))
        )
}

