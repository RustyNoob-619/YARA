rule MAL_WIN_PE_Ransomware_SLug_RansomwareNoteStrings_JAN24
{
    meta:
        description = "Detects the ransomware note of the Slug ransomware group"
        author = "RustyNoob619"
        source = "https://twitter.com/Threatlabz/status/1747729463855751179"
        filehash = "Unknown"
    strings:
        $str1 = "05cb63af9848ae85a0016581a14a9848d516ed2f9fcb4f98a081363c48ee7f570b" 
        $str2 = "http://3ytm3d25hfzvbylkxiwyqmpvzys5of7l4pbosm7ol7czlkplgukjq6yd.onion/post/"
        $txt1 = "All your files were stolen by us" 
        $txt2 = "We stole a 1T file from this location"
        $txt3 = "Contact us for get price" 
        $txt4 = "You have 3 days to contact us for negotiation." 
        $txt5 = "If you don't contact within three days, we'll start leaking data" 
        $txt6 = "session download address: https://getsession.org/" 
        $txt7 = "EVP_EncryptFinal_ex" 
        $txt8 = "Our poison ID:" 
        $txt9 = "Note that this server is available via Tor browser only" 
        $txt10 = "Note that this server is available via Tor browser only"  
       
    condition:
        uint16(0) == 0x5A4D
        and any of ($str*) 
        and 7 of ($txt*) 
        
}




