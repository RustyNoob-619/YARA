
rule TTP_Microsoft_Dev_Tunnels_strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects suspicious files using Microsoft Dev Tunnels for C2 communication"
    credit = "@xme for sharing the malware samples and explaining the technique used"
    source = "https://isc.sans.edu/diary/31724Njrat"
    filehash1 = "0b0c8fb59db1c32ed9d435abb0f7e2e8c3365325d59b1f3feeba62b7dc0143ee"
    filehash2 = "9ea760274186449a60f2b663f535c4fbbefa74bc050df07614150e8321eccdb7"
    
  strings:
    $str1 = "devtunnels.ms" ascii
    $str2 = "devtunnels.ms" wide
    
  condition:
    any of them
    and filesize < 100KB //Feel free to modify the filesie to match on wider samples
}


