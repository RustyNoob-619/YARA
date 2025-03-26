
rule Actor_APT_DPRK_Lazarus_MAL_JavaScript_strings_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects the JavaScript used by Lazarus in the infamous ByBit hack"
    credit = "@Now_on_VT for identifying and sharing the JavaScript"
    source1 = "https://x.com/Now_on_VT/status/1895942995230523815"
    source2 = "https://docsend.com/view/rmdi832mpt8u93s7/d/xc2rkprqm799pymq"
    filehash = "fbd5e3eb17ef62f2ecf7890108a3af9bcc229aaa51820a6e5ec08a56864d864d"

    //Possible Related Files ===>
    filehash1 = "52492ee33fee3adefc197137e9bf39c74dbd78c564e1040ccc72d43a98a36924" // Filename: 12test.js | Detection: 02/62 |  First Seen: 26-02-2025
    filehash2 = "b93eeeb2063e69101c78eb218991c82f9228191794a4d289ba1403b076c5eef2" // Filename: unknown   | Detection: 13/62 |  First Seen: 26-02-2025
    filehash3 = "c71195d65ab158d0bb6d1d7216053982cecc2913bbee1feb44ba41047b6578ce" // Filename: unknown   | Detection: 16/62 |  First Seen: 26-02-2025
    filehash4 = "30f04d3da89d6bc17c27bfce532d533f130a72e68238913cbc8ea993c682ea5e" // Filename: _app-4f0dcee809cce622.js | Detection: 00/62 |  First Seen: 27-02-2025
    filehash5 = "e807aeabe65205b1732a5a112226fc789ec0005e3725523d778e2088289f65f8" // Filename: safe js injection _app-52c9031bfa03da47.js  | Detection: 02/62 |  First Seen: 03-03-2025
    filehash6 = "de9544691d5e4a68a3639e091cbb37a80604a8968fce9864afc853c8b07a0910" // Filename: modified.js | Detection: 03/62 |  First Seen: 03-03-2025
    filehash7 = "e370b27201f3b780dbc2e1733c03e2625d0cab807704db2a318effb2e46cc065" // Filename: _app-52c9031bfa03da47_archive.org.js | Detection: 02/62 |  First Seen: 04-03-2025
    filehash8 = "e4ef787b37fd23be50fdc7dce29bf3f459016689706fda21382009f866cbb855" // Filename: unknown | Detection: 01/62 |  First Seen: 06-03-2025
    
  strings:
    $javascript = "text/javascript" ascii

    $id1 = "0x5aFE3855358E112B5647B952709E6165e1c1eEEe" ascii
    $id2 = "0xd16d9C09d13E9Cf77615771eADC5d51a1Ae92a26" ascii
    $id3 = "0x0a7CB434f96f65972D46A5c1A64a9654dC9959b2" ascii
    $id4 = "0xb161ccb96b9b817F9bDf0048F212725128779DE9" ascii
    $id5 = "0xfF501B324DC6d78dC9F983f140B9211c3EdB4dc7" ascii
    $id6 = "0x0a7CB434f96f65972D46A5c1A64a9654dC9959b2" ascii

    $str1 = "localhost:3000" ascii
    $str2 = "walletAddress" ascii
    $str3 = "ethereum" ascii
    $str4 = "payload" ascii
    
  condition:
    $javascript
    and any of ($id*)
    and any of ($str*)
    and filesize < 4MB
}

