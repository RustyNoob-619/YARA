rule Actor_APT_DPRK_Unknown_MAL_Indicators_Strings_Feb26
{
      meta:
            rule_id = "10982aed-1c45-4864-a6ff-ffd19f38912d"
            date = "23-02-2026"
            author = "Rustynoob619"
            description = "Detects cluster of DPRK Nexus malware based on known artifacts"

      strings:
            $XOR1 = {32 5b 67 57 66 47 6a 3b 3c 3a 2d 39 33 5a 5e 43}
            $XOR2 = {6d 36 3a 74 54 68 5e 44 29 63 42 7a 3f 4e 4d 5d}
            $XOR3 = {63 41 5d 32 21 2b 33 37 76 2c 2d 73 7a 65 55 7d}
            $XOR4 = {54 68 5a 47 2b 30 6a 66 58 45 36 56 41 47 4f 4a}
            $XOR5 = {34 23 75 4c 65 56 4d 5b 33 6c 45 53 4c 47 41}
            $XOR6 = {39 4b 79 41 53 74 2b 37 44 30 6d 6a 50 48 46 59}
            $XOR7 = {54 68 5a 47 2b 30 6a 66 58 45 36 56 41 47 4f 4a}

            $tron1 = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii wide
            $tron2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii wide
            $tron3 = "TLmj13VL4p6NQ7jpxz8d9uYY6FUKCYatS" ascii wide

            $aptos1 = "be037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e" ascii wide
            $aptos2 = "3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3" ascii wide
            $aptos3 = "3414a658f13b652f24301e986f9e0079ef506992472c1d5224180340d8105837" ascii wide

            $bsc1 = "f46c86c886bbf9915f4841a8c27b38c519fe3ce54ba69c98d233d0ffc94d19fc" ascii wide
            $bsc2 = "d33f78662df123adf2a178628980b605a0026c0d8c4f4e87e43e724cda258fef" ascii wide
            $bsc3 = "a8cdabea3616a6d43e0893322112f9dca05b7d2f88fd1b7370c33c79076216ff" ascii wide

            $telegram = "7870147428:AAGbYG_eYkiAziCKRmkiQF-" ascii wide

            $marker = "*C250617A*" ascii wide

            $obfs1 = "_$af402041" ascii wide
            $obfs2 = "_$af813180" ascii wide
            $obfs3 = "_$_2d00[]" ascii wide

      condition:
            any of them
}
