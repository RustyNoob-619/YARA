rule Actor_APT_IR_APT35_MAL_Artifacts_02_Feb26
{
    meta:
        rule_id = "96755782-7799-4507-be83-1601e6bd1d6d"
        date = "04-02-2026"
        author = "Rustynoob619"
        description = "Detects potential Iranian APT35 (Charming Kitten) related malware  based on unique embedded strings"
        source = "https://github.com/KittenBusters/CharmingKitten/tree/main/Episode%203/BellaCiao"
        filehash = "470bf7706ab118bd308350e6ceafb5cbbfae15c89d11d31f9b6ad0e518514d61"
    
    strings:
        $lang1 = "NOPQR-STUVWXYZabcdefghijklmnopqrstu=vwxyz0123456789" ascii wide
        $lang2 = "Qk3\\afcPbYJTGywSv=0Egdx62X-NRVz" ascii wide
        $lang3 = "Uq7os1ijFMuLOetCl98K5hBDn4.prWAHmIZ" ascii wide

        $capcha = "JgAAgP7jP38JwxmUgBgbuF8P_Nmlh2EEBhzhIQOBCEgGdAeWqYD_xNXr3UBFH35AAgACOJqOmhmdA2KVQwAEsGJYhhEAAAAAAAAAAA" ascii wide
        $param = "\"Accept-Language\" : \"whoami\"," ascii wide
        $msg = "print('good bye commonder" ascii wide
        $goodboy = "i am good boy" wide fullword
        
    condition:
        any of them
        and filesize < 100KB

}
