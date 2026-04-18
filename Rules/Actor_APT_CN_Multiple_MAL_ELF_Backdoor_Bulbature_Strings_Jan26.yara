rule Actor_APT_CN_Multiple_MAL_ELF_Backdoor_Bulbature_Strings_Jan26
{
    meta:
        rule_id = "e6725a7d-5a96-458f-a95b-7acf808477c3"
        date = "17-01-2026"
        author = "Rustynoob619"
        description = "Detects Bulbature backdoor used by Chinese APTs such as UAT-7290 and APT31 based on strings"
        source = "https://blog.sekoia.io/bulbature-beneath-the-waves-of-gobrat/"
        filehash = "41e189a5b68f305ab6251a06475b76777bda0d035ea06cd569306ed5c98bdc98"

    strings:
        $GCC1 = "GCC: (Ubuntu 12.3.0-1ubuntu1" ascii fullword
        $GCC2 = "22.04) 12.3.0" ascii fullword
        $GCC3 = "GCC: (LEDE GCC 5.4.0 r3556-46e29bd) 5.4.0" ascii fullword

        $place1 = "%d.%d.%d.%d" ascii fullword
        $place2 = "%I:%M:%S %p" ascii fullword
        $place3 = "%a %b %e %T %Y" ascii fullword

        $crypto1 = "-----BEGIN RSA PRIVATE KEY-----" ascii fullword
        $crypto2 = "-----BEGIN CERTIFICATE-----" ascii fullword
        $crypto3 = "-----BEGIN EC PRIVATE KEY-----" ascii fullword
        $crypto4 = "-----BEGIN RSA PUBLIC KEY-----" ascii fullword
        $crypto5 = "-----BEGIN PRIVATE KEY-----" ascii fullword

        $id1 = "id-at-dnQualifier" ascii fullword
        $id2 = "id-at-uniqueIdentifier" ascii fullword
        $id3 = "id-kp-serverAuth" ascii fullword
        $id4 = "id-at-pseudonym" ascii fullword
        $id5 = "id-at-title" ascii fullword

        $path1 = "/dev/pts/%d" ascii
        $path2 = "/etc/resolv.conf" ascii
        $path3 = "/bin/sh" ascii
        $path4 = "/usr/share/zoneinfo/" ascii

    condition:
        uint32be(0) == 0x7f454c46
        and all of ($GCC*)
        and 2 of ($place*)
        and 3 of ($crypto*)
        and 3 of ($path*)
        and 4 of ($id*)
        and filesize < 2MB

}

