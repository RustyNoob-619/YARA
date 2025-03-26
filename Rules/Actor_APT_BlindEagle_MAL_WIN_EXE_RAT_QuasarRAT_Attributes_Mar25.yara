
import "pe"

rule Actor_APT_BlindEagle_MAL_WIN_EXE_RAT_QuasarRAT_Attributes_Mar25
{
      meta:
            rule_id = "bf23b50f-4d44-4df6-a370-4f469ee35c61"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects QuasarRAT malware potentially linked to APT Blind Eagle based on PDB path and encryption keys"
            credit = "@johnk3r for sharing the malware sample and attribution"
            source = "https://x.com/johnk3r/status/1903565136314462331"
            filehash = "72157acbb76515e2eb904d29afbf86a81a780525b177b0940d2ce26ad89df62f"

      strings:
            $aes_key = "1WvgEMPjdwfqIMeM9MclyQ==" wide fullword
            $hmac_key = "NcFtjbDOcsw7Evd3coMC0y4koy/SRZGydhNmno81ZOWOvdfg7sv0Cj5ad2ROUfX4QMscAIjYJdjrrs41+qcQwg==" wide fullword 
            $hostkey = "5e:78:65:69:f9:9b:b0:a3:27:20:1a:76:d4:1c:f9:fa" wide

      condition:
            (pe.pdb_path contains "R.A.T Source 5 NUCLEAR RAT"
            or any of them)
            and filesize < 500KB

}