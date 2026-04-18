
import "pe"

rule Actor_APT_RU_HydraSaiga_MAL_WIN_PE_RAT_JLORAT_Multiple_Mar26
{
    meta:
        rule_id = "5f2e8a11-3d4c-4b9a-9e12-c7f823a1b5d1"
        date = "11-03-2026"
        author = "Rustynoob619"
        description = "Detects JLORAT malware used by Russian APT HydraSaiga based on PE properties and strings"
        source = "https://www.vmray.com/hydra-saiga-covert-espionage-and-infiltration-of-critical-utilities/#elementor-toc__heading-anchor-3"
        filehash = "66962bb324a7c5a57ba0e9663bba156576a7e6aa5c6c1401c315b3d32f8d467d"

    strings:
        $mod1 = "src\\moduls\\get_info.rs" ascii 
        $mod2 = "src\\moduls\\reqw.rs" ascii 
        $mod3 = "src\\moduls\\sendfile.rs" ascii
        $mod4 = "src\\moduls\\screen.rs" ascii

        $func1 = "cmduploadscreen" ascii fullword
        $func2 = "cpu_usagecoresvendor_idbrandfrequency" ascii fullword
        $func3 = "SELECT * FROM MSAcpi_ThermalZoneTemperature" wide fullword

    condition:
        uint16(0) == 0x5a4d 
        and ((pe.imphash() == "02381668e12db939d5d3102a19166ef6" or pe.pdb_path == "jlo.pdb")
        or  (
            2 of ($mod*)
            and 2 of ($func*)
            ))
        and filesize < 2MB

}
