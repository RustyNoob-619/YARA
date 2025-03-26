//Note: Please configure author field in the snippet code for YARA
//Note: Not all fields are mandatory, please see Wiki for more info on Rule Naming Convention here: https://dev.azure.com/BWC-SECOPS/Cyber%20Threat%20Intelligence/_wiki/wikis/Cyber-Threat-Intelligence.wiki/71634/YARA-Rules-Naming-Convention
//Rule Name: Intention_ActorType_CountryCode_ActorName_OSType_Technology_MalwareType_MalwareName_OPTIONALArtifact_RuleDate

//Import Modules Here (Optional)

rule Actor_APT_CountryCode_ActorName_MAL_WIN_PE_Loader_MalwareName_OPTIONALArtifact_Mar25
{
    meta:
        rule_id = "a31dd4f1-e9b1-466b-a982-8aa2f613db66"
        date = "25-03-2025"
        author = "FirstName LastName"
        description = "Detects MalwareX used by ActorY based on "
        source = "Source_URL"
        filehash = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    strings:
        $str1 = ""
        $str2 = ""
        $str3 = ""

    condition:
        uint16(0) == 0x5a4d //Change for non-PE File Types
        and all of them
        and filesize < 100KB //Change as Required

}