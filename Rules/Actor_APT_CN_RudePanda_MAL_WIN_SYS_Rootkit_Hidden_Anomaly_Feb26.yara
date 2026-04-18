rule Actor_APT_CN_RudePanda_MAL_WIN_SYS_Rootkit_Hidden_Anomaly_Feb26
{
    meta:
        rule_id = "bd1913dd-f730-49f4-8e82-69d678995c46"
        date = "10-02-2026" 
        author = "Rustynoob619"
        description = "Detects rootkit derived from the open-source Hidden project used by Chinese APT RudePanda based on invalid code signing certificate"
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"

    condition:
        pe.version_info["ProductName"] == "Windows (R) Win 7 DDK driver"
        and pe.is_signed
        and not pe.signatures[0].valid_on(pe.timestamp)
}
