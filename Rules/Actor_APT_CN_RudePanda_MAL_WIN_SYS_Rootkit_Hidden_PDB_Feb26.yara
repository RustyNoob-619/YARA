rule Actor_APT_CN_RudePanda_MAL_WIN_SYS_Rootkit_Hidden_PDB_Feb26
{
    meta:
        rule_id = "9f209eec-6558-4a95-91bc-0318459f49c4"
        date = "09-02-2025" 
        author = "Rustynoob619"
        description = "Detects rootkit derived from the open-source Hidden project used by Chinese APT RudePanda based on PE PDB path"
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"

    condition:
        pe.pdb_path startswith "D:\\DriverSpace\\hidden"
        or pe.pdb_path endswith "Winkbj.pdb"
}
