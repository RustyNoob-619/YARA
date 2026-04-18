import "pe"

rule Actor_APT_CN_RudePanda_MAL_WIN_DLL_RAT_TOLLBOOTH_PDB_Feb26
{
    meta:
        rule_id = "8b38e255-b3f2-44a8-8a51-1d6d129dd809"
        date = "07-02-2026" 
        author = "Rustynoob619"
        description = "Detects malicious IIS modules which enable C2 comms used by Chinese APT RudePanda based on PDB path"
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash = "2e84ea5cef8a9a8a60c7553b5878a349a037cffeab4c7f40da5d0873ede7ff72"

    condition:
        pe.pdb_path startswith "D:\\IIS\\IISCPP-GM\\x64\\"
        or pe.pdb_path endswith "Dongtai.pdb"
}
