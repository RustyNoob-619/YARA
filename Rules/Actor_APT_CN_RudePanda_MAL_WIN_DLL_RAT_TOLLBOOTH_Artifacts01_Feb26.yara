rule Actor_APT_CN_RudePanda_MAL_WIN_DLL_RAT_TOLLBOOTH_Artifacts01_Feb26
{
    meta:
        rule_id = "2a513c09-2330-4b4d-85aa-c3f1f6d57f6a"
        date = "06-02-2026" 
        author = "Rustynoob619"
        description = "Detects malicious IIS modules which enable C2 comms used by Chinese APT RudePanda based on a unique artifacts"
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash = "2e84ea5cef8a9a8a60c7553b5878a349a037cffeab4c7f40da5d0873ede7ff72"

    strings:
        $challenge = "Tqpn0tGX550fVwt5D6g4CGWP6UDer6JXfWyNmCnCqTi" ascii
        // URL ACME Challenge 
        $path = "_FAB234CD3-09434-8898D-BFFC-4E23123DF2C" ascii 
        // C:\Windows\Temp\_FAB234CD3-09434-8898D-BFFC-4E23123DF2C\
    condition:
        any of them
        and filesize < 2MB
}
