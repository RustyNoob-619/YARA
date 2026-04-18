
rule Actor_APT_CN_Multiple_MAL_LNX_ELF_Backdoor_VoidLink_Strings_Jan26
{
    meta:
        rule_id = "1904ff5d-edb2-4116-a2c4-51957b89d517"
        date = "19-01-2026"
        author = "Rustynoob619"
        description = "Detects VoidLink Linux Backdoor used by Chinese Nexus Threat Actors based on strings"
        source = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        filehash = "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"

    strings:

        $unq = {4167656e742049443a2020204332205461726765743a203a} //Agent ID: C2 Target: :

        $hrtbt1 = "heartbeat_mode" ascii
        $hrtbt2 = "total_heartbeats" ascii
        $hrtbt3 = "heartbeat_jitter" ascii
        $hrtbt4 = "/api/v2/heartbeat" ascii fullword

        $beacon1 = "beacon_random_delay" ascii fullword
        $beacon2 = "beacon_net_accept" ascii fullword
        $beacon3 = "beacon_send_result" ascii fullword
        $beacon4 = "beacon_net_connect" ascii fullword
        $beacon5 = "beacon_sleep_ms" ascii fullword
        $beacon6 = "beacon_net_listen" ascii fullword
        $beacon7 = "beacon_geteuid" ascii fullword
        $beacon8 = "beacon_get_task_id" ascii fullword
        $beacon9 = "beacon_stealth_exec" ascii fullword
        $beacon10 = "beacon_base64_encode" ascii fullword

    condition:
        uint32be(0) == 0x7f454c46
        and (
            $unq or 
            (
                2 of ($hrtbt*)
                and 3 of ($beacon*)
            )
        )
        and filesize < 6MB

}
