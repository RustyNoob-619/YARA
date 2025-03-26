
rule MAL_LNX_ELF_Rootkit_Symbiote_strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Linux Rootkit known as Symbiote based on observed strings"
    source = "https://intezer.com/blog/research/new-linux-threat-symbiote/"
    filehash = "a0cd554c35dee3fed3d1607dc18debd1296faaee29b5bd77ff83ab6956a6f9d6"
    
  strings:
    $compile = "GCC: (GNU) 4.4.7 20120313 (Red Hat 4.4.7-17)" ascii fullword
    $str1 = "hidden_ports" ascii fullword
    $str2 = "hidden_address" ascii fullword
    $str3 = "download_script" ascii fullword
    $str4 = "get_machine_id" ascii fullword
    $str5 = "dns_txt_download" ascii fullword
    $str6 = "check_backdoor" ascii fullword
    $str7 = "keylogger" ascii fullword
    $str8 = "log_cmd_line" ascii fullword
    $str9 = "execute_dns_code" ascii fullword
    $str10 = "must_hide" ascii fullword
    $str11= "hide_proc_net_connection" ascii fullword
    $str12= "fake_trace_objects" ascii fullword
    $str13= "dns_broadcast_request" ascii fullword
    $str14= "get_dns_servers" ascii fullword
    
  condition:
    uint32be(0) == 0x7f454c46
    and $compile
    and 8 of ($str*)
    and filesize < 100KB
}

