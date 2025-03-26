
rule Actor_APT_RU_FIN7_MAL_WIN_Script_PY_Backdoor_Anubis_strings_Mar25
{
      meta:
            rule_id = "cf97a924-4558-4053-883f-eb44676c6d44"
            date = "12-03-2025"
            author = "RustyNoob619"
            description = "Detects Anubis loader used by FIN7 group based on observed strings"
            source = "https://x.com/MalGamy12/status/1899907026978849182"
            filehash = "e5255d5f476784fcef97f9c41b12665004c1b961e35ad445ed41e0d6dbbc4f8e"

      strings:
            $imprt1 = "import socket"
            $imprt2 = "import base64"
            $imprt3 = "import subprocess"
            $imprt4 = "import os"
            $imprt5 = "import threading"
            $imprt6 = "import hashlib"

            $str1 = "global C2_SERVERS" ascii fullword
            $str2 = "os.environ.get('COMPUTERNAME')"
            $str3 = "C2_SERVERS = servers"
            $str4 = "sock.connect(('8.8.8.8', 80))"
            $str5 = "base64.b64decode(encrypted_data)"
            $str6 = "AES.new(key_hash, AES.MODE_CBC, iv)"
            $str7 = "ports = C2_PORTS" ascii fullword
            $str8 = "pid_ip = str(os.getpid())" ascii fullword

            $func1 = "change_directory(decode_bytes(command[3:]))"
            $func2 = "download_file_or_dir(decode_bytes(command[3:]))"
            $func3 = "upload_file(command[3:])"
            $func4 = "get_environment_variable(command[4:])"
            $func5 = "configure_connection(command[4:], 0)"
            $func6 = "configure_connection(command[5:], 1)"
            $func7 = "execute_command(decode_bytes(command))"

            $ioc1 = "PROTOCOL_ID = 'A19N'" ascii fullword
            $ioc2 = "38.134.148.20" 
            $ioc3 = "5.252.177.249" 

      condition:
            (any of ($ioc*)
            or
            (3 of ($imprt*)
            and 3 of ($func*)
            and 3 of ($str*)))
            and filesize < 50KB
}



