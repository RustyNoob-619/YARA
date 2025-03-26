rule Actor_CN_UNC5337_Script_Dropper_PHASEJAM_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects PHASEJAM, a dropper bash shell script that was used in the Ivanti Zero-Day exploitation"
    credit = "@Now_on_VT for notification of the malware sample"
    source = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
    filehash = "63b386027ee268f1921f7b605a36cd91d08921f86ea5c6dd10f1808d25114b9d"
    
  strings:
    $bckdr1 = "create backdoor 1" ascii fullword
    $bckdr2 = "create backdoor 2" ascii fullword

    $jam1 = "/jam/getComponent.cgi.bak" ascii
    $jam2 = "/home/webserver/htdocs/dana-na/jam/getComponent.cgi" ascii
    
    $bs641 = "MIME::Base64" base64
    $bs642 = "HTTP_QUERY" base64
    $bs643 = "HTTP_CODE" base64
    $bs644 = "processUpgradeDisplay()" base64
    $bs645 = "/home/bin/dsrunpriv" base64
    $bs646 = "/bin/dschown" base64
    $bs647 = "/root/home/VERSION" base64

    $pth1 = "/home/perl/DSUpgrade.pm.bak" ascii
    $pth2 = "/home/perl/DSUpgrade.pm" ascii

    $cmd1 = "echo" ascii
    $cmd2 = "sed" ascii
    $cmd3 = "grep" ascii
    $cmd4 = "chmod 777" ascii

    $str1 = "pkill cgi-server" ascii fullword
    $str2 = "processUpgradeDisplay" ascii

    $dbg1 = "remotedebug" ascii fullword
    $dbg2 = "/home/bin/remotedebug"
    $dbg3 = "/home/bin/remotedebug.bak"
    
  condition:
    any of ($bckdr*)
    and any of ($jam*)
    and any of ($pth*)
    and any of ($str*)
    and any of ($dbg*)
    and 4 of ($bs64*)
    and 3 of ($cmd*)
    
    and filesize < 25KB
}




