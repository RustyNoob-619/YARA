import "time"

rule TTP_Tampered_Time_Stamp_JAN25 {
    meta:
        author = "RustyNoob619"
        description = "Detects PE files that have time stamps from the future"

    condition:
        pe.timestamp > time.now() //Feedback requires edit to remove potential SYS files as FPs
}


