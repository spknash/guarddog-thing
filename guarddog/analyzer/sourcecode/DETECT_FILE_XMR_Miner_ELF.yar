rule DETECT_FILE_XMR_Miner_ELF
{
    meta:
        description = "Detects ELF binaries associated with XMR mining activity"
        author = "Andy Giron, Datadog"
        tags = "XMR, miner, cryptocurrency, elf"
    strings:
        $miner_string1 = "stratum+tcp://" ascii
        $miner_string2 = "xmr.pool" ascii
        $miner_string3 = "monerohash.com" ascii
        $miner_string4 = /[a-zA-Z0-9]{95,}/  
    condition:
        uint32(0)==0x464c457f and 2 of ($miner_string*) 
}

