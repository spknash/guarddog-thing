rule INTEL_FILE_MUT_688 {
    meta:
        description = "Detects IoCs related to MUT-688 campaignn"
        author = "Appsec Research Team, eslam@datadoghq.com"
    strings:
        // Device ID
        $mid = "83d8d5a0e009d6787f3f535a" ascii wide
        //root ID
        $room = "6456352068782141" ascii wide

        // C2 Domains
        $c2_1 = "support.datatabletemplate.shop/directory/room" ascii wide
        $c2_2 = "writeup.live/update" ascii wide
        $c2_3 = "safeup.store/update" ascii wide
        $c2_4 = "upload-test.xyz/test" ascii wide
        $c2_5 = "bots.auto/update.online/test" ascii wide
        $c2_6 = "update-assist.org/test" ascii wide

        
        // Common patterns
        
        $js_base64 = "Buffer.from(\"cmV0dXJuIGFzeW5jICgpID0+IHsNCiAgICB0cnkgew0KICAgICAgICBjb25zdCBmcyA9IGF3YWl0IGltcG9ydCgnZnMnKTsNCiAgICAgICAgY29uc3Qgb3MgPSBhd2FpdCBpbXBvcnQoJ29zJyk7DQogICAgICAgIGNvbnN0IHsgZXhlYywgc3Bhd24gfSA9IGF3YWl0IGltcG9ydCgnY2hpbGRfcHJvY2VzcycpOw" ascii
        $js_func_1 = /seedFunction\s*=\s*new\s*Function\s*\([^)]*\)/ nocase
        $js_func_2 = "seedFunction()()" ascii nocase
        

    condition:
        ( 
            any of ($mid, $room) or
            (any of ($c2_*)) or
            (all of ($js_func_*)) or
            $js_base64
        )
}
