rule DETECT_FILE_WhatsApp_Ransomware
{
    meta:
        description = "Detects suspicious function name and C2 for WhatsApp ransomware"
        author = "Andy Giron, Datadog"
        tags = "WhatsApp, Detection, Ranswomware, JavaScript"

    strings:
        $sus_function1 = "interaktiveMeta" ascii
        $sus_function2 = "getPairingCode" ascii

        $ip_check = "https://ipwho.is/?lang=id-ID" base64

        $c2_domain = "https://rest-api.vreden.my.id/cek?id=" base64
        $c2_domain2 = "https://rest-api.vreden.my.id?leads?id=" base64


    condition:
        1 of ($sus_function1, $sus_function2) and 1 of ($ip_check, $c2_domain, $c2_domain2)

}