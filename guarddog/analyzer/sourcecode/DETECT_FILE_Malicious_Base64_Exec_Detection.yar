rule DETECT_FILE_Malicious_Base64_Exec_Detection
{
    meta:
        description = "Detects use of exec and invoke with base64-encoded strings"
        author = "Andy Giron, Datadog"
        tags = "malware, detection, base64, obfuscation, httpsmovements v1.3.5"

    strings:
        $exec_base64 = /exec\(\s*"[A-Za-z0-9\+\/=]+"/
        
        $invoke_base64 = /invoke\(\s*"[A-Za-z0-9\+\/=]+"/

        $decode_utf8 = /\.decode\(\s*['"]utf-8['"]\s*\)/

        $decode_no_arg = /\.decode\(\s*\)/

    condition:
        (any of ($exec_base64, $invoke_base64)) and (any of ($decode_utf8, $decode_no_arg))
}
