rule INTEL_FILE_BeaverTail_Obfuscated_JS
{
    meta:
        description = "Detects BeaverTail malware used by DPRK threat actor Tenacious Pungsan in npm packages"
        author = "Andy Giron, Datadog"
        tags = "BeaverTail, DPRK, JavaScript, supply_chain"

    strings:
        $long_encoded_line = /[A-Za-z0-9+\/]{100,}/ ascii
        $eval_decode = /eval\(atob\(/ ascii

        $package_passports = "passports-js" ascii
        $package_bcrypts = "bcrypts-js" ascii
        $package_blockscan = "blockscan-api" ascii
        $chrome_dir = "Brave Software/Brave-Browser/Default" ascii
        $login_keychain = "com.apple.keychain" ascii

        $c2_server = "95.164.17.24" ascii
        $campaign_id_726 = "/client/3/726" ascii
        $campaign_id_525 = "/client/3/525" ascii

    condition:
        1 of ($package_*, $chrome_dir, $login_keychain) and 1 of ($long_encoded_line, $eval_decode) and 1 of ($c2_server, $campaign_id_726, $campaign_id_525)
}
