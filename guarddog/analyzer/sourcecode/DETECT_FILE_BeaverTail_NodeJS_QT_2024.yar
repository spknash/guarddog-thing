rule DETECT_FILE_BeaverTail_NodeJS_QT_2024 {
    meta:
        description = "Catches node.js and Qt variants of BeaverTail"
        author = "matt.muir@datadoghq.com"
        target_entity ="file"
    strings:
        // sample hunts for these browser extensions IDs
        $extension_id_1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"
        $extension_id_2 = "ejbalbakoplchlghecdalmeeeajnimhm"
        $extension_id_3 = "fhbohimaelbohpjbbldcngcnapndodjp"
        $extension_id_4 = "hnfanknocfeofbddgcijnmhnfnkdnaad"
        $extension_id_5 = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
        $extension_id_6 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
        $extension_id_7 = "aeachknmefphepccionboohckonoeemg"
        $extension_id_8 = "hifafgmccdpekplomjjkcfgodnhcellj"
        $extension_id_9 = "jblndlipeogpafnldhgmapagcccfchpi"
        $extension_id_10 = "acmacodkjbdgmoleebolmdjonilkdbch"
        $extension_id_11 = "dlcobpjiigpikoobohmabehhmhfoodbb"
        $extension_id_12 = "aholpfdialjgjfhomihkjbmgjidlcdno"

        // sample enumerates these browser user data paths
        $browser_paths_1 = "/AppData/Local/Google/Chrome/User Data"
        $browser_paths_2 = "/.config/google-chrome"
        $browser_paths_3 = "/Library/Application Support/Google/Chrome"
        $browser_paths_4 = "/AppData/Local/BraveSoftware/Brave-Browser/User Data"
        $browser_paths_5 = "/.config/BraveSoftware/Brave-Browser"
        $browser_paths_6 = "/Library/Application Support/BraveSoftware/Brave-Browser"
        $browser_paths_7 = "/AppData/Roaming/Opera Software/Opera Stable"
        $browser_paths_8 = "/.config/opera"
        $browser_paths_9 = "/Library/Application Support/com.operasoftware.opera"
        $browser_paths_10 = "Profile "
        $browser_paths_11 = "Default"
        $browser_paths_12 = "/Login Data"
        $browser_paths_13 = "/Local Extension Settings/"
        $browser_paths_14 = "/Local State"

        // C2 HTTP endpoints
        $http_endpoint_1 = "/uploads"
        $http_endpoint_2 = "/pdown"
        $http_endpoint_3 = "/client/99"

        // Log statements
        $log_statement_1 = "Download Client Success!"
        $log_statement_2 = "Download Python Success!"
        $log_statement_3 = "Upload LDB Finshed!!!"

        // sample interacts with macOS Keychain
        $mac_keychain_1 = "logkc_db"
        $mac_keychain_2 = "/Library/Keychains/login.keychain-db"

        // misc strings
        $str1 = "/.pyp/python.exe"
        $str2 = "upLDBFinished"
        $str3 = "pDownFinished"
        $str4 = "clientDownFinished"
    condition:
        6 of ($extension_id_*) and
        7 of ($browser_paths_*) and
        any of ($http_endpoint_*) and
        any of ($log_statement_*) and
        any of ($mac_keychain_*) and
        any of ($str*)
}

