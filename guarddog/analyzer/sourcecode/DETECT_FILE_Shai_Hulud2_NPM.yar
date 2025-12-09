rule DETECT_FILE_Shai_Hulud2_NPM {
    meta:
        description = "Catches node.js Shai-Hulud2"

    strings:
        // --- High Confidence Indicators ---
        // The specific hardcoded description/name found in the createRepo function
        $str_hulud = "Sha1-Hulud: The Second Coming." ascii
        
        // Exfiltration targets: The script saves harvested data to these specific JSON files
        $dump_file1 = "actionsSecrets.json" ascii
        $dump_file2 = "cloud.json" ascii
        
        // --- Function Signatures ---
        // Unique Function Names and logic identified in the script
        $func_bun = "downloadAndSetupBun" ascii
        $func_save = "saveContents" ascii
        // The specific function signature for creating the repo with the malicious default
        $func_create_repo = "async [\"createRepo\"]" ascii 
        
        // --- Environment & Targets ---
        $env_actions = "process.env.GITHUB_ACTIONS" ascii
        $env_npm = "process.env.NPM_TOKEN" ascii
        
        // --- Tool & API Signatures ---
        $tool_truffle = ".truffler-cache" ascii
        $gcp_api = "secretmanager.googleapis.com" ascii
        $azure_res = "Microsoft.KeyVault" ascii

    condition:
        // 1. Context: Must be running in CI/CD or setup the Bun environment
        ($env_actions or $func_bun) and
        
        (
            // 2A. Strongest Indicator: The specific "Hulud" string
            $str_hulud
            
            or
            
            // 2B. Standard Detection: Exfiltration files + one other malicious capability
            ( 
                ($dump_file1 or $dump_file2) and 
                1 of ($func_save, $func_create_repo, $env_npm, $tool_truffle, $gcp_api, $azure_res) 
            )
        )
}
