rule HUNT_FILE_WhatsApp_Destructive_Behaviour
{
    meta:
        description = "Hunting WhatsApp ransomware module with destructive capabilities"
        author = "Andy Giron, Datadog"
        tags = "WhatsApp, hunting, ransomware, JavaScript"

    strings:
        $sus_function1 = "interaktiveMeta" ascii
        $sus_function2 = "requestPairingCode" ascii

        $rm_command = "rm -rf *" ascii
        $rm_command_base64 = "cm0gLXJmICo=" ascii

        $exec_rm_rf = /child_process\.exec\(\s*["']rm\s+-rf\s+\*["']\s*\)/ ascii

    condition:
        1 of ($sus_function1, $sus_function2) and 1 of ($rm_command, $rm_command_base64, $exec_rm_rf)
}
