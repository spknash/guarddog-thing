rule HUNT_FILE_Telegram_Bot_API_Commands
{
    meta:
        description = "Detects Telegram bot API commands"
        author = "Andy Giron, Datadog"
        tags = "telegram, api_commands, network"

    strings:
        $telegram_api_base = "https://api.telegram.org/bot" ascii
        $token_pattern = /\b[0-9]{7,10}:[A-Za-z0-9_-]{35}\b/  


        $command_getMe = "/getMe" ascii
        $command_getUpdates = "/getUpdates" ascii
        $command_getWebhookInfo = "/getWebhookInfo" ascii
        $command_deleteWebhook = "/deleteWebhook" ascii
        $command_drop_updates = "/deleteWebhook?drop_pending_updates=true" ascii

        $identifier_chat_id = "chat_id" ascii

    condition:
        1 of ($telegram_api_base, $token_pattern) and 1 of ($command_getMe, $command_getUpdates, $command_getWebhookInfo, $command_deleteWebhook, $command_drop_updates, $identifier_chat_id)
}


