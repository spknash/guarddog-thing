rule INTEL_FILE_Validator_Stealer_Indicators 
{
    meta:
        description = "known malicious domains and IPs attributed to Validator Stealer"
        author = "Andy Giron, Datadog"
        tags = "correlation, telegram-utils, grammy-utils"

    strings:
        $domain1 = "validator.icu" fullword nocase
        $domain2 = "cryptowhiz.net" fullword nocase
        $domain3 = "cryptoshiny.com" fullword nocase
        $domain4 = "pumpportals.com" fullword nocase
        $domain5 = "miletadev.com" fullword nocase
        $domain6 = "netragon.online" fullword nocase
        $domain7 = "launchpadx.pro" fullword nocase
        $domain8 = "wpepe.io" fullword nocase

        $ip1 = "95.216.37.86" fullword nocase
        $ip2 = "88.99.95.50" fullword nocase
        $ip3 = "195.201.81.120" fullword nocase
        $ip4 = "95.216.73.81" fullword nocase
        $ip5 = "84.32.84.32" fullword nocase
        $ip6 = "195.201.175.103" fullword nocase
        $ip7 = "94.130.34.108" fullword nocase
        $ip8 = "95.216.37.139" fullword nocase

        $user = "jordanjack1022" fullword nocase
        $user2 = "jordanjack1022@gmail.com" fullword nocase
        $user3 = "cryptoshiny1224@gmail.com" fullword nocase
        // $user4 = "silverlight"
        $user5 = "nightfury98760@gmail.com" fullword nocase

        $key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINBLXXGbUFlXZPjt6NFyt00VVHQJOAJU9CdKCL7OVbjP"
        $key2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0eFAxoea78gXpURdj7ufXx1LVEOoVKawxRnwAghXHwGUw4V0V3n194wyUOUGrloGLn5IZ2JGdWLu0b0VHVG1asapkd8l7lKgvPf5yfjrccDs1qpvID8mLzsTfNMwZQlS+sw+bgJx/74f6i3t6QYuBsB0xPuLx8EXok96N1yTjPVXWq3Czwt5pmG+xZFddZLYDMpf8GonwdfTx7BACcapueoSMmOHZX3w1mjOHsT1b41gmHIEGsyo67KN4FLOkWOZIjc7Qge4iRjL24smRZPFJ4FeQjUo7rvEUxTNFb8yTgMGA+o2H3Uqvm/vXYiOTD87UUvy/3hOkoZzJLyFsV1bfyq6/8IQETqMguLzwIT8S1TlJHBUf1sXYh/5dHI4cMXz/r/eK4VlqQvZEE1TJIyAi0ZKnup6j2R3SdO/EIuZeanHyH/u6CboWZ8OcVzDY9EBVxmuYmkCIFiauNHlDNCJwm4CFM1oYinAQsh92zCUmZKQAgnH499mRPR1PWH4m1Ok="
        $key3 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1rk7yDl57W6LIkJVz9UukX+GUhNAhdABbekaTem5pRW/ERZJOFXoXtNytb0zgBaT0FUuQ//ptK1Ru6IFsBZrtUzrndvILbC9VcMl4vuUvnqPVe/FEaeOCAnJR8P3WM1Sqk3FA8rvzP4on3sgeeLfyHBqh+QcEBTpSroYfGdPaQPAWvYRfCxlE2kgrNrOuUyGYq8xriAAb7WbLhVbCDIB5tukYQeYLXXuStteNYWZTzCD+qW7QYKQmbiRLqS4Gp3s0J3O9ACjb2Ov79nzyFTPfVEjlGanq9/DE/91bOkoaUUp9qunUFw6orpQC2IqKTeuhjsQkJ0bF23i7cglz1xrqJbgZv8DfpmbdyNkZs7wMN3ksJcoVd8PyvUh6CqKvAjrRqB3JZZYy6R0NUXjHL8VOpU42nPZaRyO987ydpz5AfxsIeSUYSLFwRGOYiI/T83EjN/pLxVYZmrNs+xJg8R9z+Iohimic2wugx7bLme/4XO9EeQR3vRVuxG+T2NrjrFk="

        // strings from variant 1: node-telegram-utils, node-telegram-bot-sdk, 
        // node-telegram-sdk
        $variant1_str1 = "https.get('https://ipinfo.io/ip'"
        $variant1_str2 = "function addBotId()"
        $variant1_str3 = "username = os.userInfo().username"
        $variant1_str4 = "authorizedKeysPath = path.join(sshDir,'authorized_keys')"
        $variant1_str5 = "if(!fileContent.includes(fullPublicKey)){fs.appendFileSync(authorizedKeysPath"
        $variant1_str6 = "Public key written to new authorized_keys file."
        $variant1_str7 = "+ ipAddress + '&name=' + username" // fragment of C2 request

        // strings from variant 2: grammy-utils, telegramclient-sdk, grammyjs-sdk,
        // telegram-util, grammyjs-utils
        $variant2_str1 = "const username = os.userInfo().username;"
        $variant2_str2 = "ipAddress = await getBotId()"
        $variant2_str3 = "Public key written to new authorized_keys file."
        $variant2_str4 = "fs.mkdirSync(sshDir, { mode: 0o700 }"
        $variant2_str5 = "const publicKey = "
        $variant2_str6 = "fs.existsSync(authorizedKeysPath)"
        $variant2_str7 = "ip=${ipAddress}&name=${username}"  // C2 URL params

    condition:
        any of ($domain*) or any of ($ip*) or any of ($user*) or any of ($key*) or (5 of ($variant1*)) or (5 of ($variant2*))
}
