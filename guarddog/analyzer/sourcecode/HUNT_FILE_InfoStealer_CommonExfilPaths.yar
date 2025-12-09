rule HUNT_FILE_InfoStealer_CommonExfilPaths
{
    meta:
      description = "Identifies when a packages is trying to access common files exfiltrated by stealers"
    strings:

      //browser data paths
      
      $browser_gral_loginpath = /\bLogin Data\b/i
      $browser_gral_leveldb = /\bleveldb\b/i
      // Opera
      $browser_opera = /\bOpera Software\b/i
      // Chrome
      $browser_chrome = /\bChrome\b/i
      // Edge 
      $browser_edge = /\bedge\b/i
      // Firefox
      $browser_ff = /\bFirefox\b/i
      $browser_ff_data = /\blogins.json\b/i


      // credential files
      $credentials_linux1= "/etc/passwd" ascii wide
      $credentials_linux2 = "/etc/shadow" ascii wide
      $credentials_linux3 = "/etc/sudoers" ascii wide
      $credentials_linux4 = "/etc/ssh/sshd_config" ascii wide
      $credentials_linux5 = "/etc/ssh/ssh_config" ascii wide
      $credentials_linux6 = "/etc/ssh/ssh_host_rsa_key" ascii wide
      $credentials_aws1 = ".aws/credentials" ascii wide
      $credentials_aws2 = ".aws/config" ascii wide
      $credentials_azure1 = ".azure/credentials" ascii wide
      $credentials_azure2 = ".azure/config" ascii wide
      $credentials_gcp1 = ".gcp/credentials" ascii wide
      $credentials_gcp2 = ".gcp/config" ascii wide
      $credentials_oci1 = ".oci/credentials" ascii wide
      $credentials_oci2 = ".oci/config" ascii wide
      $credentials_oci3 = ".oci/oci_api_key.pem" ascii wide
      $credentials_mac1 = "/Library/Keychains/login.keychain"
      $credentials_mac2 = "/Library/Keychains/System.keychain"


      // crypto wallets

      // atomic
      $wallets_atomic = /\batomic\b/i
      $wallets_atomic_data = /\bleveldb\b/i
      // exodus
      $wallets_exodus = /\bexodus\.wallet\b/i
      // metamask 
      $wallets_ext_metamask1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii nocase wide
      $wallets_ext_metamask2= "ejbalbakoplchlghecdalmeeeajnimhm" ascii nocase wide
      $wallets_ext_bnb = "fhbohimaelbohpjbbldcngcnapndodjp" ascii nocase wide
      $wallets_ext__coinbase = "hnfanknocfeofbddgcijnmhnfnkdnaad"
      $wallets_ext_tronlink = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
      $wallets_ext_phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
      $wallets_ext__coin98 = "aeachknmefphepccionboohckonoeemg"
      $wallets_ext__cryptocom = "hifafgmccdpekplomjjkcfgodnhcellj"
      $wallets_ext_kia = "jblndlipeogpafnldhgmapagcccfchpi"
      $wallets_ext_rabby = "acmacodkjbdgmoleebolmdjonilkdbch"
      $wallets_ext_argentx = "dlcobpjiigpikoobohmabehhmhfoodbb"
      $wallets_ext_exodus = "aholpfdialjgjfhomihkjbmgjidlcdno"

      // coinbase
      $wallets_coinbase = /\bCoinbaseWallet\b/i


      // targeted applications

      // Telegram
      $app_telegram = /\bTelegram Desktop\b/i ascii nocase wide
      $app_telegram_data = /\btdata\b/i ascii nocase wide
      // Signal
      $app_signal = /\bSignal\b/i ascii nocase wide
      $app_signal_data1 = /\bdb\.sqlite\b/i ascii nocase wide
      $app_signal_data2 = /\bconfig\.json\b/i ascii nocase wide
      // Steam
      $app_steam = /\bSteam\b/i
      $app_steam_data = /\bconfig.vdf\b/i
      // Discord
      $app_discord = /\bdiscord\b/i
      $app_discord_data = /\bleveldb\b/i
      // Filezilla
      $app_filezilla = /\bFileZilla\b/i
      $app_filezilla_data1 = /\brecentservers\.xml\b/i
      $app_filezilla_data2 = /\bsitemanager.xml\b/i
      // Thunderbird
      $app_thunder = /\bThunderbird\b/i
      $app_thunder_data = /\bkey3\.db\b/i
      // VNC
      $app_vnc = /\bRealVNC\b/i
      $app_vnc_data = /\bOptions\.vnc\b/i
      // WinSCP
      $app_winscp = /\bWinSCP\.ini\b/i
      // KeePass
      $app_keepass = /\bKeePass\.config\.xml\b/i
      // PuTTY
      $app_putty = /\bPuTTY\b/i
      $app_putty_data = /\bsessions\b/i

    condition:
      ($browser_chrome and 1 of ($browser_gral*)) or
      ($browser_opera and 1 of ($browser_gral*)) or
      ($browser_edge and 1 of ($browser_gral*)) or
      ($browser_ff and 1 of ($browser_gral*,$browser_ff_data)) or
      any of ($credentials*) or
      all of ($wallets_atomic*) or
      all of ($wallets_exodus*) or
      all of ($wallets_ext_*) or
      all of ($wallets_coinbase*) or
      all of ($app_telegram*) or
      ($app_signal and 1 of ($app_signal_data*)) or
      all of ($app_steam*) or
      all of ($app_discord*) or
      ($app_filezilla and 1 of ($app_filezilla_data*)) or
      all of ($app_thunder*) or
      all of ($app_vnc*) or
      $app_winscp or
      $app_keepass or
      all of ($app_putty*)

}
