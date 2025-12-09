rule INTEL_FILE_S1NGULARITY
  {
      meta:
          description = "Detects IoCs related to s1ngularity campaignn"
          author = "Appsec Research Team, sebastian.obregoso@datadoghq.com"

      strings:
          // Wallet-related keywords
          $wallet1 = /\bwallet\b/i
          $wallet2 = /\bkeystore\b/i
          $wallet3 = /\bmetamask\b/i
          $wallet4 = /\belectrum\b/i
          $wallet5 = /\bledger\b/i
          $wallet6 = /\btrezor\b/i
          $wallet7 = /\bexodus\b/i
          $wallet8 = /\bphantom\b/i
          $wallet9 = /\bsolflare\b/i
          $wallet10 = /\btrust\b/i
          $wallet11 = /\.ethereum\b/
          $wallet12 = /\bkeychain\b/i
          $wallet13 = /\bbinance\b/i
          $wallet14 = /\bcoinbase\b/i

          // Sensitive file patterns
          $sensitive1 = /\bid_rsa\b/
          $sensitive2 = /\.secret\b/
          $sensitive3 = /\*\.key\b/
          $sensitive4 = /\bkeyfile\b/
          $sensitive5 = /\bUTC--/
          $sensitive6 = /\bIndexedDB\b/
          $sensitive7 = /\bLocal Storage\b/
          $sensitive8 = /\.env\b/
          $sensitive9 = /\bsecrets\.json\b/
          $sensitive10 = /\bkeystore\.json\b/

          // System/filesystem keywords
          $system1 = /\/proc\b/
          $system2 = /\/sys\b/
          $system3 = /\/dev\b/
          $system4 = /\$HOME\b/

          // Path traversal indicators
          $traverse1 = /\bApplication Support\b/
          $traverse2 = /\.config\b/
          $traverse3 = /\.local\/share\b/
          $traverse4 = /\/etc\b/
          $traverse5 = /\/var\b/
          $traverse6 = /\/tmp\b/
          $traverse7 = /\bLibrary\/Application/

          // Command/permission keywords with boundaries
          $cmd1 = /\bsudo\b/
          $cmd2 = /\broot\b/

      condition:
          // Must have at least 5 wallet-related terms
          5 of ($wallet*) and
          // Must have at least 3 sensitive file patterns
          4 of ($sensitive*) and
          // Must have system scanning indicators
          2 of ($system*) and
          // Must have path traversal patterns
          3 of ($traverse*) and
          // Should have command/permission references
          1 of ($cmd*) 
  }
