rule HUNT_FILE_LOLBAS_Windows_Linux 
{
    meta:
      description = "Identify when a package uses a binary or script bundled in the OS (Live Of The Land) to leverage their capabilities. See more at https://lolbas-project.github.io"
    strings:

      $winbin1 = /\baddinutil\.exe\b.{30}/i
      $winbin2 = /\batbroker\.exe\b.{30}/i
      $winbin3 = /\bbitsadmin\.exe\b.{30}/i
      $winbin4 = /\bcertoc\.exe\b.{30}/i
      $winbin5 = /\bcmstp\.exe\b.{30}/i
      $winbin6 = /\bcustomshellhost\.exe\b.{30}/i
      $winbin7 = /\bextexport\.exe\b.{30}/i
      $winbin8 = /\bfsutil\.exe\b.{30}/i
      $winbin9 = /\bgpscript\.exe\b.{30}/i
      $winbin10 = /\biediagcmd\.exe\b.{30}/i
      $winbin11 = /\bieexec\.exe\b.{30}/i
      $winbin12 = /\binstallutil\.exe\b.{30}/i
      $winbin13 = /\bmavinject\.exe\b.{30}/i
      $winbin14 = /\bmmc\.exe\b.{30}/i
      $winbin15 = /\bmsconfig\.exe\b.{30}/i
      $winbin16 = /\bmsedge\.exe\b.{30}/i
      $winbin17 = /\bmshta\.exe\b.{30}/i
      $winbin18 = /\bmsiexec\.exe\b.{30}/i
      $winbin19 = /\bodbcconf\.exe\b.{30}/i
      $winbin20 = /\bofflinescannershell\.exe\b.{30}/i
      $winbin21 = /\bpcwrun\.exe\b.{30}/i
      $winbin22 = /\bpresentationhost\.exe\b.{30}/i
      $winbin23 = /\bprovlaunch\.exe\b.{30}/i
      $winbin24 = /\brasautou\.\b.{30}/i
      $winbin25 = /\bregister-cimprovider\.exe\b.{30}/i
      $winbin26 = /\bregsvcs\.exe\b.{30}/i
      $winbin27 = /\bregsvr32\.exe\b.{30}/i
      $winbin28 = /\brundll32\.exe\b.{30}/i
      $winbin29 = /\brunexehelper\.exe\b.{30}/i
      $winbin30 = /\brunonce\.exe\b.{30}/i
      $winbin31 = /\brunscripthelper\.exe\b.{30}/i
      $winbin32 = /\bscriptrunner\.exe\b.{30}/i
      $winbin33 = /\bsetres\.exe\b.{30}/i
      $winbin34 = /\bsettingsynchost\.exe\b.{30}/i
      $winbin35 = /\bstordiag\.exe\b.{30}/i
      $winbin36 = /\bsyncappvpublishingserver\.exe\b.{30}/i
      $winbin37 = /\bverclsid\.exe\b.{30}/i
      $winbin38 = /\bwab\.exe\b.{30}/i
      $winbin39 = /\bwmic\.exe\b.{30}/i
      $winbin40 = /\bworkfolders\.exe\b.{30}/i
      $winbin41 = /\bwuauclt\.exe\b.{30}/i
      $winbin42 = /\bxwizard\.exe\b.{30}/i
      $winbin43 = /\bmsedge_proxy\.exe\b.{30}/i
      $winbin44 = /\bmsedgewebview2\.exe\b.{30}/i
      $winbin45 = /\bacccheckconsole\.exe\b.{30}/i
      $winbin46 = /\bagentexecutor\.exe\b.{30}/i
      $winbin47 = /\bappcert\.exe\b.{30}/i
      $winbin48 = /\bappvlp\.exe\b.{30}/i
      $winbin49 = /\bbginfo\.exe\b.{30}/i
      $winbin50 = /\bcoregen\.exe\b.{30}/i
      $winbin51 = /\bdefaultpack\.exe\b.{30}/i
      $winbin52 = /\b\bdevinit\.exe\b.{30}/i
      $winbin53 = /\bdotnet\.exe\b.{30}/i
      $winbin54 = /\bmsdeploy\.exe\b.{30}/i
      $winbin55 = /\bsqlps\.exe\b.{30}/i
      $winbin56 = /\bsqltoolsps\.exe\b.{30}/i
      $winbin57 = /\bsquirrel\.exe\b.{30}/i
      $winbin58 = /\bteams\.exe\b.{30}/i
      $winbin59 = /\bupdate\.exe\b.{30}/i
      $winbin60 = /\bvsiisexelauncher\.exe\b.{30}/i
      $winbin61 = /\bvsls-agent\.exe\b.{30}/i
      $winbin63 = /\bwscript\.exe\b.{30}/i
      $winbin64 = /\bpowershell(\.exe)?\b.{30}/i

      $linbin1 = /\b((\/bin\/)*?bash|\/bin\/sh)\b -(i|c).{30}?/
      $linbin2 = /.{30}?\|(\s*?|\b)((\/bin\/)*?bash|\/bin\/sh)\b/
      $linbin3 = /\b(curl|wget)\b\s+?\S+?\|/
      $linbin4 = /\bbusybox\b.{30}/ 

      $script1 = /\bwinrm\.vbs\b.{30}/i

    condition:
        any of them
}
