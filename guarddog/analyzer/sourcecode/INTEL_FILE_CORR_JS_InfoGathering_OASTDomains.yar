rule INTEL_FILE_CORR_InfoGathering
{
    meta:
        description = "Identifies info-gathering and exfiltration attempts and system profiling"
        author = "Andy Giron, Datadog"
        tags = "intelligence, correlation, JavaScript, OAST"

    strings:
        $url1 = "dnipqouebm-psl.cn.oast-cn.byted-dast.com" ascii
        $url2 = "oqvignkp58-psl.i18n.oast-row.byted-dast.com" ascii
        $url3 = "sbfwstspuutiarcjzptfenn9u0dsxhjlu.oast.fun" ascii

        $domain1 = /[a-z0-9\-]+byted-dast.com/
        $domain2 = /[a-z0-9\-]+oast.fun/

        $param_pattern = "/realtime_p/pypi/" ascii

        $platform = "platform.node()" ascii
        $username = "getpass.getuser()" ascii
        $current_path = "os.getcwd()" ascii

    condition:
        (
            $domain1 or $domain2 or $url1 or $url2 or $url3 or $param_pattern
        ) and
        (
            $platform or $username or $current_path
        )
}
