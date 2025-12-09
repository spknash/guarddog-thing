rule INTEL_FILE_MUT_4831
{
    meta:
        description = "Detects IoCs related to MUT-4831 campaign"
        author = "Ian Kretz, Datadog"
        tags = "ioc, correlation"
    strings:
        // C2 domains
        $c2_1 = "https://upload.bullethost.cloud/download" ascii wide

        // Files
        $f_1 = "bLtjqzUn.zip" ascii wide
        $f_2 = "kijczfFw.zip" ascii wide
        $f_3 = "YxWNShrn.zip" ascii wide
        $f_4 = "gZpHoOMJ.zip" ascii wide
        $f_5 = "AaUFdnXQ.zip" ascii wide
        $f_6 = "oBmqjIeU.zip" ascii wide
        $f_7 = "bridle.exe" ascii wide
        $f_8 = "oqyelxyaa.exe" ascii wide

        // Postinstall scripts
        $pi_1 = "postinstall\": \"node src/dependencies.js" ascii wide
        $pi_2 = "postinstall\": \"node src/extract.js" ascii wide

    condition:
        (
            any of them
        )
}
