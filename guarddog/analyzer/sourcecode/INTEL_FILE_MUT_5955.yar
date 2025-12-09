rule INTEL_FILE_MUT_5955
{
    meta:
        description = "Detects IoCs related to MUT-5955 campaignn"
        author = "Seba Obregoso, Datadog"
        tags = "ioc, correlation"
    strings:
        // 2nd stage host
        $stg_1 = "raw.githubusercontent.com/yellphonenaing199" ascii wide
        $stg_2 = "raw.githubusercontent.com/laravel-main" ascii wide

    condition:
        ( 
            any of ($stg_*)
        )
}
