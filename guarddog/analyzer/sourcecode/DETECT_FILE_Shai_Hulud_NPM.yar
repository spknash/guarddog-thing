rule DETECT_FILE_Shai_Hulud_NPM {
    meta:
        description = "Catches node.js Shai-Hulud"
        target_entity ="file"
    strings:
        $ioc_name1= "Shai-Hulud"
        $npm_code1 = "Buffer.from(Buffer.from(Buffer.from(r).toString(\"base64\")).toString(\"base64\")).toString"
        $npm_code2 = "makeRepo"
        $spread1 = "GitHubModule"
        $spread2 ="getCurrentToken"
        $github1 = "octokit"
        $github2 = "api.github.com"
        $github3 = "createForAuthenticatedUser"
        $hardvesting1 = "truffleHog"
    condition:
        all of ($ioc* , $npm*, $spread*, $github*, $hardvesting*)
}

