import "math"

rule HUNT_FILE_Embedded_Secrets
{
    meta:
        description = "Detects known secrets in files"
        author = "Seba Obregoso, Datadog"
        credits = "https://docs.gitguardian.com/secrets-detection/detect/secrets-incidents"

    strings:
        $token_github1  = /\bgh[pousr]_[A-Za-z0-9_-]{36}\b/  
        $token_github2 = /\bgithub_pat_[A-Za-z0-9_-]{29}\b/  

        $token_aws = /\b((ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))\b/i
        $token_telegram = /\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b/

        $token_discord = /\b[m-z][a-z0-9_-]{23}\.[a-z0-9_-]{6}\.[a-z0-9_-]{27}\b/i
        $token_dockerhub = /dckr_pat_[a-z0-9-]{27}/i


    condition:
        math.entropy(@token_github1+4, !token_github1-4) > 4
        or
        math.entropy(@token_github2+11, !token_github2-11) > 4
        or
        math.entropy(@token_aws+4, !token_aws-4) > 4
        or
        math.entropy(@token_telegram+(!token_telegram-35), 35) > 4
        or
        math.entropy(@token_discord, 59) > 4
        or
        math.entropy(@token_dockerhub+9, !token_dockerhub-9) > 4
}


