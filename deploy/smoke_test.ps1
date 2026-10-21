# smoke_test.ps1 - quick end-to-end check of the VisaGlobal flow (blocks 1-5).
# Works in Windows PowerShell 5.1 and PowerShell 7. ASCII only on purpose.
#
# Example:
#   .\smoke_test.ps1 -VisaToken "<BLS_BOT_TOKEN_VISAGLOBAL>"
#   .\smoke_test.ps1 -VisaToken "<token>" -ClientTokenA "<alice token>" -ClientTokenB "<bob token>"
#
# Default run sends only SAFE codes: nothing here puts an IP into a long cooldown.
# Every lease is released at the end (normal release = 60 s cooldown for that IP).
# -IncludeIpBan adds CF_BLOCK twice with different profiles: this DOES cool the IP down (confirmed block).
param(
    [string]$BaseUrl = "https://bls-proxy.shikinn.com",
    [Parameter(Mandatory = $true)][string]$VisaToken,   # token of purpose visaglobal (or client A token)
    [string]$ClientTokenA = "",                          # optional: per-client token, owner of the lease
    [string]$ClientTokenB = "",                          # optional: other client, must get 403 on A's lease
    [string]$AccountId = "smoke-test-001",
    [switch]$IncludeIpBan
)
$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")
$script:Fails = 0
$script:Results = @()

function Call([string]$Method, [string]$Path, [string]$Token, $Body = $null) {
    $h = @{ "X-Bot-Token" = $Token }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 0; $text = ""
    try {
        if ($Body -ne $null) {
            $json = $Body | ConvertTo-Json -Depth 8 -Compress
            $r = Invoke-WebRequest -Uri ($BaseUrl + $Path) -Method $Method -Headers $h `
                 -ContentType "application/json" -Body $json -UseBasicParsing -TimeoutSec 30
        } else {
            $r = Invoke-WebRequest -Uri ($BaseUrl + $Path) -Method $Method -Headers $h -UseBasicParsing -TimeoutSec 30
        }
        $status = [int]$r.StatusCode; $text = $r.Content
    } catch {
        $resp = $_.Exception.Response
        if ($resp -ne $null) {
            $status = [int]$resp.StatusCode
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $text = $_.ErrorDetails.Message          # PowerShell 7
            } else {
                try {
                    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())   # Windows PowerShell 5.1
                    $text = $sr.ReadToEnd()
                } catch { $text = $_.Exception.Message }
            }
        } else { $status = -1; $text = $_.Exception.Message }
    }
    $sw.Stop()
    $obj = $null
    try { $obj = $text | ConvertFrom-Json } catch { }
    return [pscustomobject]@{ Status = $status; Ms = [int]$sw.ElapsedMilliseconds; Text = $text; Json = $obj }
}

function Show([string]$Title, $R) {
    Write-Host ""
    Write-Host ("== {0}  [HTTP {1}, {2} ms]" -f $Title, $R.Status, $R.Ms) -ForegroundColor Cyan
    Write-Host $R.Text
}

function Check([string]$Name, [bool]$Ok, [string]$Got) {
    $mark = if ($Ok) { "PASS" } else { "FAIL"; $script:Fails++ }
    $color = if ($Ok) { "Green" } else { "Red" }
    Write-Host ("[{0}] {1}  (got: {2})" -f $mark, $Name, $Got) -ForegroundColor $color
    $script:Results += [pscustomobject]@{ Test = $Name; Result = $mark; Got = $Got }
}

$tokA = if ($ClientTokenA) { $ClientTokenA } else { $VisaToken }

# 1. health
$r = Call "GET" "/health" $tokA
Show "GET /health" $r
Check "health answers 200" ($r.Status -eq 200) "$($r.Status)"

# 2. acquire
$acq = Call "POST" "/acquire" $tokA @{ account_id = $AccountId; count = 1; ttl_seconds = 120; purpose = "visaglobal"; client_id = "smoke-test" }
Show "POST /acquire" $acq
if ($acq.Status -ne 200) { Check "acquire answers 200" $false "$($acq.Status)"; exit 1 }
$lease = $null
if ($acq.Json -and $acq.Json.leases -and $acq.Json.leases.Count -gt 0) { $lease = $acq.Json.leases[0].lease_id }
if (-not $lease) {
    $wait = if ($acq.Json) { $acq.Json.retry_after_seconds } else { "?" }
    Write-Host "Pool is empty right now (retry_after_seconds=$wait). That is normal: run again later." -ForegroundColor Yellow
    exit 0
}
Check "acquire gave a lease" $true $lease

# 3. info event (log only)
$r = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "info"; phase = "navigate"; detail = @{ step = 1; http_status = 200; latency_ms = 840 } }
Show "report info / phase navigate" $r
Check "info accepted" ($r.Status -eq 200) "$($r.Status)"

# 4. cycle_ok
$r = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "cycle_ok"; phase = "dashboard"; latency_ms = 2100 }
Show "report cycle_ok" $r
Check "cycle_ok accepted" ($r.Status -eq 200) "$($r.Status)"

# 5. alias of a site-side code: must NOT blame the IP
$r = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "captcha_unsolved"; phase = "captcha"; detail = @{ profile_id = "p-smoke-1"; profile_fresh = $true } }
Show "report error captcha_unsolved (alias, lowercase)" $r
$changeIp = if ($r.Json) { "$($r.Json.change_ip)" } else { "?" }
Check "captcha_unsolved does not change IP" ($r.Status -eq 200 -and $changeIp -ne "True") "change_ip=$changeIp code=$($r.Json.code) next=$($r.Json.next_action)"

# 6. profile problem: reset profile, keep IP
$r = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "PROFILE_BROKEN"; phase = "login"; detail = @{ profile_id = "p-smoke-1"; profile_fresh = $false } }
Show "report error PROFILE_BROKEN" $r
Check "PROFILE_BROKEN -> reset_profile" ($r.Status -eq 200 -and "$($r.Json.next_action)" -eq "reset_profile") "next=$($r.Json.next_action) change_ip=$($r.Json.change_ip)"

# 7. account problem: never touches the IP
$r = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "account_issue"; phase = "login"; detail = @{ profile_id = "p-smoke-1" } }
Show "report error account_issue (alias of AUTH_ISSUE)" $r
$changeIp = if ($r.Json) { "$($r.Json.change_ip)" } else { "?" }
Check "account_issue does not change IP" ($r.Status -eq 200 -and $changeIp -ne "True") "change_ip=$changeIp code=$($r.Json.code)"

# 8. unknown code: stored as UNKNOWN, no ban, not rejected
$r = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "SOMETHING_NEW_4032XX"; phase = "login"; detail = @{ site_code = "403204"; profile_id = "p-smoke-1" } }
Show "report error with unknown code" $r
$changeIp = if ($r.Json) { "$($r.Json.change_ip)" } else { "?" }
Check "unknown code accepted, IP untouched" ($r.Status -eq 200 -and $changeIp -ne "True") "code=$($r.Json.code) change_ip=$changeIp"

# 9. optional: confirmed IP block (cools the IP down!)
if ($IncludeIpBan) {
    $r1 = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "ip_blocked"; phase = "navigate"; detail = @{ profile_id = "p-ban-1"; profile_fresh = $true } }
    Show "report error ip_blocked, profile 1 (not confirmed yet)" $r1
    $r2 = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "ip_blocked"; phase = "navigate"; detail = @{ profile_id = "p-ban-1"; profile_fresh = $true } }
    Show "report error ip_blocked, SAME profile again (must stay unconfirmed)" $r2
    $r3 = Call "POST" "/report" $tokA @{ lease_id = $lease; event_type = "error"; error_code = "ip_blocked"; phase = "navigate"; detail = @{ profile_id = "p-ban-2"; profile_fresh = $true } }
    Show "report error ip_blocked, DIFFERENT clean profile (should confirm)" $r3
    Check "same profile twice does not confirm" ($r2.Json -and [int]$r2.Json.cooldown_s -le 120) "cooldown_s=$($r2.Json.cooldown_s)"
    Check "second clean profile confirms" ($r3.Json -and [int]$r3.Json.cooldown_s -gt 120) "cooldown_s=$($r3.Json.cooldown_s)"
}

# 10. client isolation: client B must not touch client A's lease
if ($ClientTokenA -and $ClientTokenB) {
    $r = Call "POST" "/report" $ClientTokenB @{ lease_id = $lease; event_type = "info"; phase = "navigate" }
    Show "client B report on client A lease" $r
    Check "client B gets 403 on report" ($r.Status -eq 403) "$($r.Status)"
    $r = Call "POST" "/release" $ClientTokenB @{ lease_id = $lease; reason = "released" }
    Show "client B release on client A lease" $r
    Check "client B gets 403 on release" ($r.Status -eq 403) "$($r.Status)"
} else {
    Write-Host ""
    Write-Host "Client isolation skipped: pass -ClientTokenA and -ClientTokenB to test it." -ForegroundColor Yellow
}

# 11. normal release, no error code: IP goes back without blame
$r = Call "POST" "/release" $tokA @{ lease_id = $lease; reason = "released"; phase = "dashboard" }
Show "POST /release (normal)" $r
Check "release answers 200 with ok" ($r.Status -eq 200 -and $r.Json.ok -eq $true) "$($r.Status) verdict=$($r.Json.verdict) next=$($r.Json.next_action)"

# 12. old client: release of the same lease again must not crash the server
$r = Call "POST" "/release" $tokA @{ lease_id = $lease; reason = "released" }
Show "POST /release again (idempotence)" $r
Check "second release does not give 5xx" ($r.Status -lt 500 -and $r.Status -gt 0) "$($r.Status)"

# 13. bad token
$r = Call "POST" "/release" "wrong-token" @{ lease_id = $lease; reason = "released" }
Check "bad token gets 401" ($r.Status -eq 401) "$($r.Status)"

Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Cyan
$script:Results | Format-Table -AutoSize
if ($script:Fails -eq 0) { Write-Host "ALL CHECKS PASSED" -ForegroundColor Green } else { Write-Host "$($script:Fails) CHECK(S) FAILED - send me the output above" -ForegroundColor Red }
