[CmdletBinding(DefaultParameterSetName = 'MessageID')]
param(
    # Connection - all optional; prompted for interactively when omitted so this
    # can be handed to someone else without them needing to already have a
    # session open, but can still be scripted non-interactively when supplied.
    # $Server also accepts 'EXO' to connect to Exchange Online / Security &
    # Compliance PowerShell instead of an on-prem server.
    [Parameter()]
    [string]$Server,

    [Parameter()]
    [PSCredential]$Credential,

    [switch]$UseSSL,

    [Parameter(ParameterSetName = 'MessageID')]
    [ValidateNotNullOrEmpty()]
    [string]$MessageID,

    [Parameter(ParameterSetName = 'Criteria')]
    [ValidateNotNullOrEmpty()]
    [string]$SenderEmail,

    [Parameter(ParameterSetName = 'Criteria')]
    [string]$RecipientEmail,

    [Parameter(ParameterSetName = 'Criteria')]
    [string]$Subject,

    [Parameter(ParameterSetName = 'Criteria')]
    [string]$BodyContains,

    [Parameter(ParameterSetName = 'Criteria')]
    [string]$ReceivedDateTimeFrom,

    [Parameter(ParameterSetName = 'Criteria')]
    [string]$ReceivedDateTimeTo,

    # FIX: was [Parameter(Mandatory = $true)] AND had a default value - contradictory.
    # Mandatory=$true forces an interactive prompt and the default never gets a
    # chance to apply, which hangs non-interactive runs (RTR, scheduled tasks, etc).
    [ValidateSet('Soft', 'Hard')]
    [string]$DeleteType = 'Soft',

    # ADDED: run the search + preview only, no delete action, no confirmation prompt
    # to bypass. Use this every time you're not 100% sure of the query yet.
    [switch]$SearchOnly,

    # Opt-in only - see Test-ScriptVersionCurrent for why this is never on by
    # default. Compares $ScriptVersion below against whatever's on $UpdateCheckUrl
    # and prints a one-line notice (never blocks, never downloads/replaces
    # anything) if what you're running is behind.
    [switch]$CheckForUpdates,

    [switch]$Force
)

# EDIT BEFORE USE: point this at the raw file URL for wherever this script is
# actually hosted, e.g.:
#   https://raw.githubusercontent.com/<org-or-user>/<repo>/main/pull-email.ps1
# Left as an obvious placeholder rather than a guessed real-looking URL, so a
# silent failure here can't be mistaken for "checked, nothing newer" when it
# actually never reached anything.
$UpdateCheckUrl = 'https://raw.githubusercontent.com/t-d-knight/pull-email-exchange-onprem/main/pull-email.ps1'
$UpdateCheckTimeoutSeconds = 3

$ScriptVersion = '1.4.0'

# KNOWN ISSUES / TROUBLESHOOTING NOTES
# -------------------------------------
# "Unable to execute the task. Reason: Failed to retrieve executing user."
# (on New-ComplianceSearch/Start-ComplianceSearch/Get-ComplianceSearch, on-prem
# only) has TWO unrelated causes that present identically. See the full
# writeup on Test-ExecutingUserMailbox below before assuming either one:
#   1. Missing/broken org-wide Discovery mailbox
#      (SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}) - fails for
#      EVERY account on that org. Fix: Setup.exe /PrepareAD (change window).
#   2. Executing account has no on-prem mailbox - fails for THAT account only,
#      regardless of RBAC roles held. Fix: use/provision an account with a
#      mailbox. This script now warns about this at connect time (Step 0d).
# Diagnostic shortcut: if it fails for one account but not another on the same
# server, it's #2, not #1 - don't reach for /PrepareAD first.

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

$MaxSearchWaitSeconds = 600  # 10 minutes
$MaxActionWaitSeconds = 1200 # 20 minutes
$QueryTimeoutMinutes = 30
$CmdDelaySeconds = 5

# One log file per script *run* (not per search - a single session can run
# several searches back to back via the "Run another search?" loop, and those
# should all land in the same transcript rather than fragmenting across files).
$ScriptRunTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $PSScriptRoot "ComplianceSearch_${ScriptRunTimestamp}_log.txt"

# Overreach guardrail thresholds - above these, a "large impact" typed-token
# confirmation is required instead of a plain yes/no (see Confirm-LargeImpact).
$LargeImpactItemThreshold = 25
$LargeImpactMailboxThreshold = 10

# Above this many matched items WHILE A SEARCH IS STILL RUNNING, the search is
# stopped and aborted automatically rather than left to run to its full
# timeout - see Wait-ComplianceSearch. This is a much higher bar than
# $LargeImpactItemThreshold on purpose: that one gates a legitimate large but
# intentional delete: this one exists purely to catch a query that's silently
# degraded into an unfiltered org-wide scan (confirmed possible: 90M+ items,
# 30-minute timeout, against a search meant to hit exactly one email - see the
# Message-ID header-indexing note on New-ComplianceSearchQuery). 50,000 is
# comfortably above any legitimate single-incident cleanup for this org size,
# and comfortably below where a runaway scan lands within the first minute or
# two of polling.
$RunawaySearchItemThreshold = 50000

# Above this many matched rows, the console preview switches from a full
# per-item listing to a condensed sender+subject summary (full detail always
# still goes to the preview file - a 1,000-mailbox hit is unreadable dumped
# straight to the console).
$PreviewDisplayLimit = 20

# Compliance search can't filter on message headers (Message-ID) in EITHER
# on-prem Exchange or Exchange Online, since headers aren't indexed for search.
# A -MessageID search is always resolved first - via message tracking logs
# on-prem (Resolve-MessageIdToCriteria) or message trace in EXO
# (Resolve-MessageIdToCriteria-EXO) - into a sender+subject+date-window
# search instead. These control how far back to look, and how wide a date
# window to build around the resolved result.
$MessageTrackingLookbackDays = 30
$MessageIdDateWindowHours = 12


function Test-ScriptVersionCurrent {
    param(
        [string]$CurrentVersion,
        [string]$Url,
        [int]$TimeoutSeconds = 3
    )

    # Opt-in (-CheckForUpdates) and best-effort by design, not just by
    # accident - the direct reason this exists: a colleague ran a copy dated
    # the 30th while a run of real fixes landed in the days after (transcript
    # logging, the EXO Message-ID/header-indexing bug, the on-prem mailbox
    # preflight, the runaway-search abort...). A one-line "you're behind, here's
    # the link" would have saved that confusion. It does NOT auto-download or
    # replace anything - see the README on why: silently running whatever's
    # currently on main is the exact thing this project's own disclaimer tells
    # people not to do, doubly so for a tool that deletes mail org-wide.
    #
    # Every failure mode here (no internet, DNS, proxy, GitHub down, placeholder
    # URL never edited, regex miss because the upstream file's format changed)
    # must degrade to complete silence - this can NEVER be allowed to block,
    # slow down, or fail an actual incident-response run over a version check.
    if ($Url -match 'CHANGEME') {
        return
    }

    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop

        if ($response.Content -notmatch "`$ScriptVersion\s*=\s*'([\d.]+)'") {
            return
        }
        $remoteVersionString = $Matches[1]

        $current = [version]$CurrentVersion
        $remote = [version]$remoteVersionString

        if ($remote -gt $current) {
            Write-Host "`nNOTE: You're running v$CurrentVersion - v$remoteVersionString is available." -ForegroundColor Yellow
            Write-Host "  $Url" -ForegroundColor Yellow
            Write-Host "  (Not downloaded automatically - review changes before updating, same as you would for any script that touches production mail.)`n" -ForegroundColor DarkGray
        }
    }
    catch {
        # Deliberately silent - see comment above. Uncomment the line below only
        # for local troubleshooting of the check itself, never leave it on:
        # Write-Verbose "Update check failed (non-fatal): $_"
    }
}


function Connect-ExchangeSession {
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [switch]$UseSSL
    )

    if (-not $Server) {
        $Server = Read-Host "Exchange server to connect to (FQDN), or 'EXO' for Exchange Online"
    }
    if (-not $Server) {
        Write-Error "An Exchange server FQDN (or 'EXO') is required to connect."
    }

    if ($Server -match '^(EXO|ExchangeOnline)$') {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Error "Exchange Online support requires the ExchangeOnlineManagement module, which isn't installed. Install it first: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        }

        $upn = if ($Credential) { $Credential.UserName } else { Read-Host "Exchange Online admin UPN (e.g. admin@contoso.onmicrosoft.com)" }
        if (-not $upn) {
            Write-Error "A UPN is required to connect to Exchange Online."
        }

        Write-Host "Connecting to Exchange Online (Security & Compliance PowerShell) as $upn - a sign-in prompt may appear..." -ForegroundColor Cyan
        # Same reason as the on-prem branch below - Import-Module's and Connect-IPPSSession's
        # own internal module-loading code reads the GLOBAL $VerbosePreference, not a local
        # override, so it has to be flipped at global scope to actually quiet the
        # Importing-cmdlet/Exporting-function dump (~500+ lines for this module).
        $previousVerbosePreference = $global:VerbosePreference
        $global:VerbosePreference = 'SilentlyContinue'
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            # -EnableSearchOnlySession: required (ExchangeOnlineManagement 3.9.0+) for
            # New-ComplianceSearch/Start-ComplianceSearch to actually work over the newer
            # REST-based Security & Compliance backend - without it, Start-ComplianceSearch
            # fails with "Please close the current session and open a new session using
            # Connect-IPPSSession with the -EnableSearchOnlySession flag."
            Connect-IPPSSession -UserPrincipalName $upn -EnableSearchOnlySession -WarningAction SilentlyContinue -ErrorAction Stop

            # Connect-IPPSSession (Security & Compliance PowerShell) does NOT expose
            # Get-MessageTrace/Get-MessageTraceV2 - those live in the regular Exchange
            # Online management session (Connect-ExchangeOnline), which is a different
            # backend entirely. They're needed to resolve a -MessageID search (see
            # Resolve-MessageIdToCriteria-EXO), since compliance search can't filter on
            # message headers directly. -CommandName restricts what gets imported to just
            # the trace cmdlets, so this session doesn't clobber any Compliance-session
            # cmdlets of the same name (e.g. Get-Recipient exists in both modules).
            Connect-ExchangeOnline -UserPrincipalName $upn -CommandName 'Get-MessageTrace', 'Get-MessageTraceV2', 'Get-MessageTraceDetail', 'Get-MessageTraceDetailV2' -ShowBanner:$false -WarningAction SilentlyContinue -ErrorAction Stop
        }
        finally {
            $global:VerbosePreference = $previousVerbosePreference
        }

        if (-not $Credential) {
            # Connect-IPPSSession is modern-auth/interactive (MFA-capable) and doesn't take
            # a password here - build a placeholder credential just to carry the UPN through
            # to the permission check downstream (which only ever reads .UserName off it).
            $Credential = New-Object System.Management.Automation.PSCredential($upn, (New-Object System.Security.SecureString))
        }

        Write-Host "Connected to Exchange Online." -ForegroundColor Green
        return [pscustomobject]@{
            Session    = $null
            Credential = $Credential
            IsEXO      = $true
        }
    }

    if (-not $Credential) {
        $Credential = Get-Credential -Message "Credentials for connecting to $Server (the account needs the eDiscovery/compliance role checked in the next step)"
    }

    $scheme = if ($UseSSL) { 'https' } else { 'http' }
    $connectionUri = "${scheme}://$Server/PowerShell/"

    Write-Host "Connecting to $connectionUri as $($Credential.UserName) ..." -ForegroundColor Cyan
    # Import-PSSession is itself implemented as a function in a built-in module, and its
    # internal Import-Module call reads $VerbosePreference from ITS OWN module scope, not
    # from this function's local scope - a plain (non-$global:) reassignment here only
    # shadows the variable within Connect-ExchangeSession and never reaches that nested
    # call, which is why -Verbose:$false and a local override both failed to quiet the
    # "Exporting/Importing function" dump. Flipping the actual global value is what
    # both scopes fall back to when neither has its own local override.
    $previousVerbosePreference = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'
    try {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $connectionUri -Authentication Kerberos -Credential $Credential -ErrorAction Stop

        Import-PSSession $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
    }
    finally {
        $global:VerbosePreference = $previousVerbosePreference
    }

    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
    }
    catch {
        Write-Error "Connected to $Server, but a basic cmdlet (Get-OrganizationConfig) failed - check the account's Exchange RBAC role assignments. Details: $_"
    }

    Write-Host "Connected to $Server." -ForegroundColor Green
    return [pscustomobject]@{
        Session    = $session
        Credential = $Credential
        IsEXO      = $false
    }
}


function Get-SearchImplementation {
    param(
        [string]$DeleteType,
        [switch]$SearchOnly
    )

    Write-Host "Checking which search cmdlets this Exchange server supports..." -ForegroundColor Cyan

    if (Get-Command -Name New-ComplianceSearch -ErrorAction SilentlyContinue) {
        Write-Host "Found New-ComplianceSearch - using Modern mode." -ForegroundColor Green
        return 'Modern'
    }

    if (Get-Command -Name Search-Mailbox -ErrorAction SilentlyContinue) {
        Write-Host "New-ComplianceSearch is not available. Falling back to the legacy Search-Mailbox cmdlet (Legacy mode)." -ForegroundColor Yellow

        if ($DeleteType -eq 'Hard' -and -not $SearchOnly) {
            Write-Error "Legacy mode (Search-Mailbox) has no hard-delete equivalent - it can only move matched items to Recoverable Items. Re-run with -DeleteType Soft, or run this against an Exchange server new enough to support New-ComplianceSearch."
        }

        if (-not (Get-Mailbox -Identity 'Discovery Search Mailbox' -ErrorAction SilentlyContinue)) {
            Write-Error "Legacy mode targets a 'Discovery Search Mailbox' and none was found. Create one first, e.g.: New-Mailbox -Discovery -Name 'Discovery Search Mailbox' -UserPrincipalName DiscoverySearchMailbox@<yourdomain>"
        }

        return 'Legacy'
    }

    Write-Error "Neither New-ComplianceSearch nor Search-Mailbox is available in this session. The connecting account is likely missing the required RBAC role (e.g. 'Discovery Management'), or this Exchange version supports neither cmdlet."
}


function Test-RequiredPermissions {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Modern', 'Legacy')]
        [string]$Mode,

        [PSCredential]$Credential,

        [switch]$DeleteRequested
    )

    $accountName = $Credential.UserName
    if ($accountName -match '\\(.+)$') { $accountName = $Matches[1] }
    elseif ($accountName -match '^(.+)@') { $accountName = $Matches[1] }

    Write-Host "Checking '$accountName' has the RBAC role(s) needed for $Mode mode..." -ForegroundColor Cyan

    if (-not (Get-Command -Name Get-ManagementRoleAssignment -ErrorAction SilentlyContinue)) {
        # Exchange Online's Security & Compliance PowerShell (Connect-IPPSSession) doesn't
        # expose role-assignment cmdlets at all - RBAC there is managed through the Purview
        # compliance portal, not this session. There's no way to check a specific role name
        # here, so fall back to a light capability probe and let the search/delete cmdlets
        # enforce real authorization when they actually run.
        Write-Host "Get-ManagementRoleAssignment isn't available in this session (expected for Exchange Online) - running a basic capability check instead." -ForegroundColor Yellow
        try {
            $null = Get-ComplianceSearch -ResultSize 1 -ErrorAction Stop
        }
        catch {
            Write-Error "Account '$accountName' cannot run Get-ComplianceSearch - it likely lacks a compliance/eDiscovery role (e.g. eDiscovery Manager) in Microsoft Purview. Details: $_"
        }
        Write-Host "Basic capability check passed for '$accountName'. This does not confirm the 'Search And Purge' role specifically - if a delete action fails with an authorization error, check for that role in the Purview compliance portal." -ForegroundColor Yellow
        return
    }

    $assignments = Get-ManagementRoleAssignment -RoleAssignee $accountName -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
    $roleNames = @($assignments | Select-Object -ExpandProperty Role -Unique)

    if ($Mode -eq 'Modern') {
        $required = @('Mailbox Search', 'Compliance Search')
        if (-not ($roleNames | Where-Object { $required -contains $_ })) {
            Write-Error "Account '$accountName' has none of the required roles ($($required -join ', ')) for compliance search. Add it to the 'Discovery Management' (or 'Compliance Management') role group and try again."
        }
        if ($DeleteRequested -and ($roleNames -notcontains 'Search And Purge')) {
            Write-Host "NOTE: '$accountName' doesn't show the 'Search And Purge' role, which Exchange Online/Purview uses to gate the actual delete action. If the delete step fails with an authorization error, that's the role to add - on-prem accounts with 'Compliance Search' typically don't need it separately, so this may be a false alarm there." -ForegroundColor Yellow
        }
    }
    else {
        if ($roleNames -notcontains 'Mailbox Search') {
            Write-Error "Account '$accountName' does not have the 'Mailbox Search' role required for Search-Mailbox. Add it to the 'Discovery Management' role group and try again."
        }
        if ($DeleteRequested -and ($roleNames -notcontains 'Mailbox Import Export')) {
            Write-Error "Account '$accountName' does not have the 'Mailbox Import Export' role required to delete content with Search-Mailbox (-DeleteContent). Grant that role (e.g. New-ManagementRoleAssignment -Role 'Mailbox Import Export' -User $accountName) and try again, or re-run with -SearchOnly."
        }
    }

    Write-Host "Permission preflight passed for '$accountName' ($Mode mode)." -ForegroundColor Green
}


function Test-ExecutingUserMailbox {
    param(
        [string]$AccountName,
        [switch]$IsEXO
    )

    # BACKGROUND (do not remove without re-reading this): "Unable to execute the
    # task. Reason: Failed to retrieve executing user. Please try again later."
    # thrown by New-ComplianceSearch/Start-ComplianceSearch/Get-ComplianceSearch
    # has TWO distinct, unrelated root causes we've now hit in production, and
    # they present IDENTICALLY - same error text, same immediate/every-call
    # failure pattern - so don't assume it's the same one twice:
    #
    #   1. The org-wide Discovery/arbitration system mailbox
    #      (SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}) is missing or
    #      broken. This breaks the error for EVERY account on that org, no
    #      exceptions - confirmed at Kerhosp. Fix is Setup.exe /PrepareAD
    #      (org-wide, change-window territory, not a quick fix).
    #
    #   2. The EXECUTING account itself has no on-prem mailbox. This is
    #      per-account, not org-wide - confirmed at Swan Hill, where the same
    #      cmdlet against the same server on the same day failed for one admin
    #      account and succeeded cleanly for another. If cause #1 were in play
    #      it would have failed for both. RBAC role count is NOT the
    #      differentiator either - the failing account there had Organization
    #      Management (effectively every role available) and still failed
    #      identically to a standard analyst account elsewhere failing under
    #      cause #1. This matches how a lot of tiered-admin naming conventions
    #      (_adm/.admin suffixed accounts) work: deliberately not mail-enabled,
    #      as a security posture, which is fine for almost everything BUT this.
    #
    # Diagnostic order when this error shows up on-prem: check whether it's
    # account-specific first (does it fail for other accounts on the same
    # server?) before chasing the org-wide arbitration mailbox - that saves a
    # /PrepareAD detour when the real fix is "use/provision an account with a
    # mailbox" instead.
    #
    # This check is a WARNING, not a hard block: it's a strong correlation from
    # two real incidents, not a documented Microsoft requirement (their own
    # guidance for Exchange Online content search explicitly says a mailbox is
    # NOT required there - this appears to be on-prem-specific, and even there
    # we have an n=1 confirmed case, not exhaustive proof). Blocking a valid
    # run on a hypothesis this specific would be worse than an occasional
    # false-negative warning.

    if ($IsEXO) {
        # Documented as not required for Exchange Online content search - skip.
        return
    }

    if (-not (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue)) {
        return
    }

    Write-Host "Checking '$AccountName' has an on-prem mailbox (known correlate of 'Failed to retrieve executing user')..." -ForegroundColor Cyan

    $mbx = Get-Mailbox -Identity $AccountName -ErrorAction SilentlyContinue

    if (-not $mbx) {
        Write-Host @"
WARNING: '$AccountName' does not appear to have an on-prem mailbox.

If New-ComplianceSearch / Start-ComplianceSearch / Get-ComplianceSearch fail
below with "Failed to retrieve executing user", this is now a two-time-confirmed
correlate (Swan Hill, 2026-08) - the SAME error also has an unrelated org-wide
cause (missing Discovery/arbitration mailbox), so don't assume this is it
without checking whether the failure is account-specific first.

If it does fail this way: re-run as, or ask whoever holds the search to run as,
an account that DOES have a mailbox - RBAC roles alone (even Organization
Management) do not work around this.
"@ -ForegroundColor Yellow
    }
    else {
        Write-Host "  '$AccountName' has a mailbox ($($mbx.PrimarySmtpAddress)) - not a likely cause if 'Failed to retrieve executing user' shows up." -ForegroundColor DarkGray
    }
}


function Get-SearchCriteriaInteractive {
    Write-Host "`nNo search criteria were supplied on the command line - let's build one interactively." -ForegroundColor Cyan
    Write-Host "  1) Message-ID (most specific - use this whenever you have it)"
    Write-Host "  2) Sender/Recipient + a narrower (subject, link/text, or date range)"
    Write-Host "  3) Cancel"
    $choice = Read-Host "`nChoice"

    $result = [ordered]@{
        ParameterSetName     = $null
        MessageID            = $null
        SenderEmail          = $null
        RecipientEmail       = $null
        Subject              = $null
        BodyContains         = $null
        ReceivedDateTimeFrom = $null
        ReceivedDateTimeTo   = $null
    }

    switch ($choice) {
        '1' {
            $result.ParameterSetName = 'MessageID'
            $result.MessageID = Read-Host "Message-ID (e.g. <abc123@contoso.com>)"
            if (-not $result.MessageID) {
                Write-Error "A Message-ID is required."
            }
        }
        '2' {
            $result.ParameterSetName = 'Criteria'

            Write-Host "`nWho (at least one required):" -ForegroundColor Cyan
            $result.SenderEmail = Read-Host "  Sender email (blank to skip)"
            $result.RecipientEmail = Read-Host "  Recipient email - to/cc/bcc (blank to skip)"
            if (-not $result.SenderEmail -and -not $result.RecipientEmail) {
                Write-Error "At least one of sender or recipient is required to narrow a criteria-based search."
            }

            Write-Host "`nWhat/when (at least one required):" -ForegroundColor Cyan
            $result.Subject = Read-Host "  Subject contains (blank to skip)"
            $result.BodyContains = Read-Host "  Body contains this link or text (blank to skip)"

            $lastDays = Read-Host "  Received in the last N days (blank to specify an exact date range instead)"
            if ($lastDays) {
                if ($lastDays -notmatch '^\d+$') {
                    Write-Error "Received in the last N days must be a whole number."
                }
                $result.ReceivedDateTimeTo = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                $result.ReceivedDateTimeFrom = (Get-Date).AddDays(-[int]$lastDays).ToString('yyyy-MM-dd HH:mm:ss')
                Write-Host "  Using range: $($result.ReceivedDateTimeFrom) to $($result.ReceivedDateTimeTo)" -ForegroundColor DarkGray
            }
            else {
                $result.ReceivedDateTimeFrom = Read-Host "  Received from - yyyy-MM-dd (blank to skip)"
                if ($result.ReceivedDateTimeFrom) {
                    $result.ReceivedDateTimeTo = Read-Host "  Received to - yyyy-MM-dd"
                }
            }

            if (-not $result.Subject -and -not $result.BodyContains -and -not ($result.ReceivedDateTimeFrom -and $result.ReceivedDateTimeTo)) {
                Write-Error "At least one of subject, body/link text, or a full date range is required to narrow a criteria-based search."
            }
        }
        default {
            Write-Host "Cancelled." -ForegroundColor Yellow
            $result.ParameterSetName = 'Cancelled'
        }
    }

    return $result
}


function Resolve-MessageIdToCriteria-EXO {
    param(
        [string]$MessageID
    )

    # IMPORTANT: compliance search / content search does NOT index message headers
    # (Message-ID is a header field), and separately drops/ignores unindexed or
    # unsupported query clauses rather than erroring - so a raw "(MessageId:"<...>")"
    # ContentMatchQuery silently becomes an unfiltered, org-wide search instead of
    # failing loudly. This bit us in production: a single-message search matched
    # 90M+ items and timed out. Resolve via message trace first, the same way the
    # on-prem branch resolves via message tracking logs, and build a real indexed
    # (from/subject/received) query from that instead of trusting MessageId: at all.
    Write-Host "`nCompliance search doesn't index message headers, so Message-ID can't be searched directly even in Exchange Online (an unrecognized 'MessageId:' clause is silently dropped rather than erroring, which turns this into an unfiltered org-wide search) - resolving this Message-ID via message trace first..." -ForegroundColor Yellow

    $traceCmd = if (Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue) { 'Get-MessageTraceV2' } else { 'Get-MessageTrace' }
    Write-Verbose "Using $traceCmd for message trace lookup."

    $startDate = (Get-Date).AddDays(-$MessageTrackingLookbackDays)
    $endDate = Get-Date

    try {
        $entries = @(& $traceCmd -MessageId $MessageID -StartDate $startDate -EndDate $endDate -ErrorAction Stop)
    }
    catch {
        Write-Error "Message trace lookup ($traceCmd) failed for '$MessageID': $_"
    }

    if (-not $entries -or $entries.Count -eq 0) {
        Write-Error "Could not resolve Message-ID '$MessageID' via $traceCmd (last $MessageTrackingLookbackDays day(s)). The message may be older than trace retention for this tenant, or the ID may be wrong. Identify the sender/subject/date manually and re-run with -SenderEmail/-Subject/-ReceivedDateTimeFrom/-ReceivedDateTimeTo instead."
    }

    # Multiple trace rows can come back for one message (one per recipient) - any of
    # them carries the same sender/subject, so the earliest received timestamp anchors
    # the narrowest accurate date window.
    $entry = $entries | Sort-Object Received | Select-Object -First 1
    $resolvedSender = $entry.SenderAddress
    $resolvedSubject = $entry.Subject
    $resolvedTimestamp = $entry.Received

    if (-not $resolvedSender -or -not $resolvedTimestamp) {
        Write-Error "Found a $traceCmd entry for '$MessageID' but it's missing sender/date detail. Identify the sender/subject/date manually and re-run with -SenderEmail/-Subject/-ReceivedDateTimeFrom/-ReceivedDateTimeTo instead."
    }

    $windowStart = $resolvedTimestamp.AddHours(-$MessageIdDateWindowHours).ToString('yyyy-MM-dd HH:mm:ss')
    $windowEnd = $resolvedTimestamp.AddHours($MessageIdDateWindowHours).ToString('yyyy-MM-dd HH:mm:ss')

    Write-Host "Resolved via ${traceCmd}:" -ForegroundColor Green
    Write-Host "  Sender   : $resolvedSender"
    Write-Host "  Subject  : $resolvedSubject"
    Write-Host "  Traced at: $resolvedTimestamp"
    Write-Host "Narrowing the search to this sender + subject + a $($MessageIdDateWindowHours * 2)-hour window around that timestamp.`n" -ForegroundColor Green

    return [pscustomobject]@{
        SenderEmail          = $resolvedSender
        Subject              = $resolvedSubject
        ReceivedDateTimeFrom = $windowStart
        ReceivedDateTimeTo   = $windowEnd
    }
}


function Resolve-MessageIdToCriteria {
    param(
        [string]$MessageID
    )

    Write-Host "`nOn-premises Exchange has no 'messageid' KQL property (that field is Exchange Online-only) - resolving this Message-ID via message tracking logs first..." -ForegroundColor Yellow

    $servers = @(Get-TransportService -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if (-not $servers) {
        # Fallback for older builds (pre-2013) where Get-TransportService doesn't exist.
        $servers = @(Get-TransportServer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    }
    if (-not $servers) {
        Write-Error "Could not enumerate any transport servers to search message tracking logs on."
    }

    $startDate = (Get-Date).AddDays(-$MessageTrackingLookbackDays)
    $entries = @()
    foreach ($srv in $servers) {
        try {
            $entries += Get-MessageTrackingLog -Server $srv -MessageId $MessageID -Start $startDate -ResultSize Unlimited -ErrorAction Stop
        }
        catch {
            Write-Verbose "No message tracking log results on $srv for this Message-ID: $_"
        }
    }

    if (-not $entries -or $entries.Count -eq 0) {
        Write-Error "Could not resolve Message-ID '$MessageID' via message tracking logs on any server (searched: $($servers -join ', '); last $MessageTrackingLookbackDays day(s)). The message may be older than the tracking log retention, it may never have transited on-prem transport (e.g. it originated in Exchange Online in a hybrid environment - if so, connect with -Server EXO instead), or the ID may be wrong. Identify the sender/subject/date manually and re-run with -SenderEmail/-Subject/-ReceivedDateTimeFrom/-ReceivedDateTimeTo instead."
    }

    $entry = $entries | Sort-Object Timestamp | Select-Object -First 1
    $resolvedSender = $entry.Sender
    $resolvedSubject = $entry.MessageSubject
    $resolvedTimestamp = $entry.Timestamp

    if (-not $resolvedSender -or -not $resolvedSubject) {
        Write-Error "Found a message tracking log entry for '$MessageID' but it's missing sender/subject detail. Identify the sender/subject/date manually and re-run with -SenderEmail/-Subject/-ReceivedDateTimeFrom/-ReceivedDateTimeTo instead."
    }

    $windowStart = $resolvedTimestamp.AddHours(-$MessageIdDateWindowHours).ToString('yyyy-MM-dd HH:mm:ss')
    $windowEnd = $resolvedTimestamp.AddHours($MessageIdDateWindowHours).ToString('yyyy-MM-dd HH:mm:ss')

    Write-Host "Resolved via message tracking log:" -ForegroundColor Green
    Write-Host "  Sender   : $resolvedSender"
    Write-Host "  Subject  : $resolvedSubject"
    Write-Host "  Tracked at: $resolvedTimestamp"
    Write-Host "Narrowing the search to this sender + subject + a $($MessageIdDateWindowHours * 2)-hour window around that timestamp.`n" -ForegroundColor Green

    return [pscustomobject]@{
        SenderEmail          = $resolvedSender
        Subject              = $resolvedSubject
        ReceivedDateTimeFrom = $windowStart
        ReceivedDateTimeTo   = $windowEnd
    }
}


function Test-QuerySpecificity {
    param(
        [string]$ParameterSetName,
        [string]$SenderEmail,
        [string]$RecipientEmail,
        [string]$Subject,
        [string]$BodyContains,
        [string]$ReceivedDateTimeFrom,
        [string]$ReceivedDateTimeTo
    )

    if ($ParameterSetName -eq 'MessageID') {
        return
    }

    $hasWho = [bool]$SenderEmail -or [bool]$RecipientEmail
    $hasWhatWhen = [bool]$Subject -or [bool]$BodyContains -or ([bool]$ReceivedDateTimeFrom -and [bool]$ReceivedDateTimeTo)

    if (-not $hasWho -or -not $hasWhatWhen) {
        Write-Error @"
Query is not narrow enough to run against -ExchangeLocation All.

A criteria-based search must specify:
  - WHO       : -SenderEmail and/or -RecipientEmail, AND
  - WHAT/WHEN : -Subject and/or -BodyContains, and/or a full -ReceivedDateTimeFrom/-ReceivedDateTimeTo range

This prevents a lone sender (or a bare wildcard) from matching every email
that sender or recipient has ever sent or received across the entire
organization. Narrow the query, or use -MessageID if you have it.
"@
    }
}


function New-ComplianceSearchQuery {
    param(
        [string]$MessageID,
        [string]$SenderEmail,
        [string]$RecipientEmail,
        [string]$Subject,
        [string]$BodyContains,
        [string]$ReceivedDateTimeFrom,
        [string]$ReceivedDateTimeTo
    )

    $queryParts = @()

    # Defensive trim - treat a whitespace-only value the same as "not provided" so a
    # stray space typed into a prompt can't sneak an empty/blank clause into the query.
    $MessageID = if ($MessageID) { $MessageID.Trim() } else { $MessageID }
    $SenderEmail = if ($SenderEmail) { $SenderEmail.Trim() } else { $SenderEmail }
    $RecipientEmail = if ($RecipientEmail) { $RecipientEmail.Trim() } else { $RecipientEmail }
    $Subject = if ($Subject) { $Subject.Trim() } else { $Subject }
    $BodyContains = if ($BodyContains) { $BodyContains.Trim() } else { $BodyContains }

    if ($MessageID) {
        # Compliance search does not index message headers in EITHER on-prem Exchange
        # or Exchange Online - a raw "MessageId:" clause is not a real indexed filter
        # and gets silently dropped rather than erroring, which turns this into an
        # unfiltered org-wide search (confirmed in production: 90M+ items, 30-minute
        # timeout, against a single-message search). MessageID is resolved to
        # sender+subject+date-window criteria upstream (Resolve-MessageIdToCriteria /
        # Resolve-MessageIdToCriteria-EXO) before this function is ever called with a
        # MessageID value - this branch should be unreachable. It's kept only as a loud
        # failure rather than a silent no-op, in case that resolution step is bypassed.
        Write-Error "Internal error: New-ComplianceSearchQuery was called with -MessageID set. Message-ID must be resolved to sender/subject/date criteria before reaching the query builder - compliance search cannot filter on message headers directly in any environment."
    }
    else {
        # Criteria-based search
        if ($SenderEmail) {
            $queryParts += "(from:""$SenderEmail"")"
        }

        if ($RecipientEmail) {
            $queryParts += "(to:""$RecipientEmail"" OR cc:""$RecipientEmail"" OR bcc:""$RecipientEmail"")"
        }

        if ($Subject) {
            $queryParts += "(subject:""$Subject"")"
            Write-Host "`nNOTE: On-premises Exchange subject search uses full-text indexing. Trailing numbers are ignored (e.g. 'Invoice payment 2027' matches any subject containing 'Invoice payment'). Numbers at the start or middle of the subject work correctly. No KQL escape exists for this. Use a narrow ReceivedDateTime range to avoid false matches.`n" -ForegroundColor Yellow
        }

        if ($BodyContains) {
            $queryParts += "(body:""$BodyContains"")"
        }

        if ($ReceivedDateTimeFrom -and $ReceivedDateTimeTo) {
            try {
                $dtFrom = [datetimeoffset]::Parse($ReceivedDateTimeFrom)
                $dtTo = [datetimeoffset]::Parse($ReceivedDateTimeTo)

                # A date-only "To" value (e.g. "2026-07-26") parses to midnight of that
                # day - if left as-is, a same-day range (or any date-only range) becomes
                # a zero-width instant instead of covering the whole day(s). Bump it to
                # the last moment of that day instead, unless a time-of-day was actually
                # given (in which case it won't land exactly on midnight).
                if ($dtTo.TimeOfDay -eq [timespan]::Zero) {
                    $dtTo = $dtTo.AddDays(1).AddTicks(-1)
                }

                $localTz = (Get-TimeZone -ErrorAction SilentlyContinue).Id
                Write-Host "  Date range (local$(if ($localTz) { ", $localTz" })): $($dtFrom.ToString('yyyy-MM-dd HH:mm:ss')) to $($dtTo.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray

                $dateFromStr = $dtFrom.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $dateToStr = $dtTo.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $queryParts += "(received:$dateFromStr..$dateToStr)"
            }
            catch {
                Write-Error "Invalid ReceivedDateTime format. Use 'yyyy-MM-dd' or 'yyyy-MM-dd HH:mm:ss'."
            }
        }
    }

    if ($queryParts.Count -eq 0) {
        Write-Error "At least one search criterion must be provided."
    }

    $query = $queryParts -join ' AND '
    return $query
}


function Remove-ComplianceSearchWithReport {
    param(
        [string]$Identity
    )

    # Used on the error/abort cleanup path (the success path's own
    # Remove-ComplianceSearch calls elsewhere don't need this - the search is
    # already Completed by the time those run, so there's nothing to stop).
    # A search that's still actively running (InProgress/Starting) can't
    # always be removed cleanly in one step, hence stop-first. Both steps are
    # best-effort - a failed cleanup here means the underlying operation
    # already failed too, and this function's job is to report what happened,
    # not to throw a second error on top of the first.
    $stopSucceeded = $true
    try {
        $current = Get-ComplianceSearch -Identity $Identity -ErrorAction Stop
        if ($current.Status -notin @('Completed', 'Stopped')) {
            Stop-ComplianceSearch -Identity $Identity -Confirm:$false -ErrorAction Stop
        }
    }
    catch {
        $stopSucceeded = $false
    }

    try {
        Remove-ComplianceSearch -Identity $Identity -Confirm:$false -ErrorAction Stop
        Write-Host "Cleanup: compliance search '$Identity' removed successfully." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "WARNING: cleanup FAILED - could not remove compliance search '$Identity'$(if (-not $stopSucceeded) { ' (stop-first step also failed)' }). Check its status manually: Get-ComplianceSearch -Identity '$Identity'. Details: $_" -ForegroundColor Red
    }
}


function Wait-ComplianceSearch {
    param(
        [string]$Identity,
        [int]$TimeoutSeconds = 600,
        [int]$RunawayItemThreshold = $RunawaySearchItemThreshold
    )

    $elapsed = 0
    $checkInterval = 5

    do {
        $search = Get-ComplianceSearch -Identity $Identity
        $status = $search.Status

        if ($status -eq 'Completed') {
            Write-Host "Search '$Identity' completed. Items found: $($search.Items)"
            return $search
        }
        elseif ($status -eq 'Failed' -or $status -eq 'Error') {
            Write-Error "Search failed with status: $status. Details: $($search.StatusDetails)"
        }
        elseif ($status -eq 'Stopped') {
            Write-Error "Search was stopped."
        }
        else {
            # Runaway-search abort: a query that's silently lost its filter (see
            # the Message-ID header-indexing note elsewhere in this file) looks
            # exactly like this while it's running - status InProgress, item
            # count climbing fast, well past what any legitimate single-message
            # or single-incident search should ever match. Bail out here rather
            # than let it run the full timeout, since by the time the timeout
            # fires the query has usually already walked most of the org anyway.
            if ($search.Items -gt $RunawayItemThreshold) {
                Write-Host "  Item count ($($search.Items)) has crossed the runaway-search threshold ($RunawayItemThreshold) while still $status - stopping the search now rather than letting it run to timeout." -ForegroundColor Red
                try {
                    Stop-ComplianceSearch -Identity $Identity -Confirm:$false -ErrorAction Stop
                    Write-Host "  Search stopped." -ForegroundColor Yellow
                }
                catch {
                    Write-Host "  WARNING: could not stop the runaway search automatically - check its status manually: Get-ComplianceSearch -Identity '$Identity'. Details: $_" -ForegroundColor Red
                }
                Write-Error "Search '$Identity' aborted: matched $($search.Items) items while still $status, which is almost certainly a query that lost its filter (e.g. an unindexed clause silently dropped) rather than a genuine result set for a single-incident search. Review the KQL query before retrying - do not simply re-run with a longer timeout."
            }

            Write-Host "  Searching... Status: $status, Items found so far: $($search.Items)" -ForegroundColor Yellow
            Start-Sleep -Seconds $checkInterval
            $elapsed += $checkInterval
        }

        if ($elapsed -gt $TimeoutSeconds) {
            Write-Error "Search timed out after $TimeoutSeconds seconds."
        }
    } while ($true)
}


function Wait-ComplianceSearchAction {
    param(
        [string]$ActionIdentity,
        [int]$TimeoutSeconds = 1200
    )

    $elapsed = 0
    $checkInterval = 10

    do {
        $action = Get-ComplianceSearchAction -Identity $ActionIdentity
        $status = $action.Status
        $percentComplete = $action.PercentComplete

        if ($status -eq 'Completed') {
            Write-Host "Delete action '$ActionIdentity' completed. Results: $($action.Results)"
            return $action
        }
        elseif ($status -eq 'Failed' -or $status -eq 'Error') {
            Write-Error "Delete action failed with status: $status. Details: $($action.ResultsLink)"
        }
        elseif ($status -eq 'Stopped') {
            Write-Error "Delete action was stopped."
        }
        else {
            Write-Host "  Deleting... Status: $status, Progress: ${percentComplete}%" -ForegroundColor Yellow
            Start-Sleep -Seconds $checkInterval
            $elapsed += $checkInterval
        }

        if ($elapsed -gt $TimeoutSeconds) {
            Write-Error "Delete action timed out after $TimeoutSeconds seconds."
        }
    } while ($true)
}


function Invoke-LegacyMailboxPreview {
    param(
        [string]$SearchQuery,
        [string]$TargetFolder
    )

    Write-Host "Enumerating mailboxes and running Search-Mailbox (estimate only) against each - this can take a while org-wide..." -ForegroundColor Cyan
    $mailboxes = @(Get-Mailbox -ResultSize Unlimited)

    $rows = @()
    $i = 0
    foreach ($mbx in $mailboxes) {
        $i++
        Write-Progress -Activity "Estimating legacy search" -Status "$($mbx.PrimarySmtpAddress)" -PercentComplete (($i / [math]::Max($mailboxes.Count, 1)) * 100)
        try {
            $result = Search-Mailbox -Identity $mbx.Identity -SearchQuery $SearchQuery `
                -TargetMailbox 'Discovery Search Mailbox' -TargetFolder $TargetFolder `
                -EstimateResultOnly -LogLevel Full -Force -ErrorAction Stop
        }
        catch {
            Write-Verbose "Skipping $($mbx.PrimarySmtpAddress): $_"
            continue
        }

        if ($result.ResultItemsCount -gt 0) {
            $rows += [pscustomobject]@{
                Mailbox   = $mbx.PrimarySmtpAddress.ToString()
                ItemCount = $result.ResultItemsCount
            }
        }
    }
    Write-Progress -Activity "Estimating legacy search" -Completed

    return $rows
}


function Invoke-LegacyMailboxDelete {
    param(
        [string]$SearchQuery,
        [string]$TargetFolder,
        [object[]]$MatchedMailboxes
    )

    foreach ($row in $MatchedMailboxes) {
        Write-Host "  Deleting matched items in $($row.Mailbox) ..." -ForegroundColor Yellow
        Search-Mailbox -Identity $row.Mailbox -SearchQuery $SearchQuery `
            -TargetMailbox 'Discovery Search Mailbox' -TargetFolder $TargetFolder `
            -DeleteContent -Force -LogLevel Full -ErrorAction Stop | Out-Null
    }
}


function Confirm-LargeImpact {
    param(
        [int]$ItemsFound,
        [int]$MailboxCount,
        [string]$DeleteType,
        [int]$ItemThreshold,
        [int]$MailboxThreshold,
        [switch]$Force
    )

    $isLargeImpact = ($ItemsFound -gt $ItemThreshold) -or ($MailboxCount -gt $MailboxThreshold)
    $needsToken = $isLargeImpact -or ($DeleteType -eq 'Hard')

    if (-not $needsToken) {
        return
    }

    if ($Force) {
        Write-Host "WARNING: -Force bypassed the large-impact confirmation ($ItemsFound item(s) across $MailboxCount mailbox(es), DeleteType=$DeleteType)." -ForegroundColor Red
        return
    }

    $charCodes = (48..57) + (65..90)
    $token = -join (1..6 | ForEach-Object { [char]($charCodes | Get-Random) })

    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "LARGE-IMPACT DELETE" -ForegroundColor Red
    Write-Host "  Items found   : $ItemsFound" -ForegroundColor Red
    Write-Host "  Mailboxes hit : $MailboxCount" -ForegroundColor Red
    Write-Host "  Delete type   : $DeleteType" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red

    $typed = Read-Host "`nType $token to confirm this delete"
    if ($typed -ne $token) {
        Write-Error "Confirmation token did not match - aborting."
    }
}


function Invoke-EmailSearchAndDelete {
    param(
        [string]$SearchMode,
        [string]$BoundParameterSetName,
        [switch]$IsEXO,
        [switch]$UseBoundCriteria
    )

    $SearchName = "ComplianceSearch_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    # Guards the catch-block cleanup below - without this, a failure that happens
    # BEFORE New-ComplianceSearch ever runs (e.g. Message-ID resolution failing)
    # still triggers a Remove-ComplianceSearch attempt against a search that was
    # never created, producing a confusing secondary ManagementObjectNotFoundException
    # that buries the real error in the log.
    $searchCreated = $false

    try {
        # 1. Collect search criteria (interactively if none were supplied on the command line,
        # or if this isn't the first search run in this session - CLI-bound criteria only ever
        # apply once, further searches in the same session always go through the interactive menu).
        Write-Host "`n[Step 1] Validating input parameters..."
        $criteriaSupplied = $UseBoundCriteria -and ($MessageID -or $SenderEmail -or $RecipientEmail -or $Subject -or $BodyContains -or $ReceivedDateTimeFrom -or $ReceivedDateTimeTo)

        # NOTE: working copies, not the bound parameters themselves. $MessageID/$SenderEmail
        # carry [ValidateNotNullOrEmpty()], which re-validates on every assignment (not just
        # initial CLI binding) - writing $null back into whichever field the interactive
        # menu didn't use would throw.
        if (-not $criteriaSupplied) {
            $interactive = Get-SearchCriteriaInteractive
            if ($interactive.ParameterSetName -eq 'Cancelled') {
                return
            }
            $effectiveParameterSetName = $interactive.ParameterSetName
            $qMessageID = $interactive.MessageID
            $qSenderEmail = $interactive.SenderEmail
            $qRecipientEmail = $interactive.RecipientEmail
            $qSubject = $interactive.Subject
            $qBodyContains = $interactive.BodyContains
            $qReceivedDateTimeFrom = $interactive.ReceivedDateTimeFrom
            $qReceivedDateTimeTo = $interactive.ReceivedDateTimeTo
        }
        else {
            $effectiveParameterSetName = $BoundParameterSetName
            $qMessageID = $MessageID
            $qSenderEmail = $SenderEmail
            $qRecipientEmail = $RecipientEmail
            $qSubject = $Subject
            $qBodyContains = $BodyContains
            $qReceivedDateTimeFrom = $ReceivedDateTimeFrom
            $qReceivedDateTimeTo = $ReceivedDateTimeTo
        }

        if ($effectiveParameterSetName -eq 'MessageID' -and -not $qMessageID) {
            Write-Error "MessageID is required when using the MessageID parameter set. Example: .\pull-email.ps1 -MessageID '<abc123@contoso.com>' -SearchOnly"
        }

        if ($effectiveParameterSetName -eq 'MessageID' -and $IsEXO) {
            # NOTE: compliance search does not index message headers in Exchange Online
            # either - Message-ID can't be searched directly. Resolve via message trace
            # into a sender+subject+date-window search, same shape as the on-prem path.
            $resolved = Resolve-MessageIdToCriteria-EXO -MessageID $qMessageID
            $effectiveParameterSetName = 'Criteria'
            $qMessageID = $null
            $qSenderEmail = $resolved.SenderEmail
            $qRecipientEmail = $null
            $qSubject = $resolved.Subject
            $qBodyContains = $null
            $qReceivedDateTimeFrom = $resolved.ReceivedDateTimeFrom
            $qReceivedDateTimeTo = $resolved.ReceivedDateTimeTo
        }
        elseif ($effectiveParameterSetName -eq 'MessageID') {
            # Neither on-prem compliance search nor Search-Mailbox support querying by
            # Message-ID directly - resolve it into a sender+subject+date-window search instead.
            $resolved = Resolve-MessageIdToCriteria -MessageID $qMessageID
            $effectiveParameterSetName = 'Criteria'
            $qMessageID = $null
            $qSenderEmail = $resolved.SenderEmail
            $qRecipientEmail = $null
            $qSubject = $resolved.Subject
            $qBodyContains = $null
            $qReceivedDateTimeFrom = $resolved.ReceivedDateTimeFrom
            $qReceivedDateTimeTo = $resolved.ReceivedDateTimeTo
        }

        if ($effectiveParameterSetName -eq 'Criteria' -and -not ($qSenderEmail -or $qRecipientEmail -or $qSubject -or $qBodyContains -or $qReceivedDateTimeFrom -or $qReceivedDateTimeTo)) {
            Write-Error "At least one of SenderEmail, RecipientEmail, Subject, BodyContains, or ReceivedDateTimeFrom/ReceivedDateTimeTo must be provided when using the Criteria parameter set."
        }

        # 1b. Overreach guardrail - block under-specified criteria searches
        Test-QuerySpecificity -ParameterSetName $effectiveParameterSetName -SenderEmail $qSenderEmail -RecipientEmail $qRecipientEmail `
            -Subject $qSubject -BodyContains $qBodyContains -ReceivedDateTimeFrom $qReceivedDateTimeFrom -ReceivedDateTimeTo $qReceivedDateTimeTo

        # 2. Build KQL query
        Write-Host "`n[Step 2] Building search query..."
        $kqlQuery = New-ComplianceSearchQuery -MessageID $qMessageID -SenderEmail $qSenderEmail -RecipientEmail $qRecipientEmail `
            -Subject $qSubject -BodyContains $qBodyContains -ReceivedDateTimeFrom $qReceivedDateTimeFrom -ReceivedDateTimeTo $qReceivedDateTimeTo
        Write-Host "Final KQL Query: $kqlQuery" -ForegroundColor Green

        $itemsFound = 0
        $mailboxCount = 0
        $legacyMatches = @()

        if ($SearchMode -eq 'Modern') {
            # 3. Create compliance search
            Write-Host "`n[Step 3] Creating compliance search '$SearchName'..."
            $search = New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery $kqlQuery
            $searchCreated = $true
            Write-Host "Compliance search created."
            Start-Sleep -Seconds $CmdDelaySeconds

            # 4. Start and wait for search to complete
            Write-Host "`n[Step 4] Starting compliance search (timeout: $QueryTimeoutMinutes minute(s))..."
            Start-ComplianceSearch -Identity $SearchName
            Start-Sleep -Seconds $CmdDelaySeconds

            $searchResult = Wait-ComplianceSearch -Identity $SearchName -TimeoutSeconds ($QueryTimeoutMinutes * 60)
            $itemsFound = $searchResult.Items

            if ($itemsFound -eq 0) {
                Write-Host "`nNo emails found matching the criteria. Exiting." -ForegroundColor Yellow
                Remove-ComplianceSearch -Identity $SearchName -Confirm:$false
                return
            }

            Write-Host "`nSearch complete. Found $itemsFound email(s)." -ForegroundColor Green

            # 4b. Preview: show affected mailboxes before deleting
            Write-Host "`n[Step 4b] Previewing matched items per mailbox..."
            $actionPreview = New-ComplianceSearchAction -SearchName $SearchName -Preview
            $SearchActionPreviewName = $actionPreview.Name
            Start-Sleep -Seconds $CmdDelaySeconds
            $preview = Get-ComplianceSearchAction -Identity $SearchActionPreviewName -Details

            # NOTE: this text-parses a free-text Results string with no documented stable
            # format. Treat this listing as a convenience, not ground truth - the full raw
            # payload is always written to $previewFile so you can cross-check it before
            # relying on this as your go/no-go for a delete.
            $rawResults = $preview.Results.Trim('{', '}').Trim()
            $entries = $rawResults -split ',\s*(?=Location:)'

            $rows = foreach ($entry in $entries) {
                $fields = @{}
                foreach ($part in ($entry.Trim() -split ';\s*')) {
                    if ($part -match '^([^:]+):\s*(.+)$') {
                        $fields[$Matches[1].Trim()] = $Matches[2].Trim()
                    }
                }
                [pscustomobject]@{
                    Mailbox  = $fields['Location']
                    Sender   = if ($qSenderEmail) { "$($fields['Sender']) <$qSenderEmail>" } else { $fields['Sender'] }
                    Subject  = $fields['Subject']
                    Received = $fields['Received Time']
                    Size     = $fields['Size']
                }
            }
            $mailboxCount = @($rows.Mailbox | Select-Object -Unique).Count

            $previewFile = Join-Path $PSScriptRoot "$SearchName`_preview.txt"
            $rows | Format-Table -AutoSize | Out-String -Width 300 | Set-Content -Path $previewFile
            Add-Content -Path $previewFile -Value "`n--- RAW PREVIEW PAYLOAD (ground truth) ---`n$($preview.Results)"

            Write-Host "`n  Matched emails ($($rows.Count)) across $mailboxCount mailbox(es)." -ForegroundColor Cyan
            Write-Host "  Full detail (and the raw payload) written to: $previewFile" -ForegroundColor Cyan
            Write-Host "  $('-' * 60)" -ForegroundColor Cyan

            if ($rows.Count -le $PreviewDisplayLimit) {
                $i = 1
                foreach ($row in $rows) {
                    Write-Host "  [$i] Mailbox  : $($row.Mailbox)"
                    Write-Host "      Sender   : $($row.Sender)"
                    Write-Host "      Subject  : $($row.Subject)"
                    Write-Host "      Received : $($row.Received)"
                    Write-Host "      Size     : $($row.Size) bytes"
                    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
                    $i++
                }
            }
            else {
                Write-Host "  $($rows.Count) items is above the inline display limit ($PreviewDisplayLimit) - showing a condensed summary grouped by sender + subject:" -ForegroundColor Yellow
                foreach ($group in ($rows | Group-Object -Property Sender, Subject)) {
                    $first = $group.Group[0]
                    $others = $group.Count - 1
                    Write-Host "  Sender  : $($first.Sender)"
                    Write-Host "  Subject : $($first.Subject)"
                    Write-Host "  Example : $($first.Mailbox)  (received $($first.Received), $($first.Size) bytes)"
                    if ($others -gt 0) {
                        Write-Host "            + $others other mailbox(es) with this same sender/subject" -ForegroundColor DarkGray
                    }
                    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
                }
            }
        }
        else {
            # Legacy mode: no single org-wide query cmdlet exists, so we loop per mailbox.
            # Search-Mailbox's -EstimateResultOnly only gives a per-mailbox item count, not
            # per-message sender/subject detail, so this can't be grouped the same way Modern
            # mode's preview is - it's a mailbox list, capped the same way for large hits.
            Write-Host "`n[Step 3-4] Running legacy Search-Mailbox preview across all mailboxes..."
            $legacyMatches = @(Invoke-LegacyMailboxPreview -SearchQuery $kqlQuery -TargetFolder $SearchName)
            $itemsFound = ($legacyMatches | Measure-Object -Property ItemCount -Sum).Sum
            if (-not $itemsFound) { $itemsFound = 0 }
            $mailboxCount = $legacyMatches.Count

            if ($itemsFound -eq 0) {
                Write-Host "`nNo emails found matching the criteria. Exiting." -ForegroundColor Yellow
                return
            }

            $previewFile = Join-Path $PSScriptRoot "$SearchName`_preview.txt"
            $legacyMatches | Format-Table -AutoSize | Out-String -Width 300 | Set-Content -Path $previewFile

            Write-Host "`nSearch complete. Found $itemsFound email(s) across $mailboxCount mailbox(es)." -ForegroundColor Green
            Write-Host "Full detail written to: $previewFile" -ForegroundColor Cyan
            Write-Host "`n  Matched mailboxes:" -ForegroundColor Cyan
            Write-Host "  $('-' * 60)" -ForegroundColor Cyan

            if ($legacyMatches.Count -le $PreviewDisplayLimit) {
                foreach ($row in $legacyMatches) {
                    Write-Host "  Mailbox : $($row.Mailbox)"
                    Write-Host "  Items   : $($row.ItemCount)"
                    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
                }
            }
            else {
                Write-Host "  $($legacyMatches.Count) mailboxes is above the inline display limit ($PreviewDisplayLimit) - showing the first $PreviewDisplayLimit, see the file above for the rest:" -ForegroundColor Yellow
                foreach ($row in ($legacyMatches | Select-Object -First $PreviewDisplayLimit)) {
                    Write-Host "  Mailbox : $($row.Mailbox)"
                    Write-Host "  Items   : $($row.ItemCount)"
                    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
                }
                Write-Host "  ...and $($legacyMatches.Count - $PreviewDisplayLimit) more mailbox(es) - see $previewFile" -ForegroundColor DarkGray
            }
        }

        if ($SearchOnly) {
            Write-Host "`n-SearchOnly was set - stopping here, no delete action will run." -ForegroundColor Green
            if ($SearchMode -eq 'Modern') {
                Write-Host "Compliance search '$SearchName' left in place for review. Remove it manually with:" -ForegroundColor Yellow
                Write-Host "  Remove-ComplianceSearch -Identity '$SearchName' -Confirm:`$false" -ForegroundColor Yellow
            }
            return
        }

        # 5. Confirm deletion with user
        Write-Host "`n[Step 5] Confirmation required..."
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "Delete Type: $DeleteType" -ForegroundColor Yellow
        Write-Host "Emails Found: $itemsFound" -ForegroundColor Yellow
        Write-Host "Mailboxes Affected: $mailboxCount" -ForegroundColor Yellow
        if ($DeleteType -eq 'Hard') {
            Write-Host "WARNING: Hard delete is PERMANENT and CANNOT be recovered!" -ForegroundColor Red
        }
        Write-Host "========================================" -ForegroundColor Yellow

        if (-not $Force) {
            $confirmation = Read-Host "`nDo you want to proceed with ${DeleteType} deletion? (y/n)"
            if ($confirmation -notin @('y', 'yes')) {
                Write-Host "Deletion cancelled by user." -ForegroundColor Yellow
                if ($SearchMode -eq 'Modern') { Remove-ComplianceSearch -Identity $SearchName -Confirm:$false }
                return
            }
        }

        # 5b. Overreach guardrail - large-impact / hard-delete runs need a typed token, not just "yes"
        Confirm-LargeImpact -ItemsFound $itemsFound -MailboxCount $mailboxCount -DeleteType $DeleteType `
            -ItemThreshold $LargeImpactItemThreshold -MailboxThreshold $LargeImpactMailboxThreshold -Force:$Force

        # 6. Perform deletion
        Write-Host "`n[Step 6] Starting ${DeleteType} delete action..."

        if ($SearchMode -eq 'Modern') {
            $purgeType = if ($DeleteType -eq 'Hard') { 'HardDelete' } else { 'SoftDelete' }
            if ($DeleteType -eq 'Hard') {
                try {
                    if (-not $Force) {
                        $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $purgeType -ErrorAction Stop
                    } else {
                        $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $purgeType -Confirm:$false -ErrorAction Stop
                    }
                } catch {
                    if ($_ -match 'HardDelete') {
                        Write-Host "Hard delete is not supported on this Exchange server (HardDelete is Exchange Online only). Re-run with -DeleteType Soft." -ForegroundColor Red
                        Remove-ComplianceSearch -Identity $SearchName -Confirm:$false
                        return
                    }
                    throw
                }
            } else {
                if (-not $Force) {
                    $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $purgeType
                } else {
                    $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $purgeType -Confirm:$false
                }
            }
            $SearchActionName = $action.Name
            Write-Host "Delete action initiated: $SearchActionName"
            Start-Sleep -Seconds $CmdDelaySeconds

            # 7. Wait for deletion to complete
            Write-Host "`n[Step 7] Waiting for delete action to complete (timeout: 20 minute(s))..."
            $actionResult = Wait-ComplianceSearchAction -ActionIdentity $SearchActionName -TimeoutSeconds $MaxActionWaitSeconds

            Write-Host "`nDeletion complete!" -ForegroundColor Green
            Write-Host "Results: $($actionResult.Results)" -ForegroundColor Green

            # 8. Cleanup
            Write-Host "`n[Step 8] Cleaning up search..."
            Remove-ComplianceSearch -Identity $SearchName -Confirm:$false
            Write-Host "Compliance search removed."
        }
        else {
            # Legacy mode: Search-Mailbox -DeleteContent only supports soft-delete-equivalent
            # behavior (items move to Recoverable Items), enforced earlier in Get-SearchImplementation.
            Write-Host "`n[Step 7] Deleting matched items via Search-Mailbox across $mailboxCount mailbox(es)..."
            Invoke-LegacyMailboxDelete -SearchQuery $kqlQuery -TargetFolder $SearchName -MatchedMailboxes $legacyMatches
            Write-Host "`nDeletion complete!" -ForegroundColor Green
        }

        Write-Host "`n======================================" -ForegroundColor Green
        Write-Host "Operation completed successfully!" -ForegroundColor Green
        Write-Host "======================================" -ForegroundColor Green
    }
    catch {
        if ($SearchMode -eq 'Modern' -and $searchCreated) {
            Remove-ComplianceSearchWithReport -Identity $SearchName
        }
        throw
    }
}


$Session = $null
$SearchMode = $null
$IsEXO = $false

try {
    # Start a transcript for this run so the whole session (console output,
    # Write-Host, and errors as they're hit) is captured to disk for later
    # review, independent of the per-search preview files above. Wrapped so a
    # transcript failure (permissions, already-transcribing, etc.) is a
    # warning, not a reason to abort the actual work.
    try {
        Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null
        Write-Host "Logging this session to: $LogFile" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "WARNING: Could not start transcript logging ($_). Continuing without a log file." -ForegroundColor Yellow
    }

    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "Exchange Compliance Search & Delete (v$ScriptVersion)" -ForegroundColor Cyan
    if ($SearchOnly) { Write-Host "MODE: SEARCH ONLY - no delete action will run" -ForegroundColor Green }
    Write-Host "======================================" -ForegroundColor Cyan

    if ($CheckForUpdates) {
        Test-ScriptVersionCurrent -CurrentVersion $ScriptVersion -Url $UpdateCheckUrl -TimeoutSeconds $UpdateCheckTimeoutSeconds
    }

    # 0. Connect and authenticate
    Write-Host "`n[Step 0] Connecting to Exchange..."
    $connection = Connect-ExchangeSession -Server $Server -Credential $Credential -UseSSL:$UseSSL
    $Session = $connection.Session
    $IsEXO = $connection.IsEXO
    # Connect-ExchangeSession prompts for credentials itself when none were bound;
    # capture the resolved credential so downstream permission checks know who connected.
    $Credential = $connection.Credential

    # 0b. Work out which search cmdlets this server supports
    Write-Host "`n[Step 0b] Checking search capability..."
    $SearchMode = Get-SearchImplementation -DeleteType $DeleteType -SearchOnly:$SearchOnly

    # 0c. Confirm the connecting account can actually do what's being asked
    Write-Host "`n[Step 0c] Checking permissions..."
    Test-RequiredPermissions -Mode $SearchMode -Credential $Credential -DeleteRequested:(-not $SearchOnly)

    # 0d. Flag a known correlate of "Failed to retrieve executing user" (on-prem
    # only - see the long comment on Test-ExecutingUserMailbox for the full
    # incident history behind this check).
    Write-Host "`n[Step 0d] Checking executing account mailbox status..."
    $accountNameForMailboxCheck = $Credential.UserName
    if ($accountNameForMailboxCheck -match '\\(.+)$') { $accountNameForMailboxCheck = $Matches[1] }
    elseif ($accountNameForMailboxCheck -match '^(.+)@') { $accountNameForMailboxCheck = $Matches[1] }
    Test-ExecutingUserMailbox -AccountName $accountNameForMailboxCheck -IsEXO:$IsEXO

    # 1+. Run a search, then offer to run another with the same session (no re-auth needed).
    # CLI-bound criteria (-MessageID/-SenderEmail/etc.) only ever apply to this first run;
    # every subsequent search in the same session goes through the interactive menu.
    $isFirstRun = $true
    do {
        Invoke-EmailSearchAndDelete -SearchMode $SearchMode -BoundParameterSetName $PSCmdlet.ParameterSetName -IsEXO:$IsEXO -UseBoundCriteria:$isFirstRun
        $isFirstRun = $false

        $again = Read-Host "`nRun another search with this session? (y/n)"
        $runAnother = ($again -in @('y', 'yes'))
        if ($runAnother) {
            Write-Host "`n======================================" -ForegroundColor Cyan
            Write-Host "Starting another search (same session)" -ForegroundColor Cyan
            Write-Host "======================================" -ForegroundColor Cyan
        }
    } while ($runAnother)

}
catch {
    Write-Error "Fatal error: $_`n$($_.ScriptStackTrace)"
    exit 1
}
finally {
    # Flip the GLOBAL $VerbosePreference (not a local/script-scope copy) - same reason as in
    # Connect-ExchangeSession: tearing down the ~800 proxied functions happens inside a
    # different module's own scope, which falls back to the true global value, not this
    # script's local one. Without this it dumps a "Removing the imported ... function"
    # line for every one of them.
    $previousVerbosePreference = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'
    if ($IsEXO) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    }
    elseif ($Session) {
        Remove-PSSession $Session -ErrorAction SilentlyContinue
    }
    $global:VerbosePreference = $previousVerbosePreference

    # Stop-Transcript last, so it also captures the disconnect/cleanup messages above.
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}