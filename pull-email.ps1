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

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

$MaxSearchWaitSeconds = 600  # 10 minutes
$MaxActionWaitSeconds = 1200 # 20 minutes
$QueryTimeoutMinutes = 30
$CmdDelaySeconds = 5

# Overreach guardrail thresholds - above these, a "large impact" typed-token
# confirmation is required instead of a plain yes/no (see Confirm-LargeImpact).
$LargeImpactItemThreshold = 25
$LargeImpactMailboxThreshold = 10

# Above this many matched rows, the console preview switches from a full
# per-item listing to a condensed sender+subject summary (full detail always
# still goes to the preview file - a 1,000-mailbox hit is unreadable dumped
# straight to the console).
$PreviewDisplayLimit = 20

# On-prem compliance search / Search-Mailbox have no "messageid" KQL property
# (that field is Exchange Online-only) - a -MessageID search is resolved via
# message tracking logs first (see Resolve-MessageIdToCriteria). These control
# how far back to look, and how wide a date window to build around the result.
# Not used at all when connected to Exchange Online (EXO) - messageid: works
# there directly.
$MessageTrackingLookbackDays = 30
$MessageIdDateWindowHours = 12


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
        Import-Module ExchangeOnlineManagement -ErrorAction Stop -Verbose:$false

        $upn = if ($Credential) { $Credential.UserName } else { Read-Host "Exchange Online admin UPN (e.g. admin@contoso.onmicrosoft.com)" }
        if (-not $upn) {
            Write-Error "A UPN is required to connect to Exchange Online."
        }

        Write-Host "Connecting to Exchange Online (Security & Compliance PowerShell) as $upn - a sign-in prompt may appear..." -ForegroundColor Cyan
        Connect-IPPSSession -UserPrincipalName $upn -WarningAction SilentlyContinue -Verbose:$false -ErrorAction Stop

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
    # Import-PSSession's internal module-import step dumps an Exporting/Importing line for
    # every one of the ~800 proxied Exchange cmdlets under the script-wide $VerbosePreference
    # = 'Continue' - and it does this regardless of -Verbose:$false on the call itself, so
    # the preference variable has to be flipped directly for these two calls to actually quiet it.
    $previousVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
    try {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $connectionUri -Authentication Kerberos -Credential $Credential -ErrorAction Stop

        Import-PSSession $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
    }
    finally {
        $VerbosePreference = $previousVerbosePreference
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

    if ($MessageID) {
        # Message-ID search (most specific)
        # KQL: internetmessageid:"<exact-id>"
        $queryParts += "(MessageId:""$MessageID"")"
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
                $dateFromStr = $dtFrom.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $dtTo = [datetimeoffset]::Parse($ReceivedDateTimeTo)
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


function Wait-ComplianceSearch {
    param(
        [string]$Identity,
        [int]$TimeoutSeconds = 600
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
            Write-Host "`nExchange Online supports Message-ID search directly - searching for exactly this message." -ForegroundColor Green
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
            $confirmation = Read-Host "`nDo you want to proceed with ${DeleteType} deletion? (yes/no)"
            if ($confirmation -ne 'yes') {
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
        if ($SearchMode -eq 'Modern') {
            try { Remove-ComplianceSearch -Identity $SearchName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
        }
        throw
    }
}


$Session = $null
$SearchMode = $null
$IsEXO = $false

try {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "Exchange Compliance Search & Delete" -ForegroundColor Cyan
    if ($SearchOnly) { Write-Host "MODE: SEARCH ONLY - no delete action will run" -ForegroundColor Green }
    Write-Host "======================================" -ForegroundColor Cyan

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

    # 1+. Run a search, then offer to run another with the same session (no re-auth needed).
    # CLI-bound criteria (-MessageID/-SenderEmail/etc.) only ever apply to this first run;
    # every subsequent search in the same session goes through the interactive menu.
    $isFirstRun = $true
    do {
        Invoke-EmailSearchAndDelete -SearchMode $SearchMode -BoundParameterSetName $PSCmdlet.ParameterSetName -IsEXO:$IsEXO -UseBoundCriteria:$isFirstRun
        $isFirstRun = $false

        $again = Read-Host "`nRun another search with this session? (yes/no)"
        $runAnother = ($again -eq 'yes')
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
    # Flip $VerbosePreference directly (not just -Verbose:$false) - same reason as in
    # Connect-ExchangeSession: tearing down the ~800 proxied functions otherwise dumps a
    # "Removing the imported ... function" line for every one of them.
    $previousVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
    if ($IsEXO) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    }
    elseif ($Session) {
        Remove-PSSession $Session -ErrorAction SilentlyContinue
    }
    $VerbosePreference = $previousVerbosePreference
}
