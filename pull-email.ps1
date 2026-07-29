[CmdletBinding(DefaultParameterSetName = 'MessageID')]
param(
    [Parameter(ParameterSetName = 'MessageID')]
    [ValidateNotNullOrEmpty()]
    [string]$MessageID,

    [Parameter(ParameterSetName = 'Criteria')]
    [ValidateNotNullOrEmpty()]
    [string]$SenderEmail,

    [Parameter(ParameterSetName = 'Criteria')]
    [string]$Subject,

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

$SearchName = "ComplianceSearch_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$MaxSearchWaitSeconds = 600  # 10 minutes
$MaxActionWaitSeconds = 1200 # 20 minutes
$QueryTimeoutMinutes = 30
$CmdDelaySeconds = 5


function New-ComplianceSearchQuery {
    param(
        [string]$MessageID,
        [string]$SenderEmail,
        [string]$Subject,
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

        if ($Subject) {
            $queryParts += "(subject:""$Subject"")"
            Write-Host "`nNOTE: On-premises Exchange subject search uses full-text indexing. Trailing numbers are ignored (e.g. 'Invoice payment 2027' matches any subject containing 'Invoice payment'). Numbers at the start or middle of the subject work correctly. No KQL escape exists for this. Use a narrow ReceivedDateTime range to avoid false matches.`n" -ForegroundColor Yellow
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


try {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "Exchange Compliance Search & Delete" -ForegroundColor Cyan
    if ($SearchOnly) { Write-Host "MODE: SEARCH ONLY - no delete action will run" -ForegroundColor Green }
    Write-Host "======================================" -ForegroundColor Cyan

    # 1. Validate input
    Write-Host "`n[Step 1] Validating input parameters..."
    if ($PSCmdlet.ParameterSetName -eq 'MessageID' -and -not $MessageID) {
        Write-Error "MessageID is required when using the MessageID parameter set. Example: .\pull-email-fixed.ps1 -MessageID '<abc123@contoso.com>' -SearchOnly"
    }
    if ($PSCmdlet.ParameterSetName -eq 'Criteria' -and -not ($SenderEmail -or $Subject -or $ReceivedDateTimeFrom -or $ReceivedDateTimeTo)) {
        Write-Error "At least one of SenderEmail, Subject, or ReceivedDateTimeFrom/ReceivedDateTimeTo must be provided when using the Criteria parameter set."
    }

    # 2. Build KQL query
    Write-Host "`n[Step 2] Building compliance search query..."
    $kqlQuery = New-ComplianceSearchQuery -MessageID $MessageID -SenderEmail $SenderEmail -Subject $Subject -ReceivedDateTimeFrom $ReceivedDateTimeFrom -ReceivedDateTimeTo $ReceivedDateTimeTo
    Write-Host "Final KQL Query: $kqlQuery" -ForegroundColor Green

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
        exit 0
    }

    Write-Host "`nSearch complete. Found $itemsFound email(s)." -ForegroundColor Green

    # 4b. Preview: show affected mailboxes before deleting
    Write-Host "`n[Step 4b] Previewing matched items per mailbox..."
    $actionPreview = New-ComplianceSearchAction -SearchName $SearchName -Preview
    $SearchActionPreviewName = $actionPreview.Name
    Start-Sleep -Seconds $CmdDelaySeconds
    $preview = Get-ComplianceSearchAction -Identity $SearchActionPreviewName -Details

    # NOTE: this text-parses a free-text Results string with no documented stable
    # format. Treat this listing as a convenience, not ground truth - cross-check
    # $preview.Results directly (Write-Host it, or dump to a file) before you rely
    # on it as your go/no-go for a delete.
    $rawResults = $preview.Results.Trim('{', '}').Trim()
    $entries = $rawResults -split ',\s*(?=Location:)'
    Write-Host "`n  Matched emails ($($entries.Count)):" -ForegroundColor Cyan
    Write-Host "  $('-' * 60)" -ForegroundColor Cyan
    $i = 1
    foreach ($entry in $entries) {
        $fields = @{}
        foreach ($part in ($entry.Trim() -split ';\s*')) {
            if ($part -match '^([^:]+):\s*(.+)$') {
                $fields[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        $senderDisplay = if ($SenderEmail) { "$($fields['Sender']) <$SenderEmail>" } else { $fields['Sender'] }
        Write-Host "  [$i] Mailbox  : $($fields['Location'])"
        Write-Host "      Sender   : $senderDisplay"
        Write-Host "      Subject  : $($fields['Subject'])"
        Write-Host "      Received : $($fields['Received Time'])"
        Write-Host "      Size     : $($fields['Size']) bytes"
        Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
        $i++
    }

    Write-Host "`nRaw preview payload (ground truth, cross-check against the parsed list above):" -ForegroundColor DarkGray
    Write-Host $preview.Results -ForegroundColor DarkGray

    if ($SearchOnly) {
        Write-Host "`n-SearchOnly was set - stopping here, no delete action will run." -ForegroundColor Green
        Write-Host "Compliance search '$SearchName' left in place for review. Remove it manually with:" -ForegroundColor Yellow
        Write-Host "  Remove-ComplianceSearch -Identity '$SearchName' -Confirm:`$false" -ForegroundColor Yellow
        exit 0
    }

    # 5. Confirm deletion with user
    Write-Host "`n[Step 5] Confirmation required..."
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "Delete Type: $DeleteType" -ForegroundColor Yellow
    Write-Host "Emails Found: $itemsFound" -ForegroundColor Yellow
    if ($DeleteType -eq 'Hard') {
        Write-Host "WARNING: Hard delete is PERMANENT and CANNOT be recovered!" -ForegroundColor Red
    }
    Write-Host "========================================" -ForegroundColor Yellow

    if (-not $Force) {
        $confirmation = Read-Host "`nDo you want to proceed with ${DeleteType} deletion? (yes/no)"
        if ($confirmation -ne 'yes') {
            Write-Host "Deletion cancelled by user." -ForegroundColor Yellow
            Remove-ComplianceSearch -Identity $SearchName -Confirm:$false
            exit 0
        }
    }

    # 6. Perform deletion
    Write-Host "`n[Step 6] Starting ${DeleteType} delete action..."
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
                exit 1
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

    Write-Host "`n======================================" -ForegroundColor Green
    Write-Host "Operation completed successfully!" -ForegroundColor Green
    Write-Host "======================================" -ForegroundColor Green

}
catch {
    Write-Error "Fatal error: $_`n$($_.ScriptStackTrace)"

    Write-Host "`nAttempting cleanup..." -ForegroundColor Yellow
    try {
        Remove-ComplianceSearch -Identity $SearchName -Confirm:$false
    }
    catch { }

    exit 1
}