# pull-email.ps1

Searches for a specific email (or a set of matching emails) across mailboxes and, after review, soft- or hard-deletes it.

Supports both **Exchange Online** and **on-premises Exchange**, automatically detecting the best search implementation available in the connected environment.

Built primarily for incident response—such as removing a phishing email or a misdirected message after it has already reached user mailboxes—the default search scope is organisation-wide. Multiple guardrails are built in to minimise the risk of accidental broad searches or deletions.

> [!WARNING]
> This script is capable of searching and deleting email across every mailbox in an Exchange organisation. Always run with `-SearchOnly` first unless you are completely confident your search criteria only match the intended messages.

---

# Features

* Supports Exchange Online and on-premises Exchange
* Automatically detects Modern (`New-ComplianceSearch`) or Legacy (`Search-Mailbox`) search capabilities
* Interactive and fully scriptable operation
* Search by:

  * Message-ID
  * Sender
  * Recipient
  * Subject
  * Body text or URL
  * Received date range
* Search-only preview mode
* Soft Delete and Hard Delete support (where supported)
* Automatic RBAC permission validation
* Query safety validation to prevent overly broad searches
* Preview matched items before deletion
* Large-impact confirmation safeguards
* Reuses the existing Exchange session for multiple searches without reconnecting

---

# Compatibility

| Platform                  | Support                        |
| ------------------------- | ------------------------------ |
| Exchange Online           | Fully supported                |
| Exchange Server 2019      | Modern mode                    |
| Exchange Server 2016 CU7+ | Modern mode                    |
| Exchange Server 2013      | Legacy mode (`Search-Mailbox`) |
| Exchange Server 2010      | Legacy mode (`Search-Mailbox`) |

The script does **not** rely on Exchange version detection. Instead, it detects the available Exchange cmdlets at runtime and automatically selects the newest supported search implementation.

---

# Prerequisites

## Common

* Windows PowerShell 5.1 is recommended (matches Exchange Management Shell compatibility).
* PowerShell 7+ works for the Exchange Online path but has not been extensively tested against on-premises remote PowerShell.
* An Exchange account with the required RBAC role assignments (see **Permissions** below).

The script validates permissions before beginning any search and will fail immediately with guidance if required roles are missing.

---

## On-premises Exchange

* Network and WinRM connectivity to the target Exchange server.
* Ability to establish remote Exchange Management Shell sessions using Kerberos authentication.
* Exchange 2016 CU7 or later for Modern mode (`New-ComplianceSearch`).
* Earlier supported versions automatically fall back to Legacy mode (`Search-Mailbox`).

### Legacy mode

A **Discovery Search Mailbox** must already exist.

The script checks for this automatically and, if missing, provides the `New-Mailbox -Discovery` command required to create one.

---

## Exchange Online

Install the Exchange Online Management module:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

Authentication uses **Microsoft Modern Authentication**, including MFA and Conditional Access policies.

---

# Permissions

The connecting account requires Exchange RBAC roles appropriate for the requested operation.

| Operation | On-premises                                 | Exchange Online     |
| --------- | ------------------------------------------- | ------------------- |
| Search    | `Mailbox Search` and/or `Compliance Search` | `Compliance Search` |
| Delete    | `Mailbox Import Export` (Legacy mode only)  | `Search And Purge`  |

In most environments this is achieved by membership of:

* **Discovery Management** (on-premises)
* An appropriate Microsoft 365 eDiscovery / Compliance role group (Exchange Online)

On-premises, the script validates the exact role assignment (`Get-ManagementRoleAssignment`)
before performing any search. **Exchange Online's Security & Compliance PowerShell session
doesn't expose that cmdlet at all** - RBAC there is managed through the Purview compliance
portal, not this session - so for EXO the script instead does a basic capability check
(`Get-ComplianceSearch -ResultSize 1`) to confirm the account can at least reach compliance
search. This does not confirm the `Search And Purge` role specifically; if a delete action
fails with an authorization error, check for that role in the Purview compliance portal.

---

# Usage

## Interactive (recommended)

```powershell
.\pull-email.ps1
```

You'll be prompted for:

1. Exchange server (FQDN or `EXO`)
2. Credentials
3. Search criteria
4. Delete confirmation (if applicable)

After completing a search, the script offers to perform additional searches using the same Exchange session, avoiding repeated authentication.

---

## Scripted

```powershell
# Search only

.\pull-email.ps1 `
    -Server mail.contoso.local `
    -SenderEmail phish@evil.com `
    -Subject "Invoice overdue" `
    -ReceivedDateTimeFrom 2026-07-28 `
    -ReceivedDateTimeTo 2026-07-30 `
    -SearchOnly

# Soft delete

.\pull-email.ps1 `
    -Server mail.contoso.local `
    -Credential $cred `
    -SenderEmail phish@evil.com `
    -Subject "Invoice overdue" `
    -ReceivedDateTimeFrom 2026-07-28 `
    -ReceivedDateTimeTo 2026-07-30

# Exchange Online hard delete

.\pull-email.ps1 `
    -Server EXO `
    -MessageID "<abc123@contoso.com>" `
    -DeleteType Hard `
    -Force
```

`-Force` suppresses the standard yes/no confirmation prompts but does **not** bypass the large-impact confirmation token required for high-impact operations.

---

# Parameters

| Parameter                                       | Description                                                                            |
| ----------------------------------------------- | -------------------------------------------------------------------------------------- |
| `-Server`                                       | Exchange server FQDN or `EXO`.                                                         |
| `-Credential`                                   | PSCredential for on-premises Exchange. Ignored for EXO except to pre-populate the UPN. |
| `-UseSSL`                                       | Uses HTTPS instead of HTTP for the remote PowerShell endpoint.                         |
| `-MessageID`                                    | Exact Message-ID search.                                                               |
| `-SenderEmail`                                  | Sender address.                                                                        |
| `-RecipientEmail`                               | Searches To/Cc/Bcc.                                                                    |
| `-Subject`                                      | Subject contains. On-premises full-text indexing ignores trailing numbers.             |
| `-BodyContains`                                 | Body text or URL contains.                                                             |
| `-ReceivedDateTimeFrom` / `-ReceivedDateTimeTo` | Date range (`yyyy-MM-dd` or `yyyy-MM-dd HH:mm:ss`), interpreted in the local machine's time zone. A date given without a time (e.g. just `2026-07-26`) is treated as the start of that day for `-From` and the *end* of that day for `-To` - so the same date on both ends covers the whole day, not a single instant. The resolved range is echoed back in local time before the search runs so you can confirm it matches what you expect. |
| `-DeleteType`                                   | `Soft` (default) or `Hard`. Hard Delete is Exchange Online only.                       |
| `-SearchOnly`                                   | Preview results without deleting anything.                                             |
| `-Force`                                        | Skips standard confirmation prompts.                                                   |

---

# Guardrails

Because the script searches the entire organisation, several safeguards are built in.

* Criteria-based searches must specify both **who** (sender and/or recipient) and **what/when** (subject, body text, or date range).
* Message-ID searches are exempt, as they are already highly specific.
* Every delete operation is preceded by a preview.
* Large-impact operations (more than 25 items or 10 mailboxes) require typing a randomly generated confirmation token.
* Hard Delete operations always require the large-impact confirmation.
* Required RBAC permissions are validated before any search begins.

---

# Output

Preview results are written to the script directory as:

```
ComplianceSearch_<timestamp>_preview.txt
```

For large result sets, the console displays a condensed summary while the preview file always contains the complete output and the raw compliance search payload.

---

# Message-ID behaviour

### Exchange Online

Uses native Message-ID searching via the Exchange Online compliance search engine.

### On-premises Exchange

Because on-premises Exchange does not support Message-ID as a KQL property, the script automatically:

1. Searches message tracking logs.
2. Resolves the sender, subject and timestamp.
3. Builds a narrow criteria search using a ±12-hour window.

Resolution will fail if:

* the tracking logs no longer contain the message,
* the message never traversed on-premises transport (for example, Exchange Online mailboxes in a hybrid deployment).

---

# Legacy mode limitations

Legacy mode uses `Search-Mailbox`, which has several inherent limitations:

* Searches each mailbox individually rather than organisation-wide.
* Supports only soft-delete behaviour.
* Cannot preview individual message details—only mailbox and item counts.
* Generally performs more slowly in larger environments.

---

# Cleanup behaviour

Compliance searches created during normal operation are automatically removed after completion or on most failure paths.

When `-SearchOnly` is used, compliance searches are intentionally left in place so administrators can inspect them before manual cleanup.

---

# What this script does not do

This utility only searches for and removes email content.

It does **not**:

* disable user accounts
* remove inbox rules
* quarantine messages
* modify transport rules
* perform Purview eDiscovery exports
* modify Defender for Office 365 policies

---

# Validation

Although the script includes extensive validation and defensive checks, it should always be exercised with `-SearchOnly` against a known test message before being relied upon during an incident.

As with any organisation-wide delete tool, testing in a non-production environment is strongly recommended before first production use.
