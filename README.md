# pull-email.ps1

**Current version: 1.4.0** (printed in the script's own startup banner - check that matches this file if in doubt which copy you're running).

Searches for a specific email (or a set of matching emails) across mailboxes and, after review, soft- or hard-deletes it.

Supports both **Exchange Online** and **on-premises Exchange**, automatically detecting the best search implementation available in the connected environment.

Built primarily for incident response—such as removing a phishing email or a misdirected message after it has already reached user mailboxes—the default search scope is organisation-wide. Multiple guardrails are built in to minimise the risk of accidental broad searches or deletions.

> [!WARNING]
> This script is capable of searching and deleting email across every mailbox in an Exchange organisation. Always run with `-SearchOnly` first unless you are completely confident your search criteria only match the intended messages.

# Disclaimer

**The fine print:** this script is provided as-is. No warranty. No guarantees. No magical safety net. If it summons an eldritch Exchange demon that's been lurking since the 2010 migration, that's on you.

It's been tested in a real hybrid Exchange environment and behaved itself. Your environment, however, may have been lovingly assembled over 15 years by six different admins, three MSPs, a consultant who disappeared mid-project, and Steve from Finance who somehow got Domain Admin in 2017. Results may vary.

Before you run it:

* Read the code.
* Use `-SearchOnly`.
* Read the output.
* Think about your life choices.
* Then, and only then, let it loose.

Don't just download a random PowerShell script from the internet, mash Enter a few times, and hope for the best. That's how you end up explaining to management why Karen's mailbox now contains the square root of fuck all.

No support is included, implied, or available. If it explodes, your first ports of call are:

* Your backups.
* Your senior sysadmin.
* The nearest pub.

If none of those help, congratulations—you've probably just discovered a brand new Exchange feature.

By running this script, you acknowledge that you are the one behind the keyboard. You're responsible for checking what it does, where it runs, and what it deletes. If you ignore `-SearchOnly`, fire it at Production on a Friday afternoon, and immediately regret your decisions, that's a valuable learning experience.

The author accepts no responsibility for lost mail, broken environments, emergency CAB meetings, uncomfortable conversations with management, or any increase in alcohol consumption resulting from use of this script.

**You've been warned. Send it.**

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
* Full session transcript logged to disk automatically
* Automatic RBAC permission validation
* Proactive warning if the executing account lacks an on-prem mailbox (see [Known gaps](#known-gaps))
* Query safety validation to prevent overly broad criteria-based searches
* Automatic abort of a search that's still running once it crosses a runaway-item threshold, rather than left to run to timeout
* Preview matched items before deletion
* Large-impact confirmation safeguards
* Reuses the existing Exchange session for multiple searches without reconnecting
* Optional, opt-in check for a newer version on first run (`-CheckForUpdates`) - never auto-downloads, just tells you and links to the repo

---

# Compatibility

| Platform                  | Support                        |
| ------------------------- | ------------------------------- |
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
* **On-premises only:** the account also needs its own on-prem mailbox - see [Known gaps](#known-gaps) for why.

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

Install the Exchange Online Management module, **version 3.9.0 or later** (needed for the `-EnableSearchOnlySession` connection flag the script relies on - older versions will fail when starting a compliance search over the newer REST-based backend):

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

Authentication uses **Microsoft Modern Authentication**, including MFA and Conditional Access policies. The script opens **two** sessions under the hood for EXO: the Security & Compliance session (`Connect-IPPSSession`, for the actual search/delete cmdlets) and a second, narrowly-scoped `Connect-ExchangeOnline` session limited to just the message-trace cmdlets (`Get-MessageTrace`/`Get-MessageTraceV2`/etc., used only to resolve `-MessageID` searches - see below). Expect an auth prompt, or a silent token reuse, for each.

---

# Permissions

The connecting account requires Exchange RBAC roles appropriate for the requested operation.

| Operation | On-premises                                 | Exchange Online     |
| --------- | ------------------------------------------- | -------------------- |
| Search    | `Mailbox Search` and/or `Compliance Search` | `Compliance Search`  |
| Delete    | `Mailbox Import Export` (Legacy mode only)  | `Search And Purge`   |

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

**Note:** more RBAC roles is not always better. An over-provisioned on-prem admin account can
fail in ways a normally-scoped account won't - see [Known gaps](#known-gaps).

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

For the date range specifically, you can either give an exact from/to range, or just answer "received in the last N days" for a quick relative filter - leave that blank to fall through to the exact from/to prompts instead.

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
| ------------------------------------------------ | ---------------------------------------------------------------------------------------- |
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
| `-CheckForUpdates`                              | Opt-in only. Compares the running version against the copy at [github.com/t-d-knight/pull-email-exchange-onprem](https://github.com/t-d-knight/pull-email-exchange-onprem) (`$UpdateCheckUrl`, already pointed at this repo's `main` branch) and prints a one-line notice if newer is available. Never downloads or replaces anything. 3-second timeout, fails completely silently on any error (no internet, proxy, GitHub down, etc.) - can never block or fail an actual run. |
| `-Force`                                        | Skips standard confirmation prompts.                                                   |

---

# Guardrails

Because the script searches the entire organisation, several safeguards are built in.

* Criteria-based searches must specify both **who** (sender and/or recipient) and **what/when** (subject, body text, or date range).
* Message-ID searches are exempt, as they are already highly specific - see [Message-ID behaviour](#message-id-behaviour) for why they still can't be trusted as a raw filter.
* Every delete operation is preceded by a preview.
* Large-impact operations (more than 25 items or 10 mailboxes) require typing a randomly generated confirmation token.
* Hard Delete operations always require the large-impact confirmation.
* Required RBAC permissions are validated before any search begins.
* The executing account is checked for an on-prem mailbox before any search begins (warning only, not a hard block - see [Known gaps](#known-gaps)).
* **Runaway-search abort**: while a search is still running, if it's already matched more than 50,000 items it's stopped and aborted automatically rather than left to run out its full timeout - that many matches almost always means a malformed or unsupported query clause silently turned into an unfiltered, organisation-wide scan rather than a genuine result set.

---

# Output

Preview results are written to the script directory as:

```
ComplianceSearch_<timestamp>_preview.txt
```

For large result sets, the console displays a condensed summary while the preview file always contains the complete output and the raw compliance search payload.

The entire console session is also transcribed automatically to:

```
ComplianceSearch_<timestamp>_log.txt
```

One log file per script *run*, not per search - if you use the "run another search?" loop, every search in that session lands in the same log. If logging can't start (permissions, already-transcribing session, etc.) the script prints a warning and continues without it rather than aborting the actual work.

---

# Message-ID behaviour

Compliance search does not index message headers - Message-ID cannot be searched directly as a query filter in **either** on-premises Exchange or Exchange Online. An unrecognized `MessageId:` clause is silently dropped rather than erroring, which turns what looks like a single-message search into an unfiltered, organisation-wide scan instead (confirmed in production: 90M+ items matched, 30-minute timeout, against a search meant to hit exactly one email). Because of this, a `-MessageID` search is **always** resolved to a sender + subject + date-window search before any compliance search is ever created - the script never trusts `MessageId:` as a real filter, in either environment.

### On-premises Exchange

1. Searches message tracking logs across all transport servers.
2. Resolves the sender, subject and timestamp.
3. Builds a narrow criteria search using a ±12-hour window.

Resolution will fail if:

* the tracking logs no longer contain the message,
* the message never traversed on-premises transport (for example, Exchange Online mailboxes in a hybrid deployment),
* the Message-ID value itself is incorrect.

### Exchange Online

1. Runs a message trace (`Get-MessageTraceV2`, falling back to `Get-MessageTrace`) for the given Message-ID.
2. Resolves the sender, subject and received timestamp from the earliest matching trace row.
3. Builds a narrow criteria search using the same ±12-hour window.

This requires the second, message-trace-only `Connect-ExchangeOnline` session mentioned under **Prerequisites > Exchange Online** above - `Connect-IPPSSession` alone does not expose these cmdlets. Confirmed working as of v1.3.0.

---

# Legacy mode limitations

Legacy mode uses `Search-Mailbox`, which has several inherent limitations:

* Searches each mailbox individually rather than organisation-wide.
* Supports only soft-delete behaviour.
* Cannot preview individual message details—only mailbox and item counts.
* Generally performs more slowly in larger environments.

---

# Cleanup behaviour

Compliance searches created during normal operation are removed automatically after completion. On a failure or an abort (including the runaway-search abort above), the script stops the search first - in case it's still actively running, which can prevent a straight removal - then removes it, and explicitly tells you whether that cleanup actually succeeded. If cleanup fails, you'll see a clear warning telling you to check its status manually rather than the script silently leaving it behind. If the search was never actually created (e.g. Message-ID resolution failed before `New-ComplianceSearch` ran), the script correctly skips the cleanup attempt entirely rather than throwing a confusing secondary error about a search that doesn't exist (fixed in v1.3.0).

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

# Known gaps

Honest list of things this script currently does **not** do, despite being the kind of thing you'd want in an incident-response tool. Not hidden in a changelog - called out here on purpose.

* **"Failed to retrieve executing user" has two unrelated causes that look identical**, both confirmed in production against different on-prem orgs:
  1. The org-wide Discovery/arbitration mailbox (`SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}`) is missing or broken - fails for *every* account on that org. Fix: `Setup.exe /PrepareAD` (change-window territory).
  2. The executing account has no on-prem mailbox - fails for *that account only*, regardless of RBAC roles held (confirmed: an account with Organization Management still failed while a normally-scoped account on the same server succeeded). Fix: use or provision an account with a mailbox.

  The script warns about cause #2 at connect time (Step 0d) but can't detect cause #1 in advance - if the warning doesn't fire and you still hit this error, check whether it's account-specific (try a second account on the same server) before reaching for `/PrepareAD`.

---

# Validation

Although the script includes extensive validation and defensive checks, it should always be exercised with `-SearchOnly` against a known test message before being relied upon during an incident.

As with any organisation-wide delete tool, testing in a non-production environment is strongly recommended before first production use.