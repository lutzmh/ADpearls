# finduser

Finds an Active Directory user across configured domains by userid (samaccountname),
SMTP/UPN address, objectGUID (registry or immutable/base64 form), or objectSid. The
script auto-detects which format you passed in.

## Requirements

- Windows PowerShell with the **ActiveDirectory** module (RSAT), enforced via
  `#Requires -Modules ActiveDirectory` at the top of the script.
- Network line of sight to a domain controller for each domain in `config.xml`.

## Permissions

- Read access to user objects in each target domain. Default AD "Authenticated Users"
  read rights are normally sufficient for the attributes this script queries
  (`objectGUID`, `objectSid`, `cn`, `displayname`, `employeeid`, `mail`,
  `samaccountname`, `userprincipalname`, `msExchMasterAccountSid`,
  `lastLogonTimestamp`).
- No write access is required or used.

To verify permissions on a given account, run a search (see below) against a known
test user in each domain and confirm the expected attributes come back populated.

## Setup

1. Copy `config.example.xml` to `config.xml`.
2. Edit `config.xml` and list the domains to search:

   ```xml
   <domains>
     <domain>contoso.com</domain>
     <domain>fabrikam.com</domain>
   </domains>
   ```

3. `config.xml` is environment-specific and is excluded from source control via
   `.gitignore` — only `config.example.xml` is checked in.

## Usage

```
finduser.ps1 <searchValue> [-NoStats]
```

Running with no arguments shows this usage screen and does nothing else.

### Examples

```
finduser.ps1 userA
finduser.ps1 lutz.mueller-hipper@frontoso.com
finduser.ps1 5Gz/Z7McHEWGzHdUTs5Kuw==
finduser.ps1 67ff6ce4-1cb3-451c-86cc-77544ece4abb
finduser.ps1 "{67ff6ce4-1cb3-451c-86cc-77544ece4abb}"
```

Add `-NoStats` to suppress the end-of-run summary (domains searched / users found /
errors), e.g. for use in another script's output pipeline.

## Logging

Each run writes a dated log file to `logs/finduser_yyyyMMdd.log` (created on first use,
excluded from source control). The console shows short status/error messages; the log
file has full detail, including the underlying exception for any AD errors.

## Folder layout

| Path | Purpose |
|---|---|
| `finduser.ps1` | Run code (source-controlled) |
| `config.example.xml` | Example config (source-controlled) |
| `config.xml` | Real, environment-specific config (not source-controlled) |
| `logs/` | Runtime log output (not source-controlled) |

## Version history

See [CHANGELOG.md](CHANGELOG.md).
