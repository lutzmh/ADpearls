# Release History - finduser.ps1

## 4.0.0 - 2026-08-19
- Rewrote script to follow team PowerShell coding standards (see coding_standards.txt).
- Fixed: `isObjectSid` always returned `$false` (referenced an undefined `$sid` variable) - SID-format lookups never matched. Reimplemented as `Test-ObjectSid` using `[System.Security.Principal.SecurityIdentifier]`.
- Fixed: empty-UPN branch cleared `$userprincipalname` instead of `$upn`, allowing a stale UPN to leak into the next result in the loop. Output is now built per-record via `Format-AdUserResult`, so there is no shared mutable state across iterations.
- Removed dead assignment (`$server = $domain` immediately overwritten).
- Moved the domain list from `domains.txt` into an XML config (`config.xml`), with `config.example.xml` as the only copy checked into source control.
- No-argument invocation now shows usage only; config/logging/AD access no longer run before the argument check.
- Added file logging (info/warning/error) under `logs/`, with short messages on console and full detail (incl. underlying exception) in the log file.
- Added end-of-run summary (domains searched, users found, errors), suppressible with `-NoStats`.
- Wrapped logic in a `Main` controller function plus single-purpose functions; renamed helper functions to PowerShell `Verb-Noun` style.
- Renamed variables to camelCase and to match the XML config element names (`domains`, `ldapAttributes`, `logFolder`).
- Added LDAP filter escaping for free-text search input (`ConvertTo-LdapEscapedString`) to avoid LDAP filter injection.
- Added `#Requires -Modules ActiveDirectory` and comment-based help documenting the dependency, required permissions, and usage.

## 3 (prior)
- History not tracked before this refactor.
