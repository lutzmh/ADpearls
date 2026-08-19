# Release History

## s_client.ps1

### 1.1.0 - 2026-08-19
- Added Subject Alternative Name (SAN) reporting (`Get-SubjectAlternativeNames`), highlighted with a `WILDCARD CERTIFICATE` marker when any SAN entry starts with `*.`.

### 1.0.0 - 2026-08-19
- Rewrote script to follow team PowerShell coding standards (see coding_standards.txt).
- Fixed: certificate expiry was never actually flagged - the original `NotAfter` check only printed a green "within validity" message and otherwise stayed silent, so an expired certificate produced no red warning at all.
- Fixed: `NotBefore`/`NotAfter` were read via a `.DateTime` property that doesn't exist on `[DateTime]` (silently returns `$null` in non-strict mode), making the printed dates blank and the not-yet-valid check unreliable. Now reads the properties directly.
- Fixed: `AuthenticateAsClient('')` sent no SNI hostname, so servers hosting multiple certificates on one IP could return the wrong certificate. Now passes `ComputerName` for SNI.
- Fixed: the signature-algorithm check only had OIDs for RSA signatures, so any ECDSA-signed certificate (the default for most current Let's Encrypt/Google/Cloudflare leaf certs) was misclassified as an unknown/weak algorithm. Added the ECDSA OID set (flags `ECDSA-SHA1` as weak, `ECDSA-SHA256/384/512` as fine) and the RSASSA-PSS OID.
- Fixed: MD5-signed certificates fell into the generic "unknown hash algorithm" message instead of being named; the lookup table now names MD5 explicitly.
- Added: reports the negotiated TLS protocol and flags SSL2/3 and TLS1.0/1.1 as weak. Note: for TLS 1.3 the console clarifies that cipher details aren't exposed by .NET Framework's `SslStream` (`CipherAlgorithm`/`CipherStrength` return "None"/0) rather than printing that misleading value.
- No-argument invocation now shows usage only, instead of PowerShell's interactive mandatory-parameter prompt.
- Added file logging (info/warning/error) under `logs/`, with short messages on console and full detail (incl. underlying exception) in the log file.
- Added an overall OK/WARNING result line based on whether any check was flagged.
- Wrapped logic in a `Main` controller function plus single-purpose functions (`Get-RemoteCertificate`, `Show-CertificateAnalysis`, `Export-CertificateFile`, etc.); renamed variables to camelCase.
- Added comment-based help documenting parameters, dependencies, required permissions, and the intentional certificate-validation bypass.
- No XML config: unlike finduser.ps1, this script has no environment-specific settings to externalize - `ComputerName`/`Port` are already runtime parameters, so a config file would only hold constants (the algorithm/protocol lookup tables), not per-environment data.

## finduser.ps1

### 4.1.0 - 2026-08-19
- Changed default search scope to the current user's domain context (`$env:USERDNSDOMAIN`, via new `Get-CurrentUserDomain`), instead of always searching every domain in `config.xml`.
- Added `-AllDomains` switch to opt into searching every domain listed in `config.xml`, restoring the previous behavior.
- Updated usage screen, comment-based help, and README to document the new default and switch.

### 4.0.0 - 2026-08-19
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

### 3 (prior)
- History not tracked before this refactor.
