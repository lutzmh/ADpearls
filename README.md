# ADpearls

Standalone PowerShell diagnostic tools. Each script is independent — no shared code
or config between them — and documented in its own section below.

- [finduser.ps1](#finduserps1) — look up an Active Directory user
- [s_client.ps1](#s_clientps1) — inspect a TLS/SSL certificate

---

## finduser.ps1

Finds an Active Directory user by userid (samaccountname), SMTP/UPN address,
objectGUID (registry or immutable/base64 form), or objectSid. The script
auto-detects which format you passed in.

By default it only searches the **current user's domain context** (`$env:USERDNSDOMAIN`).
Pass `-AllDomains` to search every domain listed in `config.xml` instead.

### Requirements

- Windows PowerShell with the **ActiveDirectory** module (RSAT), enforced via
  `#Requires -Modules ActiveDirectory` at the top of the script.
- Network line of sight to a domain controller for the target domain(s).

### Permissions

- Read access to user objects in the target domain(s). Default AD "Authenticated Users"
  read rights are normally sufficient for the attributes this script queries
  (`objectGUID`, `objectSid`, `cn`, `displayname`, `employeeid`, `mail`,
  `samaccountname`, `userprincipalname`, `msExchMasterAccountSid`,
  `lastLogonTimestamp`).
- No write access is required or used.

To verify permissions on a given account, run a search (see below) against a known
test user in each domain and confirm the expected attributes come back populated.

### Setup

1. Copy `config.example.xml` to `config.xml`.
2. Edit `config.xml` and list the domains to search when `-AllDomains` is used:

   ```xml
   <domains>
     <domain>contoso.com</domain>
     <domain>fabrikam.com</domain>
   </domains>
   ```

3. `config.xml` is environment-specific and is excluded from source control via
   `.gitignore` — only `config.example.xml` is checked in.

### Usage

```
finduser.ps1 <searchValue> [-AllDomains] [-NoStats]
```

Running with no arguments shows this usage screen and does nothing else.

**Examples**

```
finduser.ps1 userA
finduser.ps1 userA -AllDomains
finduser.ps1 lutz.mueller-hipper@frontoso.com
finduser.ps1 5Gz/Z7McHEWGzHdUTs5Kuw==
finduser.ps1 67ff6ce4-1cb3-451c-86cc-77544ece4abb
finduser.ps1 "{67ff6ce4-1cb3-451c-86cc-77544ece4abb}"
```

Add `-AllDomains` to search every domain listed in `config.xml` instead of just the
current user's domain. Add `-NoStats` to suppress the end-of-run summary (domains
searched / users found / errors), e.g. for use in another script's output pipeline.

### Logging

Each run writes a dated log file to `logs/finduser_yyyyMMdd.log` (created on first use,
excluded from source control). The console shows short status/error messages; the log
file has full detail, including the underlying exception for any AD errors.

---

## s_client.ps1

Connects to a TLS/SSL endpoint and reports on the certificate presented, inspired by
`openssl s_client`. No config file — everything is passed as a parameter, and there's
no environment-specific data to store.

Server certificate validation is deliberately disabled so the tool can inspect invalid,
expired, or self-signed certificates too (like `openssl s_client` does). This connection
is for read-only inspection only.

### Requirements

- .NET's `System.Net.Sockets.TcpClient` / `System.Net.Security.SslStream` — no external
  module required.
- Outbound network access from this host to the target `ComputerName:Port`.

### Permissions

- Outbound network access to the target host/port.
- Write access to `$env:TEMP` (the retrieved certificate is exported there) and to the
  script's own `logs\` folder.

### Usage

```
s_client.ps1 <ComputerName> [-Port <port>]
```

Running with no arguments shows this usage screen and does nothing else. Port defaults
to 443.

**Examples**

```
s_client.ps1 www.example.com
s_client.ps1 -ComputerName mail.example.com -Port 8443
```

The report covers: subject, Subject Alternative Names (highlighted if the cert is a
wildcard, e.g. `*.github.com`), issuer, validity window (flags not-yet-valid and expired
certs), negotiated TLS protocol (flags SSL2/3 and TLS1.0/1.1 as weak), cipher (not
exposed by this API for TLS 1.3 — a known .NET Framework limitation, not a script
fault), and the certificate's signature hash algorithm (flags MD5/SHA1, covers both RSA
and ECDSA signature OIDs). The certificate is also exported to `$env:TEMP` as a `.crt`
file for further analysis. Exits with an overall OK/WARNING result based on whether
anything was flagged (a wildcard cert is highlighted but does not by itself count
against the result).

### Logging

Each run writes a dated log file to `logs/sclient_yyyyMMdd.log` (created on first use,
excluded from source control). The console shows short status/error messages; the log
file has full detail, including the underlying exception for any connection errors.

---

## Folder layout

| Path | Purpose |
|---|---|
| `finduser.ps1` | Run code (source-controlled) |
| `s_client.ps1` | Run code (source-controlled) |
| `config.example.xml` | finduser example config (source-controlled) |
| `config.xml` | finduser real, environment-specific config (not source-controlled) |
| `logs/` | Runtime log output for both scripts (not source-controlled) |

## Version history

See [CHANGELOG.md](CHANGELOG.md).
