<#
.SYNOPSIS
    Connects to a TLS/SSL endpoint and reports on the certificate presented, inspired
    by `openssl s_client`.

.DESCRIPTION
    Opens a TCP connection to ComputerName:Port, performs a TLS handshake (server
    certificate validation is intentionally disabled so even invalid, expired, or
    self-signed certificates can be inspected), and reports the negotiated protocol,
    cipher, and certificate details: subject, issuer, validity window, and signature
    hash algorithm. Weak signature algorithms (MD5, SHA1) and deprecated TLS protocol
    versions (SSL2/3, TLS1.0/1.1) are flagged. The certificate is exported to a local
    file for further analysis.

.PARAMETER ComputerName
    The host to connect to.

.PARAMETER Port
    The TCP port to connect to. Defaults to 443.

.EXAMPLE
    s_client.ps1 www.example.com

.EXAMPLE
    s_client.ps1 -ComputerName mail.example.com -Port 8443

.NOTES
    Author  : lutzmh
    Version : 1.1.0

    Dependencies:
      - .NET System.Net.Sockets.TcpClient / System.Net.Security.SslStream. No external
        module required.

    Required permissions:
      - Outbound network access from this host to ComputerName:Port.
      - Write access to $env:TEMP (to export the retrieved certificate) and to the
        script's own logs\ folder.

    Security note:
      - Server certificate validation is deliberately disabled so this tool can inspect
        invalid/expired/self-signed certificates, the same way `openssl s_client`
        does. This connection is for read-only inspection only - never reuse this
        validation-disabled pattern for a connection that sends credentials or data
        that needs to be trusted.

    Independent from finduser.ps1 - no shared code/config between the two tools.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ComputerName,

    [Parameter(Position = 1)]
    [ValidateRange(1, 65535)]
    [int]$Port = 443
)

$script:ScriptVersion = "1.1.0"
$script:errorCount = 0
$script:logFilePath = $null

#region functions

function Show-Usage {
    Write-Host "Please supply a computer name to connect to"
    Write-Host "Examples:"
    Write-Host "s_client.ps1 www.example.com"
    Write-Host "s_client.ps1 -ComputerName mail.example.com -Port 8443"
    Write-Host ""
    Write-Host "Retrieves the TLS certificate from ComputerName:Port (default port 443),"
    Write-Host "reports on its validity, signature algorithm and negotiated protocol,"
    Write-Host "and exports it to a file for further analysis."
} # end function Show-Usage

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$level,

        [Parameter(Mandatory)]
        [string]$message,

        $exception
    )

    switch ($level) {
        "INFO"    { Write-Host $message }
        "WARNING" { Write-Warning $message }
        "ERROR" {
            Write-Host "Error: $message" -ForegroundColor Red
            $script:errorCount++
        }
    } # end switch level

    if ($script:logFilePath) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $fullDetail = "$timestamp [$level] $message"
        if ($exception) {
            $fullDetail += " | $($exception.Exception.Message)"
        } # end if exception supplied
        Add-Content -Path $script:logFilePath -Value $fullDetail
    } # end if log file configured
} # end function Write-Log

function Get-RemoteCertificate {
    # Connects, performs a TLS handshake without validating the server cert, and
    # returns the certificate plus the negotiated protocol/cipher. Always closes the
    # TCP connection, even on failure.
    param(
        [Parameter(Mandatory)]
        [string]$computerName,

        [Parameter(Mandatory)]
        [int]$port
    )

    $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
    try {
        $tcpClient.Connect($computerName, $port)
        $tcpStream = $tcpClient.GetStream()

        $validationCallback = { param($sender, $cert, $chain, $sslPolicyErrors) return $true }

        $sslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($tcpStream, $true, $validationCallback)
        try {
            # Pass computerName (SNI) so servers hosting multiple certs return the right one.
            $sslStream.AuthenticateAsClient($computerName)

            return [pscustomobject]@{
                certificate     = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate
                protocol        = $sslStream.SslProtocol
                cipherAlgorithm = $sslStream.CipherAlgorithm
                cipherStrength  = $sslStream.CipherStrength
            }
        } finally {
            $sslStream.Dispose()
        } # end try/finally sslStream
    } finally {
        $tcpClient.Dispose()
    } # end try/finally tcpClient
} # end function Get-RemoteCertificate

function Get-SignatureAlgorithmAssessment {
    # Reference: https://msdn.microsoft.com/en-us/library/windows/desktop/aa381133(v=vs.85).aspx
    param(
        [Parameter(Mandatory)]
        [string]$signatureAlgorithmOid
    )

    $knownAlgorithms = @{
        # RSA
        "1.2.840.113549.1.1.11" = @{ name = "RSA-SHA256"; isWeak = $false }
        "1.2.840.113549.1.1.12" = @{ name = "RSA-SHA384"; isWeak = $false }
        "1.2.840.113549.1.1.13" = @{ name = "RSA-SHA512"; isWeak = $false }
        "1.2.840.113549.1.1.5"  = @{ name = "RSA-SHA1"; isWeak = $true }
        "1.2.840.113549.1.1.4"  = @{ name = "RSA-MD5"; isWeak = $true }
        # RSASSA-PSS (hash is carried in separate parameters, not distinguishable from the OID alone)
        "1.2.840.113549.1.1.10" = @{ name = "RSASSA-PSS"; isWeak = $false }
        # ECDSA - increasingly the default for modern certs (e.g. most current Let's Encrypt/Google leaf certs)
        "1.2.840.10045.4.1"     = @{ name = "ECDSA-SHA1"; isWeak = $true }
        "1.2.840.10045.4.3.2"   = @{ name = "ECDSA-SHA256"; isWeak = $false }
        "1.2.840.10045.4.3.3"   = @{ name = "ECDSA-SHA384"; isWeak = $false }
        "1.2.840.10045.4.3.4"   = @{ name = "ECDSA-SHA512"; isWeak = $false }
    }

    if ($knownAlgorithms.ContainsKey($signatureAlgorithmOid)) {
        return $knownAlgorithms[$signatureAlgorithmOid]
    } # end if known algorithm

    return @{ name = "unknown ($signatureAlgorithmOid)"; isWeak = $true }
} # end function Get-SignatureAlgorithmAssessment

function Test-WeakProtocol {
    param(
        [Parameter(Mandatory)]
        [System.Security.Authentication.SslProtocols]$protocol
    )

    $weakProtocols = @(
        [System.Security.Authentication.SslProtocols]::Ssl2,
        [System.Security.Authentication.SslProtocols]::Ssl3,
        [System.Security.Authentication.SslProtocols]::Tls,
        [System.Security.Authentication.SslProtocols]::Tls11
    )

    return $protocol -in $weakProtocols
} # end function Test-WeakProtocol

function Get-SubjectAlternativeNames {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    )

    $sanExtension = $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
    if (-not $sanExtension) {
        return @()
    } # end if no SAN extension present

    # Format($true) returns one "<type>=<value>" entry per line (e.g. "DNS Name=*.example.com").
    $lines = $sanExtension.Format($true) -split "`r`n|`n" | Where-Object { $_ -match '=' }
    return , @($lines | ForEach-Object { ($_ -split '=', 2)[1].Trim() })
} # end function Get-SubjectAlternativeNames

function Show-CertificateAnalysis {
    # Prints the report and returns $false if anything worth flagging was found.
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate,

        [Parameter(Mandatory)]
        [System.Security.Authentication.SslProtocols]$protocol,

        [Parameter(Mandatory)]
        [string]$cipherAlgorithm,

        [Parameter(Mandatory)]
        [int]$cipherStrength
    )

    $isHealthy = $true
    $now = Get-Date

    Write-Host ""
    Write-Host "Quick analysis:"
    Write-Host "Subject:   $($certificate.Subject)" -ForegroundColor DarkCyan

    $sanNames = Get-SubjectAlternativeNames -certificate $certificate
    $wildcardNames = @($sanNames | Where-Object { $_ -match '^\*\.' })
    if ($sanNames.Count -gt 0) {
        Write-Host "SAN:       $($sanNames -join ', ')"
    } else {
        Write-Host "SAN:       (none)"
    } # end if SAN present
    if ($wildcardNames.Count -gt 0) {
        Write-Host "           WILDCARD CERTIFICATE ($($wildcardNames -join ', '))" -ForegroundColor Yellow
    } # end if wildcard cert

    Write-Host "Issuer:    $($certificate.Issuer)"

    Write-Host "NotBefore: $($certificate.NotBefore)" -NoNewline
    if ($certificate.NotBefore -gt $now) {
        Write-Host " - not valid yet" -ForegroundColor Red
        $isHealthy = $false
    } else {
        Write-Host ""
    } # end if not yet valid

    Write-Host "NotAfter:  $($certificate.NotAfter)" -NoNewline
    if ($certificate.NotAfter -lt $now) {
        Write-Host " - EXPIRED" -ForegroundColor Red
        $isHealthy = $false
    } else {
        Write-Host " - within validity" -ForegroundColor Green
    } # end if expired

    Write-Host "Protocol:  $protocol" -NoNewline
    if (Test-WeakProtocol -protocol $protocol) {
        Write-Host " - deprecated/weak protocol" -ForegroundColor Red
        $isHealthy = $false
    } else {
        Write-Host " - OK" -ForegroundColor Green
    } # end if weak protocol
    if ($protocol -eq [System.Security.Authentication.SslProtocols]::Tls13) {
        # .NET Framework's SslStream does not expose the negotiated TLS 1.3 cipher suite
        # (CipherAlgorithm/CipherStrength report "None"/0 here) - not a fault, just a gap in this API.
        Write-Host "Cipher:    not reported by this API for TLS 1.3"
    } else {
        Write-Host "Cipher:    $cipherAlgorithm ($cipherStrength bit)"
    } # end if TLS 1.3 cipher reporting gap

    $signatureAssessment = Get-SignatureAlgorithmAssessment -signatureAlgorithmOid $certificate.SignatureAlgorithm.Value
    if ($signatureAssessment.isWeak) {
        Write-Host "Signature: $($signatureAssessment.name) hash - weak/deprecated" -ForegroundColor Red
        $isHealthy = $false
    } else {
        Write-Host "Signature: $($signatureAssessment.name) hash" -ForegroundColor Green
    } # end if weak signature algorithm

    Write-Host "=========================================================="

    return $isHealthy
} # end function Show-CertificateAnalysis

function Export-CertificateFile {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    )

    $outFile = Join-Path $env:TEMP "$($certificate.Thumbprint).crt"
    Export-Certificate -Cert $certificate -FilePath $outFile | Out-Null
    return $outFile
} # end function Export-CertificateFile

function Main {
    param(
        [string]$ComputerName,
        [int]$Port
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        Show-Usage
        return
    } # end if no computer name supplied

    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $logFolder = Join-Path $scriptRoot "logs"
    if (-not (Test-Path -Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory | Out-Null
    } # end if log folder missing
    $script:logFilePath = Join-Path $logFolder ("sclient_{0}.log" -f (Get-Date -Format "yyyyMMdd"))

    Write-Log -level "INFO" -message "s_client v$script:ScriptVersion started, target: ${ComputerName}:${Port}"

    try {
        $connection = Get-RemoteCertificate -computerName $ComputerName -port $Port
    } catch {
        Write-Log -level "ERROR" -message "Could not retrieve a certificate from ${ComputerName}:${Port}" -exception $_
        return
    } # end try/catch retrieve certificate

    $isHealthy = Show-CertificateAnalysis -certificate $connection.certificate -protocol $connection.protocol -cipherAlgorithm $connection.cipherAlgorithm -cipherStrength $connection.cipherStrength

    $outFile = Export-CertificateFile -certificate $connection.certificate
    Write-Host " $outFile can be used for further analysis."
    Write-Host ""

    if ($isHealthy) {
        Write-Log -level "INFO" -message "Result: OK - certificate and connection look healthy"
    } else {
        Write-Log -level "WARNING" -message "Result: issues found - see analysis above"
    } # end if isHealthy
} # end function Main

#endregion functions

Main -ComputerName $ComputerName -Port $Port
