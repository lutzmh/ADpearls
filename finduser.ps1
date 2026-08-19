#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Finds an Active Directory user across configured domains by userid, SMTP/UPN address,
    objectGUID (registry or immutable/base64 form), or objectSid.

.DESCRIPTION
    finduser detects the format of the supplied search value and looks up the matching
    user object. By default it only searches the current user's domain context; pass
    -AllDomains to search every domain listed in config.xml instead.

.PARAMETER SearchId
    The value to search for. Format is auto-detected: samaccountname, SMTP/UPN address,
    objectGUID (registry or immutable/base64), objectSid, or a name for an ANR search.

.PARAMETER AllDomains
    Search every domain listed in config.xml instead of just the current user's domain.

.PARAMETER NoStats
    Suppress the end-of-run summary (domains searched / users found / errors).

.EXAMPLE
    finduser.ps1 userA

.EXAMPLE
    finduser.ps1 userA -AllDomains

.EXAMPLE
    finduser.ps1 lutz.mueller-hipper@frontoso.com

.EXAMPLE
    finduser.ps1 5Gz/Z7McHEWGzHdUTs5Kuw==

.EXAMPLE
    finduser.ps1 67ff6ce4-1cb3-451c-86cc-77544ece4abb

.EXAMPLE
    finduser.ps1 "{67ff6ce4-1cb3-451c-86cc-77544ece4abb}"

.NOTES
    Author  : lutzmh
    Version : 4.1.0

    Dependencies:
      - ActiveDirectory PowerShell module (RSAT), trusted Microsoft-signed module.

    Required permissions:
      - Read access to user objects in the target domain(s) (default AD
        "Authenticated Users" read rights are normally sufficient for the attributes queried).

    Configuration:
      - Reads config.xml (see config.example.xml). Only config.example.xml is checked
        into source control - config.xml is environment-specific. The domain list in
        config.xml is only used when -AllDomains is passed.
#>

param(
    [Parameter(Position = 0)]
    [string]$SearchId,

    [switch]$AllDomains,

    [switch]$NoStats
)

$script:ScriptVersion = "4.1.0"
$script:errorCount = 0
$script:logFilePath = $null

#region functions

function Show-Usage {
    Write-Host "Please supply a value for the userid you are looking for"
    Write-Host "Examples:"
    Write-Host "finduser.ps1 userA"
    Write-Host "finduser.ps1 lutz.mueller-hipper@frontoso.com"
    Write-Host "finduser.ps1 5Gz/Z7McHEWGzHdUTs5Kuw=="
    Write-Host "finduser.ps1 67ff6ce4-1cb3-451c-86cc-77544ece4abb"
    Write-Host 'finduser.ps1 "{67ff6ce4-1cb3-451c-86cc-77544ece4abb}"'
    Write-Host ""
    Write-Host "By default finduser only searches your current domain context."
    Write-Host "Add -AllDomains to search every domain listed in config.xml."
    Write-Host "Add -NoStats to suppress the end-of-run summary."
    Write-Host ""
    Write-Host "finduser will detect the format of the search parameter."
} # end function Show-Usage

function Get-CurrentUserDomain {
    # Resolves the domain of the current logged-on user/session, without needing AD connectivity first.
    if ($env:USERDNSDOMAIN) {
        return $env:USERDNSDOMAIN
    } # end if USERDNSDOMAIN available

    try {
        return ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    } catch {
        throw "Could not determine the current user's domain context. Use -AllDomains to search the domains listed in config.xml instead."
    } # end try/catch
} # end function Get-CurrentUserDomain

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

function ConvertTo-LdapEscapedString {
    # Escapes RFC 4515 special characters so free-text search input cannot alter the LDAP filter structure.
    param(
        [Parameter(Mandatory)]
        [string]$inputString
    )

    $escaped = $inputString
    $escaped = $escaped -replace '\\', '\5c'
    $escaped = $escaped -replace '\*', '\2a'
    $escaped = $escaped -replace '\(', '\28'
    $escaped = $escaped -replace '\)', '\29'
    $escaped = $escaped -replace "`0", '\00'
    return $escaped
} # end function ConvertTo-LdapEscapedString

function Test-SmtpAddress {
    param($object)
    return ($object -as [System.Net.Mail.MailAddress]).Address -eq $object -and $null -ne $object
} # end function Test-SmtpAddress

function Test-ObjectSid {
    # example: S-1-5-21-3623811015-3361044348-30300820-1013
    param($object)
    try {
        $null = [System.Security.Principal.SecurityIdentifier]$object
        return $true
    } catch {
        return $false
    } # end try/catch
} # end function Test-ObjectSid

function Test-ObjectGuidRegistry {
    # example: 67ff6ce4-1cb3-451c-86cc-77544ece4abb or {67ff6ce4-1cb3-451c-86cc-77544ece4abb}
    param($object)
    try {
        $null = [guid]$object
        return $true
    } catch {
        return $false
    } # end try/catch
} # end function Test-ObjectGuidRegistry

function Test-ObjectGuidImmutable {
    # example: 5Gz/Z7McHEWGzHdUTs5Kuw== (base64/immutable objectGUID)
    param($object)
    try {
        $null = [guid][System.Convert]::FromBase64String($object)
        return $true
    } catch {
        return $false
    } # end try/catch
} # end function Test-ObjectGuidImmutable

function Import-FindUserConfig {
    param(
        [Parameter(Mandatory)]
        [string]$configPath
    )

    if (-not (Test-Path -Path $configPath)) {
        throw "Config file not found: $configPath. Copy config.example.xml to config.xml and adjust it for your environment."
    } # end if config missing

    [xml]$configXml = Get-Content -Path $configPath

    $domains = @($configXml.FindUserConfig.domains.domain)
    $ldapAttributes = @($configXml.FindUserConfig.ldapAttributes.attribute)
    $logFolder = $configXml.FindUserConfig.logging.logFolder

    return [pscustomobject]@{
        domains        = $domains
        ldapAttributes = $ldapAttributes
        logFolder      = $logFolder
    }
} # end function Import-FindUserConfig

function Resolve-LdapFilter {
    param(
        [Parameter(Mandatory)]
        [string]$searchId
    )

    $ldapFilter = $null

    if (Test-ObjectGuidRegistry $searchId) {
        $guidHex = -join (([guid]$searchId).ToByteArray() | ForEach-Object { $_.ToString("X").PadLeft(2, "0") })
        $guidHex = $guidHex -replace '(..)', '\$1'
        $ldapFilter = "(objectGUID=$guidHex)"
    } elseif (Test-ObjectGuidImmutable $searchId) {
        $guidBytes = [System.Convert]::FromBase64String($searchId)
        $guidHex = -join (([guid]$guidBytes).ToByteArray() | ForEach-Object { $_.ToString("X").PadLeft(2, "0") })
        $guidHex = $guidHex -replace '(..)', '\$1'
        $ldapFilter = "(objectGUID=$guidHex)"
    } elseif (Test-ObjectSid $searchId) {
        $ldapFilter = "(objectSid=$searchId)"
    } elseif (Test-SmtpAddress $searchId) {
        $escapedId = ConvertTo-LdapEscapedString $searchId
        # can be SMTP or UPN, so look for both
        $ldapFilter = "(|(mail=$escapedId)(userprincipalname=$escapedId))"
    } elseif ($searchId -match " ") {
        $escapedId = ConvertTo-LdapEscapedString $searchId
        # assume this is name info usable for an ANR search
        $ldapFilter = "(anr=$escapedId)"
    } else {
        $escapedId = ConvertTo-LdapEscapedString $searchId
        # assume this is a samaccountname
        $ldapFilter = "(samaccountname=$escapedId)"
    } # end if/elseif searchId format detection

    return "(&(objectclass=user)(samaccountname=*)$ldapFilter)"
} # end function Resolve-LdapFilter

function Search-AdUserInDomain {
    param(
        [Parameter(Mandatory)]
        [string]$domain,

        [Parameter(Mandatory)]
        [string]$ldapFilter,

        [Parameter(Mandatory)]
        [string[]]$ldapAttributes
    )

    Write-Log -level "INFO" -message "Searching domain $domain"

    try {
        $dc = Get-ADDomainController -Discover -DomainName $domain -ErrorAction Stop
        $server = $dc.HostName[0]
    } catch {
        Write-Log -level "ERROR" -message "Could not discover a domain controller for $domain" -exception $_
        return , @()
    } # end try/catch discover domain controller

    try {
        [array]$searchResponse = Get-ADObject -LDAPFilter $ldapFilter -Server $server -Properties $ldapAttributes -ErrorAction Stop
    } catch {
        Write-Log -level "ERROR" -message "AD query failed against $server ($domain)" -exception $_
        return , @()
    } # end try/catch AD query

    if ($searchResponse.Count -eq 0) {
        Write-Log -level "INFO" -message "No match in $domain"
    } # end if no matches in this domain

    return , $searchResponse
} # end function Search-AdUserInDomain

function Format-AdUserResult {
    # Builds a fresh object per AD result so fields never leak between users in a loop.
    param(
        [Parameter(Mandatory)]
        $adObject,

        [Parameter(Mandatory)]
        [string]$domain
    )

    $objectGuid = $adObject.objectguid.guid
    $objectGuidBase64 = [System.Convert]::ToBase64String(([guid]$objectGuid).ToByteArray())

    return [pscustomobject]@{
        domain                  = $domain
        distinguishedName       = $adObject.distinguishedname
        samAccountName          = $adObject.samaccountname
        employeeId               = $(if ($adObject.employeeid.Count -gt 0) { $adObject.employeeid } else { $null })
        displayName              = $(if ($adObject.displayname.Count -gt 0) { $adObject.displayname } else { $null })
        mail                     = $(if ($adObject.mail.Count -gt 0) { $adObject.mail } else { $null })
        userPrincipalName        = $(if ($adObject.userprincipalname.Count -gt 0) { $adObject.userprincipalname } else { $null })
        objectGuid               = $objectGuid
        objectGuidBase64         = $objectGuidBase64
        objectSid                = $adObject.objectsid.Value
        msExchMasterAccountSid   = $adObject.msExchMasterAccountSid.Value
        lastLogonTimestamp       = $(if ($adObject.lastLogonTimestamp.Count -gt 0) { $adObject.lastLogonTimestamp } else { $null })
    }
} # end function Format-AdUserResult

function Write-AdUserResult {
    param(
        [Parameter(Mandatory)]
        $userResult
    )

    Write-Host "################### $($userResult.domain) ################################"
    Write-Host "dn                       : $($userResult.distinguishedName)"
    Write-Host "samaccountname           : $($userResult.samAccountName)"
    Write-Host "employeeid               : $($userResult.employeeId)"
    Write-Host "displayname              : $($userResult.displayName)"
    Write-Host "mail                     : $($userResult.mail)"
    Write-Host "upn                      : $($userResult.userPrincipalName)"
    Write-Host "canonical/registry format: $($userResult.objectGuid)"
    Write-Host "base64/immutable format  : $($userResult.objectGuidBase64)"
    Write-Host "objectSID                : $($userResult.objectSid)"
    Write-Host "msExchMasterAccountSid   : $($userResult.msExchMasterAccountSid)"
    Write-Host "lastLogonTimestamp       : $($userResult.lastLogonTimestamp)"
} # end function Write-AdUserResult

function Main {
    param(
        [string]$SearchId,
        [switch]$AllDomains,
        [switch]$NoStats
    )

    if ([string]::IsNullOrWhiteSpace($SearchId)) {
        Show-Usage
        return
    } # end if no search value supplied

    $scriptRoot = $PSScriptRoot
    $config = Import-FindUserConfig -configPath (Join-Path $scriptRoot "config.xml")

    $logFolder = Join-Path $scriptRoot $config.logFolder
    if (-not (Test-Path -Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory | Out-Null
    } # end if log folder missing
    $script:logFilePath = Join-Path $logFolder ("finduser_{0}.log" -f (Get-Date -Format "yyyyMMdd"))

    Write-Log -level "INFO" -message "finduser v$script:ScriptVersion started, search value: $SearchId"

    if ($AllDomains) {
        $targetDomains = $config.domains
        Write-Log -level "INFO" -message "Searching all configured domains: $($targetDomains -join ', ')"
    } else {
        $targetDomains = @(Get-CurrentUserDomain)
        Write-Log -level "INFO" -message "Searching current user domain context: $($targetDomains[0]) (use -AllDomains to search all configured domains)"
    } # end if AllDomains switch

    $ldapFilter = Resolve-LdapFilter -searchId $SearchId

    $domainsSearched = 0
    $usersFound = 0

    foreach ($domain in $targetDomains) {
        $domainsSearched++
        $searchResponse = Search-AdUserInDomain -domain $domain -ldapFilter $ldapFilter -ldapAttributes $config.ldapAttributes

        foreach ($adObject in $searchResponse) {
            $usersFound++
            $userResult = Format-AdUserResult -adObject $adObject -domain $domain
            Write-AdUserResult -userResult $userResult
        } # end foreach found object
    } # end foreach domain

    Write-Log -level "INFO" -message "finduser completed. Domains searched: $domainsSearched, users found: $usersFound, errors: $script:errorCount"

    if (-not $NoStats) {
        Write-Host ""
        Write-Host "----- Summary -----"
        Write-Host "Domains searched : $domainsSearched"
        Write-Host "Users found      : $usersFound"
        Write-Host "Errors           : $script:errorCount"
    } # end if summary not suppressed
} # end function Main

#endregion functions

Main -SearchId $SearchId -AllDomains:$AllDomains -NoStats:$NoStats
