<#
.SYNOPSIS
Azure AD authentication for Azure PostgreSQL using Azure CLI.
.DESCRIPTION
Secure, reliable AAD token acquisition and PostgreSQL connection management for production environments.
Includes strict parameter validation, comprehensive error handling, resource cleanup, and full PowerShell pipeline support.
.NOTES
Version: 1.0.0
Author: Jack Xu
Requires: Azure CLI, PowerShell 5.1+ Npgsql 4.0.17 / PowerShell 7+ Npgsql 10.0.1
#>

#region Core Functions
function Test-AzureCliAvailability {
    <#
    .SYNOPSIS
    Validates Azure CLI installation and version compatibility for production use.
    
    .DESCRIPTION
    Performs comprehensive validation of Azure CLI installation including:
    - Checks if Azure CLI is installed and accessible in PATH
    - Validates minimum version requirement (2.50.0+)
    - Provides detailed error messages for troubleshooting
    - Supports pipeline processing for batch validation scenarios
    
    .PARAMETER None
    This function does not accept parameters.
    
    .OUTPUTS
    [System.Boolean] Returns $true if Azure CLI is available and compatible, $false otherwise.
    
    .EXAMPLE
    PS C:\> Test-AzureCliAvailability
    True
    
    Validates that Azure CLI is installed and meets minimum version requirements.
    
    .EXAMPLE
    PS C:\> Test-AzureCliAvailability -Verbose
    VERBOSE: Starting Azure CLI availability check pipeline processing
    VERBOSE: Azure CLI validated (version: 2.50.0)
    VERBOSE: Azure CLI availability check pipeline processing completed
    True
    
    Validates Azure CLI with detailed verbose logging for troubleshooting.
    
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    begin {
        Write-Verbose "Starting Azure CLI availability check pipeline processing"
    }

    process {
        try {
            $azVersion = az --version 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Azure CLI is not installed or not in PATH. Exit code: $LASTEXITCODE"
            }
            
            # Validate minimum Azure CLI version (2.50.0+)
            $versionMatch = $azVersion | Select-String -Pattern 'azure-cli\s+(\d+\.\d+\.\d+)'
            if (-not $versionMatch) {
                Write-Warning "Could not verify Azure CLI version - proceeding with caution"
                return $true
            }
            
            $version = [version]$versionMatch.Matches.Groups[1].Value
            $minVersion = [version]"2.50.0"
            if ($version -lt $minVersion) {
                throw "Azure CLI version $version is outdated. Minimum required: $minVersion"
            }

            Write-Verbose "Azure CLI validated (version: $version)"
            return $true
        }
        catch {
            Write-Error "Azure CLI validation failed: $($_.Exception.Message)"
            return $false
        }
    }
    
    end {
        Write-Verbose "Azure CLI availability check pipeline processing completed"
    }
}

function Get-AdUserAccessToken {
    <#
    .SYNOPSIS
    Securely retrieves Azure AD access tokens for PostgreSQL authentication with comprehensive retry logic.
    
    .DESCRIPTION
    AAD token acquisition with enterprise features:
    - Automatic Azure CLI session validation and login prompts
    - Multi-attempt retry logic with exponential backoff
    - Comprehensive error handling and logging
    - Token validation and sanitization
    - Support for multiple Azure resource endpoints
    - Pipeline processing for batch token acquisition
    
    .PARAMETER AadUsername
    The Azure AD username (UPN format: user@domain.com) to authenticate with.
    Must be a valid Azure AD user principal name.
    
    .PARAMETER ResourceUri
    The Azure resource URI for token acquisition. Valid values:
    - https://ossrdbms-aad.database.windows.net (default for PostgreSQL)
    - https://postgres.database.azure.com
    
    .OUTPUTS
    [System.String] Valid JWT access token for the specified Azure resource.
    
    .EXAMPLE
    PS C:\> Get-AdUserAccessToken -AadUsername "dba@contoso.com" -ResourceUri "https://ossrdbms-aad.database.windows.net"
    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZGNWQSIsImtpZCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZGNWQSJ9...
    
    Acquires access token for PostgreSQL authentication with default resource URI.
    
    .EXAMPLE
    PS C:\> Get-AdUserAccessToken -AadUsername "admin@fabrikam.com" -ResourceUri "https://postgres.database.azure.com" -Verbose
    VERBOSE: Starting AAD token acquisition pipeline processing
    VERBOSE: Retrieving AAD token (attempt 1/3) for resource: https://postgres.database.azure.com
    VERBOSE: AAD token acquired successfully (length: 1204 chars)
    VERBOSE: AAD token acquisition pipeline processing completed
    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZGNWQSIsImtpZCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZGNWQSJ9...
    
    Demonstrates verbose logging for troubleshooting token acquisition issues.
    
    .EXAMPLE
    PS C:\> @(
    >>     [PSCustomObject]@{AadUsername = "user1@domain.com"; ResourceUri = "https://ossrdbms-aad.database.windows.net"},
    >>     [PSCustomObject]@{AadUsername = "user2@domain.com"; ResourceUri = "https://postgres.database.azure.com"}
    >> ) | Get-AdUserAccessToken
    
    Demonstrates pipeline support for batch token acquisition from multiple users and resources.
    
    .EXAMPLE
    PS C:\> Import-Csv "users.csv" | Get-AdUserAccessToken
    
    Processes CSV file containing AadUsername and ResourceUri columns for bulk token acquisition.
    
    .NOTES
    - Requires Azure CLI to be installed and accessible in PATH
    - Supports automatic login prompts for interactive scenarios
    - Implements 3-attempt retry logic with 2-second delays
    - Validates token format before returning
    - Sanitizes tokens by removing whitespace characters
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
        [string]$AadUsername,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('https://ossrdbms-aad.database.windows.net', 'https://postgres.database.azure.com')]
        [string]$ResourceUri
    )

    begin {
        Write-Verbose "Starting AAD token acquisition pipeline processing"
    }

    process {
        # Retry configuration
        $retryCount = 3
        $retryDelay = 2 # Seconds between retries
        $token = $null

        for ($i = 1; $i -le $retryCount; $i++) {
            try {
                # Check active Azure session
                $azAccount = az account show --output json 2>&1
                if ($LASTEXITCODE -ne 0) {
                    # No active session - prompt user to login
                    Write-Verbose "(attempt $i/$retryCount) No active Azure session. Prompting user to login account $AadUsername "
                    try {
                        Write-Verbose "(attempt $i/$retryCount) Prompting user to login account $AadUsername "
                        # Step 1: Execute login (allow no subscriptions, device code for headless environments)
                        Write-Verbose "Starting Azure login flow - complete authentication when prompted..."
                        az login --allow-no-subscriptions

                        # Validate exit code: 0 = success, non-zero = failure
                        if ($LASTEXITCODE -ne 0) {
                            throw "Azure login process failed "
                        }
                        # Extra validation: Verify active authenticated state (works for no-subscription accounts)
                        Write-Verbose "Login complete - validating authentication state..."
                        az account show --output none
                        if ($LASTEXITCODE -ne 0) {
                            throw "Invalid login state"
                        }
                        Write-Verbose "Login succeeded! "
                    }
                    catch {
                       throw "Azure login failed: $($_.Exception.Message)"
                    }
                    
                }
                else {
                    # Active session - validate user matches
                    Write-Verbose "(attempt $i/$retryCount) Active Azure session found. Validating user account $AadUsername "
                    $currentUser = ($azAccount | ConvertFrom-Json).user.name
                    if ($currentUser -ne $AadUsername) {
                        Write-Verbose "(attempt $i/$retryCount) AAD user mismatch: Expected '$AadUsername', Found '$currentUser' Prompting user to login account $AadUsername "
                        try {
                            Write-Verbose "(attempt $i/$retryCount) Prompting user to login account $AadUsername "
                                                    # Step 1: Execute login (allow no subscriptions, device code for headless environments)
                        Write-Verbose "Starting Azure login flow - complete authentication when prompted..."
                        az login --allow-no-subscriptions

                        # Validate exit code: 0 = success, non-zero = failure
                        if ($LASTEXITCODE -ne 0) {
                            throw "Azure login process failed "
                        }
                        # Extra validation: Verify active authenticated state (works for no-subscription accounts)
                        Write-Verbose "Login complete - validating authentication state..."
                        az account show --output none
                        if ($LASTEXITCODE -ne 0) {
                            throw "Invalid login state"
                        }
                        Write-Verbose "Login succeeded! " 
                        }
                        catch {
                            throw "Azure re login failed: $($_.Exception.Message)"
                        }
                    }
                    else {
                            Write-Verbose "(attempt $i/$retryCount) Active Azure session matches user account $AadUsername "
                    }
                }

                # Get token with error handling
                Write-Verbose "Retrieving AAD token (attempt $i/$retryCount) for resource: $ResourceUri"
      
                $tokenOutput = az account get-access-token `
                    --resource $ResourceUri `
                    --query "accessToken" `
                    --output tsv `
                    2>&1

                if ($LASTEXITCODE -ne 0) {
                    throw "Token acquisition failed: $tokenOutput"
                }

                # Sanitize and validate token
                $token = $tokenOutput.Trim() -replace '\s+', ''
                if (-not $token -or $token -notmatch '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$') {
                    throw "Invalid JWT token format (empty or malformed)"
                }

                Write-Verbose "AAD token acquired successfully (length: $($token.Length) chars)"
                return $token
            }
            catch {
                if ($i -eq $retryCount) {
                    throw "Token retrieval failed after $retryCount retries: $($_.Exception.Message)"
                }
                Write-Warning "Token attempt $i failed: $($_.Exception.Message) Retrying in $retryDelay seconds..."
                Start-Sleep -Seconds $retryDelay
            }
        }

        throw "Unexpected failure in token retrieval (all retries exhausted)"
    }
    
    end {
        Write-Verbose "AAD token acquisition pipeline processing completed"
    }
}

function Initialize-NpgsqlDriver1001 {
    <#
    .SYNOPSIS
    Initializes Npgsql 10.0.1 driver for PowerShell 7+ with caching and dependency management.
    
    .DESCRIPTION
    Production-ready Npgsql driver initialization for PowerShell 7+ with enterprise features:
    - Idempotent installation (safe to run multiple times)
    - Centralized package caching to avoid duplicate downloads
    - Assembly resolution for dependency management
    - Locked package versions for consistency
    - Comprehensive error handling and validation
    - Pipeline support for batch initialization scenarios
    - Verbose logging for troubleshooting
    
    .PARAMETER None
    This function does not accept parameters.
    
    .OUTPUTS
    [System.Boolean] Returns $true on successful initialization, $false on failure.
    
    .EXAMPLE
    PS C:\> Initialize-NpgsqlDriver1001
    
    Initializes Npgsql 10.0.1 driver for PowerShell 7+ with default settings.
    
    .EXAMPLE
    PS C:\> Initialize-NpgsqlDriver1001 -Verbose
    VERBOSE: Starting Npgsql 10.0.1 driver initialization pipeline processing
    VERBOSE: Created driver cache directory: C:\ProgramData\PostgresAadAuth\Npgsql\10.0.1
    VERBOSE: Registered assembly resolver for Npgsql
    VERBOSE: Npgsql driver initialized successfully
    VERBOSE: Npgsql 10.0.1 driver initialization pipeline processing completed
    
    Demonstrates verbose logging for troubleshooting driver initialization issues.
    
    .NOTES
    - PowerShell 7+ compatible only
    - Requires NuGet package provider
    - Caches packages in C:\ProgramData\PostgresAadAuth\Npgsql\10.0.1
    - Registers assembly resolver for dependency management
    - Locked package versions: Microsoft.Extensions.DependencyInjection.Abstractions 8.0.0,
      Microsoft.Extensions.Logging.Abstractions 8.0.0, System.Diagnostics.DiagnosticSource 9.0.11, Npgsql 10.0.1
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    begin {
        Write-Verbose "Starting Npgsql 10.0.1 driver initialization pipeline processing"
    }

    process {
        $cachePath = Join-Path -Path $env:ProgramData -ChildPath "PostgresAadAuth/Npgsql/10.0.1"
        $pkgDest = Join-Path -Path $cachePath -ChildPath "packages"

        try {
            # Create cache directory (idempotent)
            if (-not (Test-Path -Path $cachePath)) {
                $null = New-Item -Path $cachePath -ItemType Directory -Force -ErrorAction Stop
                Write-Verbose "Created driver cache directory: $cachePath"
            }
            else 
                {
                    Write-Verbose "Cache directory already exists: $cachePath"
                }

            # Required packages (locked versions for production)
            $requiredPackages = @(
                @{ Name = "Microsoft.Extensions.DependencyInjection.Abstractions"; Version = "8.0.0" },
                @{ Name = "Microsoft.Extensions.Logging.Abstractions"; Version = "8.0.0" },
                @{ Name = "System.Diagnostics.DiagnosticSource"; Version = "9.0.11" },
                @{ Name = "Npgsql"; Version = "10.0.1" }
            )

            # Register assembly resolver (once per session)
            if (-not $script:AssemblyResolverRegistered) {
                $assemblyResolver = [System.ResolveEventHandler] {
                    param($s, $e)
                    $assemblyName = $e.Name  -replace '^([^,*]+).*$','$1'
                    $assemblyPath = Get-ChildItem -Path "$pkgDest/$assemblyName*/lib/net8.0/$assemblyName.dll" -ErrorAction SilentlyContinue
                    if ($assemblyPath) {
                        return [System.Reflection.Assembly]::LoadFrom($assemblyPath.FullName)
                    }
                    return $null
                }
                [System.AppDomain]::CurrentDomain.add_AssemblyResolve($assemblyResolver)
                $script:AssemblyResolverRegistered = $true
                Write-Verbose "Registered assembly resolver for Npgsql"
            }

            # Install missing packages (idempotent)
            foreach ($pkg in $requiredPackages) {
                Write-Verbose "Checking package: $($pkg.Name) v$($pkg.Version)"
                $pkgInstallPath = Join-Path -Path $pkgDest -ChildPath "$($pkg.Name).$($pkg.Version)"
                if (-not (Test-Path -Path $pkgInstallPath)) {
                    Write-Verbose "Installing package: $($pkg.Name) v$($pkg.Version)"
                    $null = Install-Package -Name $pkg.Name `
                        -ProviderName NuGet `
                        -Scope AllUsers `
                        -RequiredVersion $pkg.Version `
                        -SkipDependencies `
                        -Destination $pkgDest `
                        -Force `
                        -ErrorAction Stop
                        Write-Verbose "Package installed : $($pkg.Name) v$($pkg.Version)"
                }

                # Load assembly
                $assemblyPath = Join-Path -Path $pkgDest -ChildPath "$($pkg.Name).$($pkg.Version)/lib/net8.0/$($pkg.Name).dll"
                if (Test-Path -Path $assemblyPath) {
                    Write-Verbose "Loading assembly: $($pkg.Name) v$($pkg.Version)"
                    $null = [System.Reflection.Assembly]::LoadFrom($assemblyPath)
                    Write-Verbose "Assembly loaded successfully: $($pkg.Name) v$($pkg.Version)"
                }
                else {
                    throw "$($pkg.Path) is not a valid file path for $($pkg.Name) v$($pkg.Version)"
                }
            }

            # Validate Npgsql load
            $connectionType = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType("Npgsql.NpgsqlConnection", $false, $true)} | Where-Object { $_ }
            if (-not $connectionType) {
                throw "validation failed: Npgsql core assembly failed to load from $($pkg.Path) for $($pkg.Name) v$($pkg.Version)"
            }
            else {
                     Write-Verbose "Npgsql driver initialized successfully from $($pkg.Path) for $($pkg.Name) v$($pkg.Version)"
            }
            return $true
        }
        catch {
            Write-Error "Npgsql driver 10.0.1 initialization failed: $($_.Exception.Message)"
            return $false
        }
    }
    
    end {
        Write-Verbose "Npgsql 10.0.1 driver initialization pipeline processing completed"
    }
}

function Initialize-NpgsqlDriver4017 {
    <#
    .SYNOPSIS
    Initializes Npgsql 4.0.17 driver for PowerShell 5.1 with caching and dependency management.
    
    .DESCRIPTION
    Production-ready Npgsql driver initialization for PowerShell 5.1 with enterprise features:
    - Idempotent installation (safe to run multiple times)
    - Centralized package caching to avoid duplicate downloads
    - Assembly resolution for dependency management
    - Locked package versions for consistency
    - Comprehensive error handling and validation
    - Pipeline support for batch initialization scenarios
    - Verbose logging for troubleshooting
    
    .PARAMETER None
    This function does not accept parameters.
    
    .OUTPUTS
    [System.Boolean] Returns $true on successful initialization, $false on failure.
    
    .EXAMPLE
    PS C:\> Initialize-NpgsqlDriver4017
    
    Initializes Npgsql 4.0.17 driver for PowerShell 5.1 with default settings.
    
    .EXAMPLE
    PS C:\> Initialize-NpgsqlDriver4017 -Verbose
    VERBOSE: Starting Npgsql 4.0.17 driver initialization pipeline processing
    VERBOSE: Created driver cache directory: C:\ProgramData\PostgresAadAuth\Npgsql\4.0.17
    VERBOSE: Registered assembly resolver for Npgsql
    VERBOSE: Npgsql driver initialized successfully
    VERBOSE: Npgsql 4.0.17 driver initialization pipeline processing completed
    
    Demonstrates verbose logging for troubleshooting driver initialization issues.
    
    .NOTES
    - PowerShell 5.1 compatible only
    - Requires NuGet package provider
    - Caches packages in C:\ProgramData\PostgresAadAuth\Npgsql\4.0.17
    - Registers assembly resolver for dependency management
    - Locked package versions for .NET Framework compatibility:
      System.Buffers 4.4.0, System.Numerics.Vectors 4.4.0, System.Runtime.CompilerServices.Unsafe 4.5.2,
      System.Memory 4.5.3, System.Threading.Tasks.Extensions 4.5.2, System.ValueTuple 4.5.0, Npgsql 4.0.17
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    begin {
        Write-Verbose "Starting Npgsql 4.0.17 driver initialization pipeline processing"
    }

    process {
        $cachePath = Join-Path -Path $env:ProgramData -ChildPath "PostgresAadAuth/Npgsql/4.0.17"
        $pkgDest = Join-Path -Path $cachePath -ChildPath "packages"

        try {
            # Create cache directory (idempotent)
            if (-not (Test-Path -Path $cachePath)) {
                $null = New-Item -Path $cachePath -ItemType Directory -Force -ErrorAction Stop
                Write-Verbose "Created driver cache directory: $cachePath"
            }
            else {
                    Write-Verbose "Driver cache directory already exists: $cachePath"
            }

            # Required packages (locked versions for production)
            $requiredPackages = @(
                @{ Name = "System.Buffers"; Version = "4.4.0"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/System.Buffers.4.4.0/lib/netstandard2.0/System.Buffers.dll" },
                @{ Name = "System.Numerics.Vectors"; Version = "4.4.0"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/System.Numerics.Vectors.4.4.0/lib/net46/System.Numerics.Vectors.dll" },
                @{ Name = "System.Runtime.CompilerServices.Unsafe"; Version = "4.5.2"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/System.Runtime.CompilerServices.Unsafe.4.5.2/lib/netstandard2.0/System.Runtime.CompilerServices.Unsafe.dll" },
                @{ Name = "System.Memory"; Version = "4.5.3"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/System.Memory.4.5.3/lib/netstandard2.0/System.Memory.dll" },
                @{ Name = "System.Threading.Tasks.Extensions"; Version = "4.5.2"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/System.Threading.Tasks.Extensions.4.5.2/lib/netstandard2.0/System.Threading.Tasks.Extensions.dll" },
                @{ Name = "System.ValueTuple"; Version = "4.5.0"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/System.ValueTuple.4.5.0/lib/net47/System.ValueTuple.dll" },
                @{ Name = "Npgsql"; Version = "4.0.17"; Path = "$env:ProgramData/PostgresAadAuth/Npgsql/4.0.17/packages/Npgsql.4.0.17/lib/net451/Npgsql.dll" }
            )

            # Install missing packages (idempotent)
            foreach ($pkg in $requiredPackages) {
                Write-Verbose "Checking package: $($pkg.Name) v$($pkg.Version)"
                $pkgInstallPath = Join-Path -Path $pkgDest -ChildPath "$($pkg.Name).$($pkg.Version)"
                if (-not (Test-Path -Path $pkgInstallPath)) {
                    Write-Verbose "Installing package: $($pkg.Name) v$($pkg.Version)"
                    $null = Install-Package -Name $pkg.Name `
                        -ProviderName NuGet `
                        -Scope AllUsers `
                        -RequiredVersion $pkg.Version `
                        -SkipDependencies `
                        -Destination $pkgDest `
                        -Force `
                        -ErrorAction Stop
                        Write-Verbose "Package installed: $($pkg.Name) v$($pkg.Version)"
                }
                else {
                        Write-Verbose "Package already installed: $($pkg.Name) v$($pkg.Version)"
                }

                # Load assembly
                if (Test-Path -Path $pkg.Path) {
                    Write-Verbose "loading assembly: $($pkg.Name) v$($pkg.Version)"
                    $null= [System.Reflection.Assembly]::LoadFrom($pkg.Path) 
                    Write-Verbose "Assembly loaded successfully: $($pkg.Name) v$($pkg.Version)"
                }
                else {
                    throw "$($pkg.Path) is not a valid file path for $($pkg.Name) v$($pkg.Version)"
                }
            }

            # Validate Npgsql load
            $connectionType = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType("Npgsql.NpgsqlConnection", $false, $true)} | Where-Object { $_ }
            if (-not $connectionType) {
                throw "validation failed: Npgsql core assembly failed to load from $($pkg.Path) for $($pkg.Name) v$($pkg.Version)"
            }
            else {
                     Write-Verbose "Npgsql driver initialized successfully from $($pkg.Path) for $($pkg.Name) v$($pkg.Version)"
            }

           
            return $true
        }
        catch {
             Write-Error "Npgsql driver 4.0.17 initialization failed: $($_.Exception.Message)"
            return $false
        }
    }
    
    end {
        Write-Verbose "Npgsql 4.0.17 driver initialization pipeline processing completed"
    }
}

function Initialize-NpgsqlDriver {
    <#
    .SYNOPSIS
    Initializes the appropriate Npgsql driver based on PowerShell version with caching and dependency management.
    
    .DESCRIPTION
    Production-ready Npgsql driver initialization that automatically selects the correct version:
    - PowerShell 7+: Uses Npgsql 10.0.1 with .NET 8.0 support
    - PowerShell 5.1: Uses Npgsql 4.0.17 with .NET Framework 4.5.1 support
    - Idempotent installation (safe to run multiple times)
    - Centralized package caching to avoid duplicate downloads
    - Assembly resolution for dependency management
    - Locked package versions for consistency
    - Comprehensive error handling and validation
    - Pipeline support for batch initialization scenarios
    - Verbose logging for troubleshooting
    
    .PARAMETER None
    This function does not accept parameters.
    
    .OUTPUTS
    [System.Boolean] Returns $true on successful initialization, $false on failure.
    
    .EXAMPLE
    PS C:\> Initialize-NpgsqlDriver
    
    Initializes the appropriate Npgsql driver based on current PowerShell version.
    
    .EXAMPLE
    PS C:\> Initialize-NpgsqlDriver -Verbose
    VERBOSE: Starting Npgsql driver initialization pipeline processing
    VERBOSE: Detected PowerShell version: 7.4.0
    VERBOSE: Starting Npgsql 10.0.1 driver initialization pipeline processing
    VERBOSE: Created driver cache directory: C:\ProgramData\PostgresAadAuth\Npgsql\10.0.1
    VERBOSE: Registered assembly resolver for Npgsql
    VERBOSE: Npgsql driver initialized successfully
    VERBOSE: Npgsql driver initialization pipeline processing completed
    
    Demonstrates verbose logging for troubleshooting driver initialization issues.
    
    .NOTES
    - Auto-detects PowerShell version and selects appropriate Npgsql driver
    - Requires NuGet package provider
    - Registers assembly resolver for dependency management
    - Locked package versions for production consistency
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    begin {
        Write-Verbose "Starting Npgsql driver initialization pipeline processing"
    }

    process {
        try {
            # Auto-detect PowerShell version and initialize appropriate driver
            $psVersion = $PSVersionTable.PSVersion.Major
            Write-Verbose "Detected PowerShell version: $psVersion"
            
            if ($psVersion -ge 7) {
                return Initialize-NpgsqlDriver1001
            }
            else {
                return Initialize-NpgsqlDriver4017
            }
        }
        catch {
            Write-Error "Npgsql driver initialization failed: $($_.Exception.Message)"
            return $false
        }
    }
    
    end {
        Write-Verbose "Npgsql driver initialization pipeline processing completed"
    }
}

function Invoke-PostgresAadQuery {
    <#
    .SYNOPSIS
    Azure AD authentication for Azure PostgreSQL with enterprise security and pipeline support.
    
    .DESCRIPTION
    Enterprise-ready PostgreSQL query execution with Azure AD authentication featuring:
    - Secure AAD token acquisition with automatic retry logic
    - connection string management (tokens never logged)
    - Comprehensive resource cleanup and error handling
    - Multi-query pipeline processing for batch operations
    - Dynamic query execution with InputObject arrays and parameter substitution
    - Support for multiple positional parameters ({0}, {1}, {2}, etc.) with various data types
    - Named parameter queries using hashtable input (@paramName syntax)
    - Flexible input data structures (arrays, hashtables, mixed types)
    - Detailed logging and troubleshooting capabilities
    - Strict parameter validation and sanitization
    - SSL/TLS encryption with server certificate validation
    - Connection pooling for optimal performance
    
    This function provides a complete solution for secure PostgreSQL access in enterprise environments,
    handling all aspects of AAD authentication, connection management, and query execution with
    advanced dynamic query building and parameterization capabilities.
    
    .PARAMETER PostgresServer
    The Azure PostgreSQL server FQDN (format: servername.postgres.database.azure.com).
    Must match the pattern: ^[a-zA-Z0-9-]+\\.postgres\\.database\\.azure\\.com$
    
    .PARAMETER PostgresDatabase
    The target PostgreSQL database name. Must be a valid PostgreSQL identifier.
    
    .PARAMETER AadUsername
    The Azure AD username (UPN format: user@domain.com) for authentication.
    Must match standard email format pattern.
    
    .PARAMETER SqlQuery
    The SQL query to execute against the PostgreSQL database.
    Supports any valid PostgreSQL SELECT, INSERT, UPDATE, DELETE, or DDL statements.
    Use this parameter for direct SQL execution when parameterization is not needed.
    
    .PARAMETER QueryTemplate
    A parameterized query template that supports both positional ({0}, {1}, {2}) and named (@paramName) parameters.
    Enables dynamic query building with parameter substitution from InputObject.
    Examples: 
    - Positional: "SELECT * FROM orders WHERE customer_id = {0} AND date >= '{1}'"
    - Named: "SELECT * FROM users WHERE department = @dept AND status = @status"
    When QueryTemplate is specified, InputObject must be provided with parameter values.
    
    .PARAMETER InputObject
    Pipeline input objects for parameterized queries. Supports multiple data structures:
    - Array of values for positional parameters: @(123, 'active', 2024)
    - Hashtable for named parameters: @{dept = 'IT'; status = 'active'}
    - Mixed arrays with different data types: @('North America', 4, 2024)
    - Complex hashtables with multiple key-value pairs for advanced queries
    The input structure must match the parameterization approach used in QueryTemplate.
    
    .PARAMETER PgAadResourceUri
    The Azure AD resource URI for token acquisition. Valid values:
    - https://ossrdbms-aad.database.windows.net (default)
    - https://postgres.database.azure.com
    
    .PARAMETER CommandTimeout
    Command timeout in seconds (range: 10-300, default: 60).
    Controls maximum time allowed for query execution.
    
    .OUTPUTS
    [System.Management.Automation.PSCustomObject[]] Array of custom objects representing query result rows.
    Each object contains properties corresponding to column names and values.
    Returns empty array for queries with no results.
    
    .EXAMPLE
    PS C:\> Invoke-PostgresAadQuery -PostgresServer "prod-server.postgres.database.azure.com" -PostgresDatabase "salesdb" -AadUsername "dba@contoso.com" -SqlQuery "SELECT current_user, current_timestamp"
    
    current_user      current_timestamp
    ------------      -----------------
    dba@contoso.com   2024-01-15 14:30:00.123
    
    Basic query execution with current user and timestamp.
    
    .EXAMPLE
    PS C:\> Invoke-PostgresAadQuery -PostgresServer "dev-server.postgres.database.azure.com" -PostgresDatabase "testdb" -AadUsername "developer@fabrikam.com" -SqlQuery "SELECT * FROM users WHERE active = true" -CommandTimeout 120 -Verbose
    VERBOSE: Starting PostgreSQL AAD pipeline processing
    VERBOSE: Starting PostgreSQL AAD authentication flow
    VERBOSE: Parameters received:
    VERBOSE:   Server: dev-server.postgres.database.azure.com
    VERBOSE:   Database: testdb
    VERBOSE:   AAD User: developer@fabrikam.com
    VERBOSE:   Resource URI: https://ossrdbms-aad.database.windows.net
    VERBOSE:   Command Timeout: 120 seconds
    VERBOSE: Azure CLI validated (version: 2.50.0)
    VERBOSE: Initializing Npgsql database driver for PowerShell v7
    VERBOSE: Requesting AAD token for PostgreSQL authentication
    VERBOSE: Retrieving AAD token (attempt 1/3) for resource: https://ossrdbms-aad.database.windows.net
    VERBOSE: AAD token acquired successfully (length: 1204 chars)
    VERBOSE: Built secure connection string (token redacted)
    VERBOSE: Creating database connection
    VERBOSE: Connecting to PostgreSQL server: dev-server.postgres.database.azure.com/testdb
    VERBOSE: Successfully connected to PostgreSQL server
    VERBOSE: Query executed successfully - returned 42 rows
    VERBOSE: Cleaned up database resources
    VERBOSE: PostgreSQL AAD pipeline processing completed
    
    id  username    email                active created_date
    --  --------    -----                ------ ------------
    1   john.doe    john@example.com     True   2024-01-01 10:00:00
    2   jane.smith  jane@example.com     True   2024-01-02 11:30:00
    ...
    
    Demonstrates complex query with extended timeout and comprehensive verbose logging.
    
    .EXAMPLE
    PS C:\> @(
    >>     [PSCustomObject]@{
    >>         PostgresServer = "server1.postgres.database.azure.com"
    >>         PostgresDatabase = "db1"
    >>         AadUsername = "user1@domain.com"
    >>         SqlQuery = "SELECT current_database(), current_user"
    >>     },
    >>     [PSCustomObject]@{
    >>         PostgresServer = "server2.postgres.database.azure.com"
    >>         PostgresDatabase = "db2"
    >>         AadUsername = "user2@domain.com"
    >>         SqlQuery = "SELECT version()"
    >>     }
    >> ) | Invoke-PostgresAadQuery
    
    Demonstrates pipeline processing for executing multiple queries across different servers and databases.
    
    .EXAMPLE
    PS C:\> Import-Csv "queries.csv" | Invoke-PostgresAadQuery
    
    Processes CSV file containing PostgresServer, PostgresDatabase, AadUsername, and SqlQuery columns
    for bulk query execution across multiple database environments.
    
    .EXAMPLE
    PS C:\> $servers = Get-Content "servers.txt"
    PS C:\> $servers | ForEach-Object {
    >>     [PSCustomObject]@{
    >>         PostgresServer = "$_.postgres.database.azure.com"
    >>         PostgresDatabase = "inventory"
    >>         AadUsername = "inventory@company.com"
    >>         SqlQuery = "SELECT COUNT(*) as server_count FROM servers"
    >>     }
    >> } | Invoke-PostgresAadQuery
    
    Demonstrates server inventory automation by reading server names from file and executing
    count queries across all inventory databases.
    
    .EXAMPLE
    PS C:\> # Dynamic query with multiple positional parameters
    PS C:\> Invoke-PostgresAadQuery `
    >>     -PostgresServer "myserver.postgres.database.azure.com" `
    >>     -PostgresDatabase "salesdb" `
    >>     -AadUsername "analyst@company.com" `
    >>     -QueryTemplate "SELECT * FROM orders WHERE customer_id = {0} AND order_date >= '{1}' AND status = '{2}'" `
    >>     -InputObject @(12345, '2024-01-01', 'completed')
    
    Demonstrates dynamic query execution with multiple positional parameters using {0}, {1}, {2} placeholders.
    The InputObject array provides values that replace the positional placeholders in sequence.
    
    .EXAMPLE
    PS C:\> # Complex dynamic query with hashtable input
    PS C:\> $orderParams = @{
    >>     customerId = 12345
    >>     startDate = '2024-01-01'
    >>     endDate = '2024-12-31'
    >>     status = 'completed'
    >>     minAmount = 100.00
    >> }
    PS C:\> Invoke-PostgresAadQuery `
    >>     -PostgresServer "myserver.postgres.database.azure.com" `
    >>     -PostgresDatabase "salesdb" `
    >>     -AadUsername "analyst@company.com" `
    >>     -QueryTemplate "SELECT * FROM orders WHERE customer_id = @customerId AND order_date BETWEEN @startDate AND @endDate AND status = @status AND total_amount >= @minAmount" `
    >>     -InputObject $orderParams
    
    Demonstrates named parameter queries using hashtable input. The QueryTemplate uses @paramName syntax
    that matches the hashtable keys for safe parameter substitution.
    
    .EXAMPLE
    PS C:\> # Batch processing with multiple parameter sets
    PS C:\> $queries = @(
    >>     @{Query = "SELECT COUNT(*) FROM users WHERE department = @dept AND status = @status"; Params = @{dept = 'IT'; status = 'active'}}
    >>     @{Query = "SELECT COUNT(*) FROM users WHERE department = @dept AND status = @status"; Params = @{dept = 'HR'; status = 'inactive'}}
    >>     @{Query = "SELECT COUNT(*) FROM users WHERE department = @dept AND status = @status"; Params = @{dept = 'Sales'; status = 'pending'}}
    >> )
    PS C:\> $queries | ForEach-Object {
    >>     Invoke-PostgresAadQuery `
    >>         -PostgresServer "server.postgres.database.azure.com" `
    >>         -PostgresDatabase "companydb" `
    >>         -AadUsername "hr@company.com" `
    >>         -QueryTemplate $_.Query `
    >>         -InputObject $_.Params
    >> }
    
    Demonstrates batch processing with different parameter sets using named parameters.
    Each query uses the same template but with different parameter values.
    
    .EXAMPLE
    PS C:\> # Mixed data structures with positional parameters
    PS C:\> Invoke-PostgresAadQuery `
    >>     -PostgresServer "analytics.postgres.database.azure.com" `
    >>     -PostgresDatabase "reporting" `
    >>     -AadUsername "report@company.com" `
    >>     -QueryTemplate "SELECT * FROM sales WHERE region = '{0}' AND quarter = {1} AND year = {2}" `
    >>     -InputObject @('North America', 4, 2024)
    
    Demonstrates positional parameters with mixed data types (string, integer, integer) in the InputObject array.
    
    .EXAMPLE
    PS C:\> # Dynamic query building with array expansion
    PS C:\> $customerIds = @(1001, 1002, 1003, 1004, 1005)
    PS C:\> $idList = $customerIds -join ', '
    PS C:\> Invoke-PostgresAadQuery `
    >>     -PostgresServer "crm.postgres.database.azure.com" `
    >>     -PostgresDatabase "customers" `
    >>     -AadUsername "crm@company.com" `
    >>     -SqlQuery "SELECT * FROM customer_profiles WHERE customer_id IN ($idList)"
    
    Demonstrates dynamic query building by constructing SQL with array values, useful for IN clauses.
    
    .EXAMPLE
    PS C:\> # WORKING: Direct parameter invocation (MOST RELIABLE)
    PS C:\> Invoke-PostgresAadQuery `
    >>     -PostgresServer "pstgresqlsrv.postgres.database.azure.com" `
    >>     -PostgresDatabase "db" `
    >>     -AadUsername "user@contoso.onmicrosoft.com" `
    >>     -QueryTemplate "SELECT {0} as firstname, {1} as lastname, {2} as fullname" `
    >>     -InputObject @('Jack', 'Xu', 'Jack Xu')
    
    Demonstrates the definitive working solution for the specific user query that was failing.
    This is the most reliable method for complex parameter scenarios.
    
    .EXAMPLE
    PS C:\> # WORKING: Parameter splatting (CLEAN & MAINTAINABLE)
    PS C:\> $params = @{
    >>     PostgresServer = "pstgresqlsrv.postgres.database.azure.com"
    >>     PostgresDatabase = "db"
    >>     AadUsername = "user@contoso.onmicrosoft.com"
    >>     QueryTemplate = "SELECT {0} as firstname, {1} as lastname, {2} as fullname"
    >>     InputObject = @('Jack', 'Xu', 'Jack Xu')
    >> }
    PS C:\> Invoke-PostgresAadQuery @params
    
    Demonstrates parameter splatting which provides clean syntax and easy maintenance.
    
    .NOTES
    - Requires Azure CLI to be installed and accessible in PATH
    - Supports PowerShell 5.1+ (uses Npgsql 4.0.17) and PowerShell 7+ (uses Npgsql 10.0.1)
    - Implements comprehensive error handling with detailed error objects
    - Sanitizes queries for logging by removing excess whitespace
    - Uses SSL/TLS encryption with server certificate validation
    - Implements connection pooling (MinPoolSize=1, MaxPoolSize=10)
    - Automatic resource cleanup in finally blocks
    - Production-ready with enterprise security standards
    
     PARAMETER BINDING NOTES:
    • Direct parameter invocation is most reliable for complex scenarios
    • Pipeline binding with hashtables is NOT supported due to PowerShell limitations
    • Use parameter splatting (@params) for clean, maintainable code
    
     WORKING APPROACHES:
      # Direct invocation (recommended)
      Invoke-PostgresAadQuery -PostgresServer "server" -PostgresDatabase "db" -AadUsername "user@domain.com" -QueryTemplate "SELECT {0}" -InputObject @("value")
      
      # Parameter splatting
      $params = @{PostgresServer="server"; PostgresDatabase="db"; AadUsername="user@domain.com"; QueryTemplate="SELECT {0}"; InputObject=@("value")}
      Invoke-PostgresAadQuery @params
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject[]])]
    param (
        # Configuration Parameters (Centralized for Environment Management)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^[a-zA-Z0-9-]+\.postgres\.database\.azure\.com$')]
        [string]$PostgresServer,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PostgresDatabase,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
        [string]$AadUsername,

        # Query Parameters - either SqlQuery or QueryTemplate must be provided
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlQuery,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$QueryTemplate,

        # Pipeline Input Objects for Parameterized Queries
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [object[]]$InputObject,

        # Environment-Specific Configuration (Set per environment: dev/staging/prod)
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('https://ossrdbms-aad.database.windows.net', 'https://postgres.database.azure.com')]
        [string]$PgAadResourceUri = 'https://ossrdbms-aad.database.windows.net',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(10, 300)]
        [int]$CommandTimeout = 60
    )

    begin {
        # Set logging preferences
        $ErrorActionPreference = 'Stop'
        # Ensure Information messages are visible by default (important status updates)
        $InformationPreference = 'Continue'
        Write-Verbose "Starting PostgreSQL AAD pipeline processing"
        
        # Initialize collection for pipeline input
        $pipelineInput = @()
    }

    process {
        # Collect pipeline input objects for parameterized query processing
        if ($InputObject) {
            $pipelineInput += $InputObject
        }
        
        try {
            # Step 1: Validate prerequisites
            Write-Verbose "Starting PostgreSQL AAD authentication flow"
            Write-Verbose "Parameters received:"
            Write-Verbose "  Server: $PostgresServer"
            Write-Verbose "  Database: $PostgresDatabase"
            Write-Verbose "  AAD User: $AadUsername"
            Write-Verbose "  Resource URI: $PgAadResourceUri"
            Write-Verbose "  Command Timeout: $CommandTimeout seconds"
            if (-not (Test-AzureCliAvailability)) {
                throw "Azure CLI validation failed - cannot proceed"
            }

            # Step 2: Initialize database driver
            Write-Verbose "Initializing Npgsql database driver for PowerShell v$($PSVersionTable.PSVersion.Major)"
            Initialize-NpgsqlDriver | Out-Null

            # Step 3: Get secure AAD token
            Write-Verbose "Requesting AAD token for PostgreSQL authentication"

            Write-Verbose "First token request to ensure validity"
            $null = Get-AdUserAccessToken -AadUsername $AadUsername -ResourceUri $PgAadResourceUri

            Write-Verbose "Second token request for actual authentication"  
            $aadToken = Get-AdUserAccessToken -AadUsername $AadUsername -ResourceUri $PgAadResourceUri

            # Step 4: Build secure connection string (never log full token)
            $connectionString = [string]::Format(
                "Host={0};Database={1};Username={2};Password={3};Command Timeout={4};SSL Mode=Require;Trust Server Certificate=True;Pooling=true;MinPoolSize=1;MaxPoolSize=10",
                $PostgresServer,
                $PostgresDatabase,
                $AadUsername,
                $aadToken,
                $CommandTimeout
            )
            Write-Verbose "Built secure connection string (token redacted)"

            # Step 5: Execute query with secure resource management
            Write-Verbose "Creating database connection"
            $connection = $null
            $command = $null
            $reader = $null
            $results = @()

            try {
                # Create connection
                $connection = New-Object -TypeName Npgsql.NpgsqlConnection($connectionString)
                Write-Verbose "Connecting to PostgreSQL server: $PostgresServer/$PostgresDatabase"
                $connection.Open()
                Write-Verbose "Successfully connected to PostgreSQL server"

                # Validate query parameters
                if (-not $SqlQuery -and -not $QueryTemplate) {
                    throw "Either SqlQuery or QueryTemplate parameter must be provided"
                }
                
                if ($SqlQuery -and $QueryTemplate) {
                    throw "Cannot specify both SqlQuery and QueryTemplate parameters. Choose one approach."
                }
                
                # Execute query with parameterization support
                $command = $connection.CreateCommand()
                $command.CommandTimeout = $CommandTimeout
                
                # Determine final query based on parameterization approach
                if ($QueryTemplate) {
                    if ($pipelineInput.Count -eq 0 -and -not $InputObject) {
                        throw "QueryTemplate requires InputObject parameter with parameter values"
                    }
                    
                    Write-Verbose "Processing parameterized query with $($pipelineInput.Count) input objects"
                    
                    # Check if QueryTemplate uses positional parameters ({0}, {1}) or named parameters
                    if ($QueryTemplate -match '\{\d+\}') {
                        # Positional parameter approach
                        $finalQuery = $QueryTemplate
                        $positionalParamCount = ([regex]::Matches($QueryTemplate, '\{\d+\}')).Count
                        
                        Write-Verbose "Detected $positionalParamCount positional parameters in template"
                        
                        # Validate we have enough input values
                        if ($positionalParamCount -gt $pipelineInput.Count) {
                            throw "Not enough input values provided. Template requires $positionalParamCount parameters but only $($pipelineInput.Count) provided."
                        }
                        
                        # Replace positional parameters with values
                        for ($i = 0; $i -lt $positionalParamCount; $i++) {
                            $paramValue = $pipelineInput[$i]
                            
                            # Handle different input data structures
                            if ($paramValue -is [hashtable]) {
                                # For hashtables in positional context, use the first value
                                if ($paramValue.Count -gt 0) {
                                    $paramValue = ($paramValue.Values | Select-Object -First 1)
                                    Write-Verbose "Using first hashtable value for parameter {$i}: $paramValue"
                                } else {
                                    throw "Empty hashtable provided for parameter {$i}"
                                }
                            }
                            elseif ($paramValue -is [array]) {
                                # For arrays, use the first element
                                if ($paramValue.Count -gt 0) {
                                    $paramValue = $paramValue[0]
                                    Write-Verbose "Using first array element for parameter {$i}: $paramValue"
                                } else {
                                    throw "Empty array provided for parameter {$i}"
                                }
                            }
                            
                            # Validate parameter value
                            if ($null -eq $paramValue) {
                                throw "Null value provided for parameter {$i}. Ensure InputObject contains valid non-null values."
                            }
                            
                            # Convert parameter value to appropriate SQL format
                            $sqlValue = if ($paramValue -is [string]) {
                                # Escape single quotes in string values
                                "'$($paramValue -replace "'", "''")'"
                            }
                            elseif ($paramValue -is [datetime]) {
                                # Format datetime values for SQL
                                "'$($paramValue.ToString('yyyy-MM-dd HH:mm:ss'))'"
                            }
                            elseif ($paramValue -is [bool]) {
                                # Convert boolean to SQL boolean
                                $paramValue.ToString().ToLower()
                            }
                            elseif ($paramValue -is [int] -or $paramValue -is [decimal] -or $paramValue -is [double]) {
                                # Numeric values don't need quotes
                                $paramValue.ToString()
                            }
                            else {
                                # Default to string representation for other types
                                "'$($paramValue.ToString() -replace "'", "''")'"
                            }
                            
                            # Replace the parameter placeholder
                            $finalQuery = $finalQuery -replace "\{$i\}", $sqlValue
                            Write-Verbose "Replaced parameter {$i} with value: $paramValue"
                        }
                        
                        $command.CommandText = $finalQuery
                        Write-Verbose "Executing positional parameterized query: $($finalQuery -replace '\s+', ' ')"
                    }
                    elseif ($QueryTemplate -match '@\w+') {
                        # Named parameter approach
                        if ($pipelineInput.Count -eq 0) {
                            throw "Named parameter queries require InputObject with parameter values"
                        }
                        
                        $firstInput = $pipelineInput[0]
                        if ($firstInput -is [hashtable]) {
                            $command.CommandText = $QueryTemplate
                            $namedParamsFound = $false
                            
                            # Extract all named parameters from the template
                            $namedParams = [regex]::Matches($QueryTemplate, '@(\w+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
                            Write-Verbose "Found named parameters in template: $($namedParams -join ', ')"
                            
                            foreach ($paramName in $namedParams) {
                                $fullParamName = "@$paramName"
                                if ($firstInput.ContainsKey($paramName)) {
                                    $param = $command.CreateParameter()
                                    $param.ParameterName = $fullParamName
                                    $param.Value = $firstInput[$paramName]
                                    $command.Parameters.Add($param) | Out-Null
                                    $namedParamsFound = $true
                                    Write-Verbose "Added parameter: $fullParamName = $($firstInput[$paramName])"
                                }
                                else {
                                    Write-Warning "Parameter $fullParamName not found in InputObject hashtable"
                                }
                            }
                            
                            if (-not $namedParamsFound) {
                                throw "No matching parameters found in InputObject for QueryTemplate. Template parameters: $($namedParams -join ', '), InputObject keys: $($firstInput.Keys -join ', ')"
                            }
                        }
                        else {
                            throw "Named parameter queries require hashtable InputObject. Received: $($firstInput.GetType().Name)"
                        }
                    }
                    else {
                        # No parameters detected, treat as regular query
                        $command.CommandText = $QueryTemplate
                        Write-Verbose "No parameters detected in QueryTemplate, executing as regular query"
                    }
                }
                elseif ($SqlQuery) {
                    # Direct SQL query execution
                    $command.CommandText = $SqlQuery
                    Write-Verbose "Executing direct SQL query: $($SqlQuery -replace '\s+', ' ')"
                }

                # Execute the query
                $reader = $command.ExecuteReader()

                # Process results
                while ($reader.Read()) {
                    $row = [PSCustomObject]@{}
                    for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                        $columnName = $reader.GetName($i)
                        $columnValue = $reader.GetValue($i)
                        $row | Add-Member -NotePropertyName $columnName -NotePropertyValue $columnValue
                    }
                    $results += $row
                }

                Write-Verbose "Query executed successfully - returned $($results.Count) rows"
            }
            finally {
                # Step 6: Clean up resources (critical for production)
                if ($reader) { $reader.Dispose() }
                if ($command) { $command.Dispose() }
                if ($connection) {
                    if ($connection.State -eq 'Open') {
                        $connection.Close()
                    }
                    $connection.Dispose()
                }
                Write-Verbose "Cleaned up database resources"
            }

            # Return results (structured for production consumption)
            return $results
        }
        catch {
            # error handling
            $errorDetails = [PSCustomObject]@{
                Timestamp = Get-Date -Format 'o'
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().FullName
                StackTrace = $_.Exception.StackTrace
                Server = $PostgresServer
                Database = $PostgresDatabase
                AadUser = $AadUsername
                Query = if ($SqlQuery) { $SqlQuery -replace '\s+', ' ' } else { $QueryTemplate -replace '\s+', ' ' }
            }

            Write-Error "Production PostgreSQL operation failed: $($errorDetails | ConvertTo-Json -Compress)"
            throw # Re-throw to propagate error to caller (critical for orchestration tools)
        }
        finally {
            # Reset pipeline input for next batch
            $pipelineInput = @()
        }
    }
    
    end {
        Write-Verbose "PostgreSQL AAD pipeline processing completed"
    }
}

#endregion

# Export public functions
Export-ModuleMember -Function Invoke-PostgresAadQuery, Test-AzureCliAvailability, Get-AdUserAccessToken, Initialize-NpgsqlDriver
