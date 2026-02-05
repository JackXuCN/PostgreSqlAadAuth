<#
.SYNOPSIS
    Module manifest for PostgreSqlAadAuth - Production-grade Azure AD authentication for Azure PostgreSQL.

.DESCRIPTION
    This module provides enterprise-ready Azure AD authentication for Azure PostgreSQL with comprehensive
    security features, pipeline support, and production-grade error handling.

.NOTES
    Version:        1.0.0
    Author:         Jack Xu
    Company:        Jack Xu
    Copyright:      (c) 2026 Jack Xu. All rights reserved.
    Tags:           PostgreSQL, Azure, AAD, Authentication, Production, Enterprise, Security, Pipeline, DynamicQueries, ParameterizedQueries, InputObject, PositionalParameters, NamedParameters
#>

@{
    # Script module or binary module file associated with this manifest
    RootModule = 'PostgreSqlAadAuth.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'b985699f-1718-48c9-9d11-4c59aa720e79'

    # Author of this module
    Author = 'Jack Xu'

    # Company or vendor of this module
    CompanyName = 'Jack Xu'

    # Copyright statement for this module
    Copyright = '(c) 2026 Jack Xu. All rights reserved.'

    # Description of the functionality provided by this module
    Description = @'
Production-grade Azure AD authentication for Azure PostgreSQL using Azure CLI with
advanced dynamic query capabilities. Features enterprise security, comprehensive error
handling, and full PowerShell pipeline support with InputObject arrays, multiple
positional parameters ({0}, {1}, {2}), named parameters (@paramName), and dynamic
query building. Supports parameterized queries with hashtable properties from pipeline
input, batch processing scenarios, type-safe parameter conversion, and SQL injection
prevention. Includes automatic Npgsql driver management for PowerShell 5.1+ and 7+,
multi-attempt retry logic, SSL/TLS encryption, connection pooling, and detailed
documentation with comprehensive examples.
'@

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0'

    # Processor architecture (None, X86, Amd64) required by this module
    ProcessorArchitecture = 'None'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-PostgresAadQuery',
        'Test-AzureCliAvailability', 
        'Get-AdUserAccessToken',
        'Initialize-NpgsqlDriver'
    )
    
    # Enhanced Invoke-PostgresAadQuery now supports:
    # - QueryTemplate parameter for parameterized queries
    # - InputObject parameter for pipeline input with arrays and hashtables
    # - Multiple positional parameters ({0}, {1}, {2})
    # - Named parameters (@paramName) with hashtable input
    # - Type-safe parameter conversion and SQL injection prevention

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # DSC resources to export from this module
    DscResourcesToExport = @()

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @(
        'PostgreSqlAadAuth.psm1',
        'PostgreSqlAadAuth.psd1'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('PostgreSQL', 'Azure', 'AAD', 'Authentication', 'Production', 'Enterprise', 'Security', 'Pipeline', 'DynamicQueries', 'ParameterizedQueries', 'InputObject', 'PositionalParameters', 'NamedParameters')

            # A URL to the license for this module
            LicenseUri = ''

            # A URL to the main website for this project
            ProjectUri = ''

            # A URL to an icon representing this module
            IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
VERSION 1.0.0 - Initial Release
================================
CORE SECURITY FEATURES:
• Production-grade Azure AD authentication for Azure PostgreSQL
• Enterprise security standards with token sanitization
• SSL/TLS encryption with server certificate validation
• Secure connection string management (tokens never logged)

RELIABILITY & PERFORMANCE:
• Multi-attempt retry logic with exponential backoff
• Connection pooling (MinPoolSize=1, MaxPoolSize=10)
• Automatic resource cleanup in finally blocks
• Comprehensive error handling with detailed error objects

INFRASTRUCTURE:
• Full PowerShell pipeline support for all functions
• Automatic Npgsql driver management (PowerShell 5.1+ and 7+)
• Detailed documentation with comprehensive examples
• Cross-platform compatibility (Desktop and Core editions)

DYNAMIC QUERY CAPABILITIES:
• QueryTemplate parameter for parameterized queries
• InputObject parameter for pipeline input with arrays and hashtables
• Multiple positional parameters ({0}, {1}, {2}) with type-safe substitution
• Named parameters (@paramName) with hashtable input validation
• Mixed data type support (string, datetime, boolean, numeric)
• Advanced batch processing with multiple parameter sets
• Dynamic query building with comprehensive error handling

SECURITY ENHANCEMENTS:
• Production-ready parameter sanitization
• SQL injection prevention through parameterized queries
• Type-safe parameter conversion with proper escaping
• Input validation for all parameter types

PIPELINE IMPROVEMENTS:
• Enhanced ValueFromPipeline support for InputObject
• Streamlined batch processing workflows
• Comprehensive parameter validation and error reporting
'@
        } # End of PSData hashtable
    } # End of PrivateData hashtable
}
