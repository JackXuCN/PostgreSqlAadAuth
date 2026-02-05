# PostgreSqlAadAuth PowerShell Module

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/your-username/PostgreSqlAadAuth)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A production-grade PowerShell module for Azure AD authentication with Azure PostgreSQL, featuring enterprise security, comprehensive error handling, and full pipeline support.

## Overview

This module provides secure, reliable Azure AD authentication for Azure PostgreSQL databases using Azure CLI. It includes advanced features for enterprise environments such as dynamic query building, parameterized queries, batch processing, and comprehensive security measures.

## Key Features

- **🔐 Secure Authentication**: Azure AD token-based authentication with automatic token refresh
- **🚀 Pipeline Support**: Full PowerShell pipeline integration with InputObject arrays
- **🛡️ Security**: SQL injection prevention, parameterized queries, and SSL/TLS encryption
- **📊 Dynamic Queries**: Support for positional parameters (`{0}`, `{1}`, `{2}`) and named parameters (`@paramName`)
- **🔄 Batch Processing**: Efficient handling of multiple operations with automatic retry logic
- **🔧 Type Safety**: Automatic parameter type conversion and validation
- **📈 Production Ready**: Comprehensive error handling, logging, and connection pooling

## Prerequisites

- **Azure CLI** (version 2.50.0 or higher)
- **PowerShell** 5.1+ or 7+
- **Npgsql** driver (automatically managed by the module)

## Installation

### Option 1: Manual Installation

1. Download the latest release from the [releases page](https://github.com/your-username/PostgreSqlAadAuth/releases)

2. Extract the module files to your PowerShell modules directory:
   ```powershell
   # Create user-specific module directory
   $modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\PostgreSqlAadAuth"
   New-Item -ItemType Directory -Path $modulePath -Force
   
   # Or system-wide module directory (requires admin privileges)
   # $modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\PostgreSqlAadAuth"
   ```

3. Copy the module files to the target directory:
   - `PostgreSqlAadAuth.psd1`
   - `PostgreSqlAadAuth.psm1`

4. Import the module:
   ```powershell
   Import-Module PostgreSqlAadAuth
   ```

### Option 2: Direct Import

```powershell
# Import directly from the download location
Import-Module .\PostgreSqlAadAuth.psd1
```

## Quick Start

```powershell
# 1. Import the module
Import-Module PostgreSqlAadAuth

# 2. Test prerequisites
if (Test-AzureCliAvailability) {
    # 3. Execute your first query
    $results = Invoke-PostgresAadQuery `
        -PostgresServer "your-server.postgres.database.azure.com" `
        -PostgresDatabase "your-database" `
        -AadUsername "your-user@domain.com" `
        -SqlQuery "SELECT current_database(), current_user, version()"
    
    # 4. View results
    $results | Format-Table -AutoSize
}
```

## Available Functions

### Test-AzureCliAvailability
Validates Azure CLI installation and version compatibility.

```powershell
Test-AzureCliAvailability
```

### Get-AdUserAccessToken
Securely retrieves Azure AD access tokens for PostgreSQL authentication.

```powershell
Get-AdUserAccessToken -AadUsername "user@domain.com" -ResourceUri "https://ossrdbms-aad.database.windows.net"
```

### Initialize-NpgsqlDriver
Automatically initializes the appropriate Npgsql driver based on PowerShell version.

```powershell
Initialize-NpgsqlDriver
```

### Invoke-PostgresAadQuery
Main function for executing queries with Azure AD authentication and dynamic parameter support.

```powershell
Invoke-PostgresAadQuery -PostgresServer "server.postgres.database.azure.com" -PostgresDatabase "db" -AadUsername "user@domain.com" -SqlQuery "SELECT version()"
```

## Usage Examples

### 🔑 Authentication Setup

Before executing queries, ensure Azure CLI is installed and you're authenticated:

```powershell
# Check Azure CLI availability
Test-AzureCliAvailability

# Get Azure AD access token (optional - handled automatically by Invoke-PostgresAadQuery)
$token = Get-AdUserAccessToken -AadUsername "user@domain.com"
```

### Basic Connection and Query
```powershell
# Import the module
Import-Module PostgreSqlAadAuth

# Test Azure CLI availability
if (Test-AzureCliAvailability) {
    # Execute a simple query
    $results = Invoke-PostgresAadQuery `
        -PostgresServer "prod-db.postgres.database.azure.com" `
        -PostgresDatabase "appdb" `
        -AadUsername "dba@contoso.com" `
        -SqlQuery "SELECT version()"
    $results
}
```

### Dynamic Query with Positional Parameters
```powershell
# Using positional parameters {0}, {1}, {2}
$results = Invoke-PostgresAadQuery `
    -PostgresServer "server.postgres.database.azure.com" `
    -PostgresDatabase "salesdb" `
    -AadUsername "analyst@company.com" `
    -QueryTemplate "SELECT * FROM orders WHERE customer_id = {0} AND order_date >= '{1}' AND status = '{2}'" `
    -InputObject @(12345, '2024-01-01', 'completed')
```

### Named Parameters with Hashtable Input
```powershell
# Using named parameters @paramName with hashtable
$params = @{
    customerId = 12345
    startDate = '2024-01-01'
    endDate = '2024-12-31'
    status = 'completed'
    minAmount = 100.00
}

$results = Invoke-PostgresAadQuery `
    -PostgresServer "server.postgres.database.azure.com" `
    -PostgresDatabase "salesdb" `
    -AadUsername "analyst@company.com" `
    -QueryTemplate "SELECT * FROM orders WHERE customer_id = @customerId AND order_date BETWEEN @startDate AND @endDate AND status = @status AND total_amount >= @minAmount" `
    -InputObject $params
```

### Pipeline Processing
```powershell
# Process multiple queries through pipeline
$queries = @(
    @{
        PostgresServer = "server1.postgres.database.azure.com"
        PostgresDatabase = "db1"
        AadUsername = "user1@domain.com"
        SqlQuery = "SELECT current_database(), current_user"
    },
    @{
        PostgresServer = "server2.postgres.database.azure.com"
        PostgresDatabase = "db2"
        AadUsername = "user2@domain.com"
        SqlQuery = "SELECT version()"
    }
)

$queries | Invoke-PostgresAadQuery
```

### Batch Processing with Different Parameter Sets
```powershell
# Batch processing with multiple parameter sets
$queries = @(
    @{
        Query = "SELECT COUNT(*) FROM users WHERE department = @dept AND status = @status"
        Params = @{dept = 'IT'; status = 'active'}
    },
    @{
        Query = "SELECT COUNT(*) FROM users WHERE department = @dept AND status = @status"
        Params = @{dept = 'HR'; status = 'inactive'}
    }
)

$queries | ForEach-Object {
    Invoke-PostgresAadQuery `
        -PostgresServer "server.postgres.database.azure.com" `
        -PostgresDatabase "companydb" `
        -AadUsername "hr@company.com" `
        -QueryTemplate $_.Query `
        -InputObject $_.Params
}
```

### Parameter Splatting (Clean Syntax)
```powershell
# Clean parameter splatting approach
$params = @{
    PostgresServer = "server.postgres.database.azure.com"
    PostgresDatabase = "db"
    AadUsername = "user@contoso.onmicrosoft.com"
    QueryTemplate = "SELECT {0} as firstname, {1} as lastname, {2} as fullname"
    InputObject = @('Jack', 'Xu', 'Jack Xu')
}

Invoke-PostgresAadQuery @params
```

### 🔄 Real-World Example: Data Analysis Pipeline
```powershell
# Complete data analysis workflow
$server = "analytics-db.postgres.database.azure.com"
$database = "salesdb"
$user = "analyst@company.com"

# Step 1: Get customer segments
$segments = Invoke-PostgresAadQuery `
    -PostgresServer $server `
    -PostgresDatabase $database `
    -AadUsername $user `
    -QueryTemplate "SELECT segment_id, segment_name FROM customer_segments WHERE active = {0}" `
    -InputObject @($true)

# Step 2: Analyze each segment
$results = $segments | ForEach-Object {
    $segmentId = $_.segment_id
    Invoke-PostgresAadQuery `
        -PostgresServer $server `
        -PostgresDatabase $database `
        -AadUsername $user `
        -QueryTemplate "SELECT COUNT(*) as customer_count, AVG(total_spent) as avg_spent FROM customers WHERE segment_id = {0} AND last_purchase >= '{1}'" `
        -InputObject @($segmentId, (Get-Date).AddDays(-30).ToString('yyyy-MM-dd'))
}

$results | Format-Table -AutoSize
```

## Security Features

- **Automatic Token Management**: Secure AAD token acquisition and refresh
- **SQL Injection Prevention**: Parameterized queries and input sanitization
- **SSL/TLS Encryption**: Encrypted database connections
- **Connection Pooling**: Efficient resource management
- **Error Handling**: Comprehensive logging without exposing sensitive information

## Error Handling and Logging

The module includes enterprise-grade error handling with:
- **Multi-attempt retry logic** with exponential backoff (up to 3 attempts)
- **Detailed verbose logging** for comprehensive troubleshooting
- **Graceful degradation** and automatic resource cleanup
- **Security-conscious error messages** that never expose sensitive information

### Troubleshooting Common Issues

```powershell
# Enable verbose logging for detailed diagnostics
Invoke-PostgresAadQuery `
    -PostgresServer "server.postgres.database.azure.com" `
    -PostgresDatabase "db" `
    -AadUsername "user@domain.com" `
    -SqlQuery "SELECT * FROM table" `
    -Verbose

# Test Azure CLI connectivity
Test-AzureCliAvailability -Verbose

# Verify token acquisition
$token = Get-AdUserAccessToken -AadUsername "user@domain.com" -Verbose
```

### Common Error Scenarios

| Error | Cause | Solution |
|-------|-------|----------|
| "Azure CLI not found" | Azure CLI not installed | Install Azure CLI from [official site](https://aka.ms/installazurecliwindows) |
| "Authentication failed" | Invalid credentials or expired token | Re-authenticate with `az login` |
| "Connection timeout" | Network issues or server unavailable | Check server name and network connectivity |
| "SSL connection error" | Certificate issues | Verify server SSL configuration |
| "Parameter type mismatch" | Invalid parameter types | Check InputObject array order and types |

## Module Information

- **Version**: 1.0.0
- **Author**: Jack Xu
- **Company**: Jack Xu
- **Copyright**: © 2026 Jack Xu. All rights reserved.
- **Compatible PSEditions**: Desktop, Core

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```powershell
# Clone the repository
git clone https://github.com/JackXuCN/PostgreSqlAadAuth.git
cd PostgreSqlAadAuth

# Import module for development
Import-Module .\PostgreSqlAadAuth.psd1 -Force

# Run tests (if available)
Invoke-Pester .\Tests\ -Verbose
```

## Support

### 📖 Documentation

For detailed function documentation, use PowerShell help:

```powershell
Get-Help Invoke-PostgresAadQuery -Full
Get-Help Get-AdUserAccessToken -Full
Get-Help Test-AzureCliAvailability -Full
Get-Help Initialize-NpgsqlDriver -Full
```

## Important Notes

- **Direct parameter invocation** is most reliable for complex scenarios
- **Pipeline binding with hashtables** is NOT supported due to PowerShell limitations
- Use **parameter splatting** (`@params`) for clean, maintainable code
- The module automatically handles Npgsql driver initialization for both PowerShell 5.1+ and 7+