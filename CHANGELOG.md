# Change Log

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.1] - 2026-07-27

### Fixed

- Fixed [#3](https://github.com/Tools4everBV/HelloID-Conn-SA-Full-Microsoft-EntraID-Account-ManageGroupmemberships/issues/3): When requesting the memberships of a user, when the user has none, an incident is created indicating the execution of datasource 'entra-id-account-manage-groupmemberships | EntraID-Get-User-GroupMemberships' has failed.

## [2.0.0] - 2026-03-02

This is a major release that migrates from Azure AD to Microsoft Entra ID terminology and replaces client secret authentication with certificate-based authentication. This release includes breaking changes that require reconfiguration of global variables and App Registration settings.

### Added

- Added GitHub Actions workflow for automated release creation (`Create Release` workflow)
- Added GitHub Actions workflow to verify CHANGELOG.md updates on pull requests (`Verify CHANGELOG Updated` workflow)
- Added data source to retrieve all manageable Entra ID groups (`EntraID-Get-All-Groups`)
  - Filters groups to include Microsoft 365 groups (Unified) and cloud-only security groups
  - Excludes dynamic membership groups, on-premises synced groups, mail-enabled security groups, and distribution groups
- Added data source to retrieve user group memberships (`EntraID-Get-User-GroupMemberships`)
- Added data source for wildcard user search (`EntraID-Get-Users-Wildcard-DisplayName-UPN-Mail`)
  - Supports searching by display name, user principal name, and mail address
- Added certificate-based authentication functions (`Get-MSEntraCertificate` and `Get-MSEntraAccessToken`)
  - Implements JWT token generation with X.509 certificate signing
  - Uses SHA-256 certificate thumbprint (`x5t#S256`) for enhanced security
- Added pagination support with `@odata.nextLink` for complete result sets
- Added comprehensive error handling with `Resolve-MicrosoftGraphAPIError` function

### Changed

- **BREAKING:** Migrated from Azure AD terminology to Microsoft Entra ID terminology throughout all scripts, documentation, and configuration files
- **BREAKING:** Updated global variable names to use Entra ID naming convention:
  - Old: `AADTenantId` → New: `EntraIdTenantId`
  - Old: `AADAppId` → New: `EntraIdAppId`
  - Old: `AADAppSecret` → New: `EntraIdCertificateBase64String` and `EntraIdCertificatePassword`
- **BREAKING:** Replaced client secret authentication with certificate-based authentication for Microsoft Graph API access
  - Now uses JWT (JSON Web Tokens) generated from X.509 certificates
  - Requires certificate to be uploaded to Entra ID App Registration
- **BREAKING:** Refactored data source names from Azure AD to Entra ID naming:
  - Old: `AzureAD-group-generate-table` → New: `EntraID-Get-All-Groups`
  - Old: `AzureAD-user-generate-table-groupmemberships` → New: `EntraID-Get-User-GroupMemberships`
  - Old: `AzureAD-user-generate-table-wildcard` → New: `EntraID-Get-Users-Wildcard-DisplayName-UPN-Mail`
- Updated task name from "AzureAD Account - Manage groupmemberships" to "Entra ID Account - Manage groupmemberships"
- Updated API permissions to minimal required set:
  - `Group.Read.All` - To read group information
  - `GroupMember.ReadWrite.All` - To manage group memberships
  - `User.Read.All` - To read user information
- Enhanced delegated form with improved user experience and field layout
- Improved error handling for duplicate member additions and removals with graceful skipping and audit logging
- Updated group membership operations to use Microsoft Graph API v1.0:
  - Add member: `POST /v1.0/groups/{groupId}/members/$ref`
  - Remove member: `DELETE /v1.0/groups/{groupId}/members/{userId}/$ref`
- Updated README.md with comprehensive documentation including:
  - Certificate-based authentication setup instructions
  - API permissions requirements
  - Connection settings
  - Remarks on user search, group filtering, and error handling
- Improved code formatting and consistency across all PowerShell scripts
- Enhanced audit logging for all group membership add/remove operations

### Deprecated

- Deprecated support for Azure AD naming convention in global variables (use Entra ID naming convention instead)
- Deprecated client secret authentication method (use certificate-based authentication instead)

### Removed

- Removed support for client secret-based authentication in favor of certificate-based authentication
- Removed Azure AD terminology from all scripts and documentation
- Removed excessive API permissions that were not required for group membership management

### Fixed

- Fixed pagination handling to ensure all groups and memberships are retrieved when result sets exceed page limits
- Fixed error handling to provide more detailed error messages with line numbers and friendly messages
- Fixed group filtering to properly exclude unsupported group types (dynamic, synced, distribution groups)

## [1.1.1] - 2022-08-03

### Added

- Added version numbering to scripts
- Added enhanced audit logging functionality

### Changed

- Improved audit logging output with detailed operation tracking

### Deprecated

### Removed

### Fixed

## [1.1.0] - 2022-03-14

### Added

- Added support for HelloID Service Automation agent

### Changed

- Updated code to support SA-agent execution
- Updated all-in-one setup script

### Deprecated

### Removed

### Fixed

## [1.0.1] - 2021-11-08

### Added

- Added version number to scripts

### Changed

- Updated all-in-one setup script

### Deprecated

### Removed

### Fixed

## [1.0.0] - 2021-09-02

### Added

- Initial release of HelloID-Conn-SA-Full-AzureAD-Account-ManageGroupmemberships
- Basic Azure AD user group membership management functionality
- Form-based user selection with wildcard search across displayName and userPrincipalName
- Dual-list interface for managing group memberships (Available groups vs. Member-of groups)
- Add and remove group membership operations
- Client secret-based authentication for Microsoft Graph API
- Data source for searching Azure AD users (`AzureAD-user-generate-table-wildcard`)
- Data source for retrieving user group memberships (`AzureAD-user-generate-table-groupmemberships`)
- Data source for retrieving all groups (`AzureAD-group-generate-table`)
- Task for group membership add/remove operations
- All-in-one setup script for HelloID form deployment
- Basic error handling and audit logging

### Changed

### Deprecated

### Removed

### Fixed
