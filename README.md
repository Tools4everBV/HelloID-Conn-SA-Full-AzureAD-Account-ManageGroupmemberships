# HelloID-Conn-SA-Full-AzureAD-Account-ManageGroupmemberships

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as certificate, tenant ID, and application ID. You might need administrator consent and to configure an App Registration in Microsoft Entra ID before implementing this connector. Please contact the client's application owner to coordinate the requirements. |

## Description

HelloID-Conn-SA-Full-AzureAD-Account-ManageGroupmemberships is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can manage Microsoft Entra ID (formerly Azure AD) user account group memberships. The following options are available:

1. Search for and select the target Microsoft Entra ID user account (wildcard search by display name, UserPrincipalName, or mail).
2. View all available Microsoft Entra ID groups and the current group memberships of the selected user account.
3. Add or remove group memberships for the selected user account.

## Getting started

### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions (such as user and group read/write), and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:

- [App-only authentication with certificate](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `Group.Read.All` - To read group information
  - `GroupMember.ReadWrite.All` - To manage group memberships
  - `User.Read.All` - To read user information
- **Certificate Base64 encoded string:**
  - Base64 encoded string of the certificate assigned to the app registration. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following global variables must be configured in HelloID when importing and configuring the delegated form.

| Setting                        | Description                                                           | Mandatory |
| ------------------------------ | --------------------------------------------------------------------- | --------- |
| EntraIdTenantId                | The unique identifier (ID) of the tenant in Microsoft Entra ID        | Yes       |
| EntraIdAppId                   | The unique identifier (ID) of the App Registration in Microsoft Entra ID | Yes    |
| EntraIdCertificateBase64String | The Base64-encoded string representation of the app certificate       | Yes       |
| EntraIdCertificatePassword     | The password associated with the app certificate                      | Yes       |

## Remarks

### User Search

- **Search Functionality**: Users can search for accounts using a wildcard (`*`) to return all users, or by entering partial text to search across user attributes (display name, User Principal Name, or mail address).

### Group Filtering

- **Supported Group Types**: The connector filters groups to include Microsoft 365 groups (Unified) and cloud-only security groups. It excludes:
  - Dynamic membership groups
  - On-premises synchronized groups
  - Mail-enabled security groups (excluding Microsoft 365 groups)
  - Distribution groups

### Certificate-Based Authentication

- **JWT Token Generation**: The connector uses certificate-based authentication to generate JSON Web Tokens (JWT) for secure communication with Microsoft Graph API. The certificate is converted from a base64 string and used to sign the JWT assertion for OAuth2 authentication.

### Error Handling

- **Duplicate Member Addition**: If attempting to add a user to a group where they are already a member, the operation is skipped with an appropriate audit log entry rather than failing.
- **Member Removal**: If attempting to remove a user who is not a member or if the group no longer exists, the operation is skipped with an informational audit log entry.

## Development resources

### API endpoints

The following Microsoft Graph API endpoints are used by the connector:

| Endpoint                                       | Description           |
| ---------------------------------------------- | --------------------- |
| /v1.0/users                                    | List users            |
| /v1.0/users/{id}/memberOf                      | List user group memberships |
| /v1.0/groups                                   | List groups           |
| /v1.0/groups/{id}/members/$ref                 | Add member            |
| /v1.0/groups/{id}/members/{userId}/$ref        | Remove member         |

### API documentation

- [List users](https://learn.microsoft.com/en-us/graph/api/user-list)
- [List user's group memberships](https://learn.microsoft.com/en-us/graph/api/user-list-memberof)
- [List groups](https://learn.microsoft.com/en-us/graph/api/group-list)
- [Add group member](https://learn.microsoft.com/en-us/graph/api/group-post-members)
- [Remove group member](https://learn.microsoft.com/en-us/graph/api/group-delete-members)

## Getting help

> 💡 **Tip:** For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages.

## HelloID docs

The official HelloID documentation can be found at: [https://docs.helloid.com/](https://docs.helloid.com/)
