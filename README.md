# HelloID-Conn-SA-Full-AzureAD-Account-ManageGroupmemberships

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as certificate, tenant ID, and application ID. You might need administrator consent and to configure an App Registration in Microsoft Entra ID before implementing this connector. Please contact the client's application owner to coordinate the requirements. |

## Description
HelloID-Conn-SA-Full-AzureAD-Account-ManageGroupmemberships is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your environment.

By using this delegated form, you can manage Microsoft Entra ID (Azure AD) group memberships for a selected user. The following options are available:
 1. Search and select the target user
 2. Move groups between Available and Member-of lists to add or remove
 3. Validate inputs and preview changes
 4. Apply updates to group memberships via Microsoft Graph
 5. Audit logging is written for each add/remove operation

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID, an App Registration. During the setup process, you’ll create a new App Registration in the Entra portal, assign the necessary API permissions (such as user and group read/write), and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:
- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.ReadWrite.All`
  - `Group.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `UserAuthenticationMethod.ReadWrite.All`
  - `User.EnableDisableAccount.All`
  - `User-PasswordProfile.ReadWrite.All`
  - `User-Phone.ReadWrite.All`
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)


### Connection settings

The following user-defined variables are used by the connector.

| Setting                          | Description                                                  | Mandatory |
| -------------------------------- | ------------------------------------------------------------ | --------- |
| EntraIdTenantId                  | The Tenant ID (Directory ID) of the Entra ID tenant          | Yes       |
| EntraIdAppId                     | The Application (Client) ID of the App Registration          | Yes       |
| EntraIdCertificateBase64String   | Base64-encoded certificate (including private key)           | Yes       |
| EntraIdCertificatePassword       | Password for the certificate private key                     | Yes       |
| companyName                      | Company label shown in the UI (optional)                     | No        |

## Remarks

### Certificate-based Client Assertion
- **JWT with `x5t#S256`**: The form generates a client-assertion JWT using the certificate's SHA-256 thumbprint (`x5t#S256`) and signs it with the private key to request an access token from Azure AD.

### Group Membership Operations
- **Add membership**: Uses `POST /v1.0/groups/{groupId}/members/$ref` with a body containing the target user `@odata.id`.
- **Remove membership**: Uses `DELETE /v1.0/groups/{groupId}/members/{userId}/$ref`.
- **Idempotency handling**: Attempts to add an existing membership and remove a non-existing membership are handled gracefully with informative audit logs.

### Pagination
- **`@odata.nextLink`**: When listing memberships (e.g., `memberOf`), the implementation follows `@odata.nextLink` to return complete results.

### Data sources and form behavior
- **Wildcard search**: Users can be searched by display name or UPN using a wildcard query.
- **Dual list UI**: The form presents Available vs. Member-of group lists for intuitive membership changes.
- **Run in Cloud**: All data sources and the delegated task are configured to run in the HelloID Cloud environment.

## Development resources

### API endpoints

The following Microsoft Graph endpoints are used by the connector:

| Endpoint                                              | Description                             |
| ----------------------------------------------------- | --------------------------------------- |
| `/v1.0/users`                                         | Retrieve and search users                |
| `/v1.0/users/{userPrincipalName}`                     | Retrieve a specific user                 |
| `/v1.0/users/{userPrincipalName}/memberOf`            | List a user's group memberships          |
| `/v1.0/groups`                                        | List groups                              |
| `/v1.0/groups/{groupId}/members/$ref`                 | Add a user to a group (POST)             |
| `/v1.0/groups/{groupId}/members/{userId}/$ref`        | Remove a user from a group (DELETE)      |

### API documentation

- Microsoft Graph overview: https://learn.microsoft.com/graph/
- Users API: https://learn.microsoft.com/graph/api/resources/users
- Groups API: https://learn.microsoft.com/graph/api/resources/groups
- Add member to group: https://learn.microsoft.com/graph/api/group-post-members
- Remove member from group: https://learn.microsoft.com/graph/api/group-delete-members

## Getting help
> :bulb: **Tip:**  
> For more information on Delegated Forms, please refer to our documentation pages: https://docs.helloid.com/en/service-automation/delegated-forms.html

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/


<!-- Description -->
## Description
This HelloID Service Automation Delegated Form can manage the groupmemberships for Azure users. The following options are available:
 1. Search and select the target user
 2. Choose whether the groups to add or remove
 3. After confirmation the groupmemberhips of the user are updated

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.1.1   | Added version number and added auditlogging | 2022/08/03  |
| 1.1.0   | Updated with code for SA agent | 2022/03/14  |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/08  |
| 1.0.0   | Initial release | 2021/09/02  |

<!-- Requirements -->
## Requirements
This script uses the Microsoft Graph API and requires an App Registration with App permissions:
*	Read and Write all user’s full profiles by using <b><i>User.ReadWrite.All</i></b>
*	Read and Write all groups in an organization’s directory by using <b><i>Group.ReadWrite.All</i></b>
*	Read and Write data to an organization’s directory by using <b><i>Directory.ReadWrite.All</i></b>
 
<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [Requirements](#requirements)
* [Introduction](#introduction)
* [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
  * [Application Registration](#application-registration)
  * [Configuring App Permissions](#configuring-app-permissions)
  * [Authentication and Authorization](#authentication-and-authorization)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)


## Introduction
The interface to communicate with Microsoft Azure AD is through the Microsoft Graph API.

<!-- GETTING STARTED -->
## Getting the Azure AD graph API access

By using this connector you will have the ability to manage the groupmemberships of an Azure AD User.

### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read and Write all user’s full profiles by using <b><i>User.ReadWrite.All</i></b>
*	Read and Write all groups in an organization’s directory by using <b><i>Group.ReadWrite.All</i></b>
*	Read and Write data to an organization’s directory by using <b><i>Directory.ReadWrite.All</i></b>

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At least we need to get is the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Custom Domain Names</b>, and then finding the .onmicrosoft.com domain.

## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

_Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_

### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.


## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>AADtenantID</td><td>Azure AD Tenant Id</td><td>Id of the Azure tenant</td></tr>
  <tr><td>AADAppId</td><td>Azure AD App Id</td><td>Id of the Azure app</td></tr>
<tr><td>AADAppSecret</td><td>Azure AD App Secret</td><td>Secreat of the Azure app</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'AzureAD-group-generate-table'

### Powershell data source 'AzureAD-user-generate-table-attributes-basic'

### Powershell data source 'AzureAD-user-generate-table-groupmemberships'

### Powershell data source 'AzureAD-user-generate-table-wildcard'

### Delegated form task 'AzureAD Account - Manage groupmemberships'

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/204-helloid-sa-azure-ad-manage-groupmemberships-of-user)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/