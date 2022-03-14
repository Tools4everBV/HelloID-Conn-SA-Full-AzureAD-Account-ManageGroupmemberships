# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("User Management","Azure Active Directory") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = @'
GJN7Q~_hKT8k4rpSxLdq73p6lVzq7vQir_.ME
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
83ac862d-fe99-4bdc-8d2e-87405fdb2379
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = @'
65fc161b-0c41-4cde-9908-dabf3cad26b6
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> companyName
$tmpName = @'
companyName
'@ 
$tmpValue = @'
{{company.name}}
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"
# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}
# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}

<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "AzureAD-group-generate-table" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try{
    Write-Information "Generating Microsoft Graph API Access Token.."
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken"
        'Content-Type' = "application/json"
        Accept = "application/json"
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        ConsistencyLevel = "eventual"
    }

    # Define the properties to select (comma seperated)
    # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
    # Comment out $properties to select all properties
    $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
    if ($null -ne $properties) {
        $select = "&`$select=$($properties -join ",")"
    } else {
        $select = $null
    }

    # Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API
    # https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0
    [System.Collections.ArrayList]$groups = @()

    # Get Microsoft 365 Groups only (https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)
    Write-Information "Searching for Microsoft 365 groups.."
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')$select"

    $response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    [System.Collections.ArrayList]$microsoft365Groups = $response.value
    while (![string]::IsNullOrEmpty($response.'@odata.nextLink')) {
        $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        foreach($item in $response.value){ $null = $microsoft365Groups.Add($item) }
    }
    Write-Information "Finished searching for Microsoft 365 groups. Found [$($microsoft365Groups.id.Count) groups]"
    foreach($microsoft365Group in $microsoft365Groups){ $null = $groups.Add($microsoft365Group) }

    # Get Security Groups only (https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
    Write-Information "Searching for Security groups.."
    $baseSearchUri = "https://graph.microsoft.com/"
    # Filter Cloud-Only groups (onPremisesSyncEnabled = null) and Security Groups only (https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
    $searchUri = $baseSearchUri + "v1.0/groups?`$filter=onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true$select"
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $searchUri = $searchUri + "&`$count=true"

    $response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    [System.Collections.ArrayList]$securityGroups = $response.value
    while (![string]::IsNullOrEmpty($response.'@odata.nextLink')) {
        $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        foreach($item in $response.value){ $null = $securityGroups.Add($item) }
    }
    Write-Information "Finished searching for Security Groups. Found [$($securityGroups.id.Count) groups]"
    foreach($securityGroup in $securityGroups){
        #Do not show dynamic security groups
        if (-Not ($securityGroup.groupTypes -contains 'DynamicMembership')) {
            $null = $groups.Add($securityGroup)
        }
    }

    $resultCount = @($groups).Count
    Write-Information "Result count: $resultCount"
     
    if($resultCount -gt 0){
        foreach($group in $groups){
            $returnObject = @{name="$($group.displayName)";id="$($group.id)"}
            Write-Output $returnObject
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
AzureAD-group-generate-table
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "AzureAD-group-generate-table" #>

<# Begin: DataSource "AzureAD-user-generate-table-wildcard" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $searchValue = $datasource.searchUser
    $searchQuery = "*$searchValue*"
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
    }else{
        Write-Information "Searching for: $searchQuery"
          
        Write-Information "Generating Microsoft Graph API Access Token.."
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"
        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }
 
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        Write-Information "Searching for: $searchQuery"
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users" + '?$select=UserPrincipalName,displayName,department,jobTitle,companyName' + '&$top=999'
 
        $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers = $azureADUsersResponse.value
        while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
            $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADUsers += $azureADUsersResponse.value
        }  
        $users = foreach($azureADUser in $azureADUsers){
            if($azureADUser.displayName -like $searchQuery -or $azureADUser.userPrincipalName -like $searchQuery){
                $azureADUser
            }
        }
        $users = $users | Sort-Object -Property DisplayName
        $resultCount = @($users).Count
        Write-Information "Result count: $resultCount"
          
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{UserPrincipalName=$user.UserPrincipalName; displayName=$user.displayName; department=$user.department; Title=$user.jobTitle; Company=$user.companyName}
                Write-Output $returnObject
            }
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}
  
'@ 
$tmpModel = @'
[{"key":"displayName","type":0},{"key":"department","type":0},{"key":"UserPrincipalName","type":0},{"key":"Company","type":0},{"key":"Title","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AzureAD-user-generate-table-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AzureAD-user-generate-table-wildcard" #>

<# Begin: DataSource "AzureAD-user-generate-table-groupmemberships" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $datasource.selectedUser.UserPrincipalName

    Write-Information "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Write-Information "Searching for group memberships of AzureAD user [$userPrincipalName]"

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName/memberOf"
    $azureADGroupsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    $azureADGroups = $azureADGroupsResponse.value
    while (![string]::IsNullOrEmpty($azureADGroupsResponse.'@odata.nextLink')) {
        $azureADGroupsResponse = Invoke-RestMethod -Uri $azureADGroupsResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        $azureADGroups += $azureADGroupsResponse.value
    }    

    $groups = $azureADGroups
    $resultCount = @($groups).Count
    Write-Information "Groupmemberships: $resultCount"
         
    if($resultCount -gt 0){
        foreach($group in $groups){
            $returnObject = @{name="$($group.displayName)";id="$($group.id)"}
            Write-Output $returnObject
        }
    }
} catch {
    Write-Error "Error getting groupmemberships for AzureAD user [$userPrincipalName]. Error: $($_.Exception.Message)"
}
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
AzureAD-user-generate-table-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "AzureAD-user-generate-table-groupmemberships" #>

<# Begin: DataSource "AzureAD-user-generate-table-attributes-basic" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $datasource.selectedUser.UserPrincipalName

    Write-Information "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;
         
    Write-Information "Searching for AzureAD user userPrincipalName=$userPrincipalName"

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $properties = @("displayName","userPrincipalName","givenName","surname","department","jobTitle","companyName","businessPhones","mobilePhone")
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName" + '?$select=' + ($properties -join ",")
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    Write-Information "Finished searching AzureAD user [$userPrincipalName]"
      
    foreach($tmp in $azureADUser.psObject.properties)
    {
        if($tmp.Name -in $properties){
            $returnObject = @{name=$tmp.Name; value=$tmp.value}
            Write-Output $returnObject
        }
    }
   
    Write-Information "Finished retrieving AzureAD user [$userPrincipalName] basic attributes"
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"value","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AzureAD-user-generate-table-attributes-basic
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AzureAD-user-generate-table-attributes-basic" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AzureAD Account - Manage groupmemberships" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or email address"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUsers","templateOptions":{"label":"Select user account","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"displayName"},{"headerName":"Description","field":"Description"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Company","field":"Company"},{"headerName":"Department","field":"Department"},{"headerName":"Title","field":"Title"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Memberships","fields":[{"key":"gridDetails","templateOptions":{"label":"Basic attributes","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Value","field":"value"}],"height":350,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"memberships","templateOptions":{"label":"Memberships","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"id","optionDisplayProperty":"name","labelLeft":"Available","labelRight":"Member of"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AzureAD Account - Manage groupmemberships
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
AzureAD Account - Manage groupmemberships
'@
$tmpTask = @'
{"name":"AzureAD Account - Manage groupmemberships","script":"$groupsToAdd = $form.memberships.leftToRight\r\n$groupsToRemove = $form.memberships.RightToLeft\r\n$userPrincipalName = $form.gridUsers.UserPrincipalName\r\n\r\n# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\ntry {\r\n    Write-Information \"Generating Microsoft Graph API Access Token..\"\r\n\r\n    $baseUri = \"https://login.microsoftonline.com/\"\r\n    $authUri = $baseUri + \"$AADTenantID/oauth2/token\"\r\n\r\n    $body = @{\r\n        grant_type      = \"client_credentials\"\r\n        client_id       = \"$AADAppId\"\r\n        client_secret   = \"$AADAppSecret\"\r\n        resource        = \"https://graph.microsoft.com\"\r\n    }\r\n \r\n    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'\r\n    $accessToken = $Response.access_token;\r\n         \r\n    Write-Information \"Searching for AzureAD user userPrincipalName=$userPrincipalName\"\r\n\r\n    #Add the authorization header to the request\r\n    $authorization = @{\r\n        Authorization = \"Bearer $accesstoken\";\r\n        'Content-Type' = \"application/json\";\r\n        Accept = \"application/json\";\r\n    }\r\n\r\n    $baseSearchUri = \"https://graph.microsoft.com/\"\r\n    $searchUri = $baseSearchUri + \"v1.0/users/$userPrincipalName\"\r\n    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false\r\n    Write-Information \"Finished searching AzureAD user [$userPrincipalName]\"\r\n} catch {\r\n    Write-Error \"Could not find AzureAD user [$userPrincipalName]. Error: $($_.Exception.Message)\"\r\n}\r\n\r\ntry {\r\n    foreach($group in $groupsToAdd){\r\n        try{\r\n            #Add the authorization header to the request\r\n            $authorization = @{\r\n                Authorization = \"Bearer $accesstoken\";\r\n                'Content-Type' = \"application/json\";\r\n                Accept = \"application/json\";\r\n            }\r\n\r\n            $baseGraphUri = \"https://graph.microsoft.com/\"\r\n            $addGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($group.id)/members\" + '/$ref'\r\n            $body = @{ \"@odata.id\"= \"https://graph.microsoft.com/v1.0/users/$($azureADUser.id)\" } | ConvertTo-Json -Depth 10\r\n\r\n            $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $authorization -Verbose:$false\r\n            Write-Information \"Successfully added AzureAD user [$userPrincipalName] to AzureAD group $($group)\"\r\n        } catch {\r\n            if($_ -like \"*One or more added object references already exist for the following modified properties*\"){\r\n                Write-Information \"AzureAD user [$userPrincipalName] is already a member of group $($group)\"\r\n            }else{\r\n                Write-Warning \"Could not add AzureAD user [$userPrincipalName] to AzureAD group $($group). Error: $($_.Exception.Message)\"\r\n            }\r\n        }\r\n    }\r\n} catch {\r\n    Write-Error \"Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAdd). Error: $($_.Exception.Message)\"\r\n}\r\n\r\ntry {\r\n    foreach($group in $groupsToRemove){\r\n        try{\r\n            #Add the authorization header to the request\r\n            $authorization = @{\r\n                Authorization = \"Bearer $accesstoken\";\r\n                'Content-Type' = \"application/json\";\r\n                Accept = \"application/json\";\r\n            }\r\n\r\n            $baseGraphUri = \"https://graph.microsoft.com/\"\r\n            $removeGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($group.id)/members/$($azureADUser.id)\" + '/$ref'\r\n\r\n            $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $authorization -Verbose:$false\r\n            Write-Information \"Successfully removed AzureAD user [$userPrincipalName] from AzureAD group $($group)\"\r\n        } catch {\r\n            if($_ -like \"*Resource '$($group.id)' does not exist or one of its queried reference-property objects are not present*\"){\r\n                Write-Information \"AzureAD user [$userPrincipalName] is already no longer a member or AzureAD group $($group) does not exist anymore\";\r\n            }else{\r\n                Write-Warning \"Could not remove AzureAD user [$userPrincipalName] from AzureAD group $($group). Error: $($_.Exception.Message)\"\r\n            }\r\n        }\r\n    }\r\n} catch {\r\n    Write-Error \"Could not remove AzureAD user [$userPrincipalName] from AzureAD groups $($groupsToRemove). Error: $($_.Exception.Message)\"\r\n}","runInCloud":true}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

