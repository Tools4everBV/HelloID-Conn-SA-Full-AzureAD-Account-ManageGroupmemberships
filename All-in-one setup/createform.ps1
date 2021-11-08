# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Azure Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
83ac862d-fe99-4bdc-8d2e-87405fdb2379
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

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
<# Begin: DataSource "AzureAD-user-generate-table-groupmemberships" #>
$tmpScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName

    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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

    HID-Write-Status -Message "Searching for group memberships of AzureAD user [$userPrincipalName]" -Event Information

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
     
    Hid-Write-Status -Message "Groupmemberships: $resultCount" -Event Information
    HID-Write-Summary -Message "Groupmemberships: $resultCount" -Event Information
         
    if($resultCount -gt 0){
        foreach($group in $groups){
            $returnObject = @{name="$($group.displayName)";id="$($group.id)"}
            Hid-Add-TaskResult -ResultValue $returnObject
        }
    } else {
        Hid-Add-TaskResult -ResultValue []
    }
} catch {
    HID-Write-Status -Message "Error getting groupmemberships for AzureAD user [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error getting groupmemberships for AzureAD user [$userPrincipalName]" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}
'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
AzureAD-user-generate-table-groupmemberships
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_3_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"name","type":0}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
AzureAD-user-generate-table-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "AzureAD-user-generate-table-groupmemberships" #>

<# Begin: DataSource "AzureAD-user-generate-table-attributes-basic" #>
$tmpScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName

    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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
         
    Hid-Write-Status -Message "Searching for AzureAD user userPrincipalName=$userPrincipalName" -Event Information


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
    HID-Write-Status -Message "Finished searching AzureAD user [$userPrincipalName]" -Event Information
      
    foreach($tmp in $azureADUser.psObject.properties)
    {
        if($tmp.Name -in $properties){
            $returnObject = @{name=$tmp.Name; value=$tmp.value}
            Hid-Add-TaskResult -ResultValue $returnObject
        }
    }
   
    HID-Write-Status -Message "Finished retrieving AzureAD user [$userPrincipalName] basic attributes" -Event Success
    HID-Write-Summary -Message "Finished retrieving AzureAD user [$userPrincipalName] basic attributes" -Event Success
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    HID-Write-Status -Message ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage) -Event Error
    HID-Write-Summary -Message "Error searching for AzureAD groups" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}
'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AzureAD-user-generate-table-attributes-basic
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_1_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$tmpModel = @'
[{"key":"value","type":0},{"key":"name","type":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AzureAD-user-generate-table-attributes-basic
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AzureAD-user-generate-table-attributes-basic" #>

<# Begin: DataSource "AzureAD-group-generate-table" #>
$tmpScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {    
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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

    Hid-Write-Status -Message "Searching for AzureAD groups.." -Event Information

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + 'v1.0/groups?$orderby=displayName'

    $azureADGroupsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    $azureADGroups = $azureADGroupsResponse.value
    while (![string]::IsNullOrEmpty($azureADGroupsResponse.'@odata.nextLink')) {
        $azureADGroupsResponse = Invoke-RestMethod -Uri $azureADGroupsResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        $azureADGroups += $azureADGroupsResponse.value
    }    
    
    #Filter for only Cloud groups, since synced groups can only be managed by the Sync
    $azureADGroups = foreach($azureADGroup in $azureADGroups){
        if($azureADGroup.onPremisesSyncEnabled -eq $null){
            $azureADGroup
        }
    }

    $groups = $azureADGroups
    $resultCount = @($groups).Count
     
    Hid-Write-Status -Message "Result count: $resultCount" -Event Information
    HID-Write-Summary -Message "Result count: $resultCount" -Event Information
     
    if($resultCount -gt 0){
        foreach($group in $groups){
            $returnObject = @{name="$($group.displayName)";id="$($group.id)"}
            Hid-Add-TaskResult -ResultValue $returnObject
        }
    } else {
        Hid-Add-TaskResult -ResultValue []
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    HID-Write-Status -Message ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage) -Event Error
    HID-Write-Summary -Message "Error searching for AzureAD groups" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}
'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
AzureAD-group-generate-table
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_2_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[]
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"id","type":0}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
AzureAD-group-generate-table
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "AzureAD-group-generate-table" #>

<# Begin: DataSource "AzureAD-user-generate-table-wildcard" #>
$tmpScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
try {
    $searchValue = $formInput.searchUser
    $searchQuery = "*$searchValue*"
      
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    }else{
        HID-Write-Summary -Message "Searching for: $searchQuery" -Event Information
          
        Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information
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
        Hid-Write-Status -Message "Searching for: $searchQuery" -Event Information
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
        Hid-Write-Status -Message "Result count: $resultCount" -Event Information
        HID-Write-Summary -Message "Result count: $resultCount" -Event Information
          
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{UserPrincipalName=$user.UserPrincipalName; displayName=$user.displayName; department=$user.department; Title=$user.jobTitle; Company=$user.companyName}
                Hid-Add-TaskResult -ResultValue $returnObject
            }
        } else {
            Hid-Add-TaskResult -ResultValue []
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    HID-Write-Status -Message ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage) -Event Error
    HID-Write-Summary -Message "Error searching for AzureAD groups" -Event Failed
     
    Hid-Add-TaskResult -ResultValue []
}
  
'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AzureAD-user-generate-table-wildcard
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_0_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$tmpModel = @'
[{"key":"displayName","type":0},{"key":"Company","type":0},{"key":"Department","type":0},{"key":"Description","type":0},{"key":"SamAccountName","type":0},{"key":"Title","type":0},{"key":"UserPrincipalName","type":0}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AzureAD-user-generate-table-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AzureAD-user-generate-table-wildcard" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AzureAD Account - Manage groupmemberships" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or email address"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true},{"key":"gridUsers","templateOptions":{"label":"Select user account","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"displayName"},{"headerName":"Description","field":"Description"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Company","field":"Company"},{"headerName":"Department","field":"Department"},{"headerName":"Title","field":"Title"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true}]},{"label":"Memberships","fields":[{"key":"gridDetails","templateOptions":{"label":"Basic attributes","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Value","field":"value"}],"height":350,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true},{"key":"memberships","templateOptions":{"label":"Memberships","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"id","optionDisplayProperty":"name","labelLeft":"Available","labelRight":"Member of"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"duallist","summaryVisibility":"Show","requiresTemplateOptions":true}]}]
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
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token user.." -Event Information

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
         
    Hid-Write-Status -Message "Searching for AzureAD user userPrincipalName=$userPrincipalName" -Event Information

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName"
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    HID-Write-Status -Message "Finished searching AzureAD user [$userPrincipalName]" -Event Information

} catch {
    HID-Write-Status -Message "Could not find AzureAD user [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to find AzureAD user [$userPrincipalName]" -Event Failed
}

if($groupsToAdd -ne "[]"){
    try {
        $groupsToAddJson =  $groupsToAdd | ConvertFrom-Json

        foreach($group in $groupsToAddJson){
            #Add the authorization header to the request
            $authorization = @{
                Authorization = "Bearer $accesstoken";
                'Content-Type' = "application/json";
                Accept = "application/json";
            }

            $baseGraphUri = "https://graph.microsoft.com/"
            $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($group.id)/members" + '/$ref'
            $body = @{ "@odata.id"= "https://graph.microsoft.com/v1.0/users/$($azureADUser.id)" } | ConvertTo-Json -Depth 10

            $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $authorization -Verbose:$false
        }

        HID-Write-Status -Message "Finished adding AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json)" -Event Success
        HID-Write-Summary -Message "Successfully added AzureAD user [$userPrincipalName] to AzureAD groups" -Event Success
    } catch {
        HID-Write-Status -Message "Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json). Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Failed to add AzureAD user [$userPrincipalName] to AzureAD groups" -Event Failed
    }
}

if($groupsToRemove -ne "[]"){
    try {
        $groupsToRemoveJson =  $groupsToRemove | ConvertFrom-Json

        foreach($group in $groupsToRemoveJson){
            #Add the authorization header to the request
            $authorization = @{
                Authorization = "Bearer $accesstoken";
                'Content-Type' = "application/json";
                Accept = "application/json";
            }

            $baseGraphUri = "https://graph.microsoft.com/"
            $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($group.id)/members/$($azureADUser.id)" + '/$ref'

            $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $authorization -Verbose:$false
        }

        HID-Write-Status -Message "Finished removing AzureAD user [$userPrincipalName] from AzureAD groups $($groupsToRemoveJson | ConvertTo-Json)" -Event Success
        HID-Write-Summary -Message "Successfully removed AzureAD user [$userPrincipalName] from AzureAD groups" -Event Success
    } catch {
        HID-Write-Status -Message "Could not remove AzureAD user [$userPrincipalName] from AzureAD groups $($groupsToRemoveJson | ConvertTo-Json). Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Failed to remove AzureAD user [$userPrincipalName] from AzureAD groups" -Event Failed
    }
} 
'@; 

	$tmpVariables = @'
[{"name":"groupsToAdd","value":"{{form.memberships.leftToRight.toJsonString}}","secret":false,"typeConstraint":"string"},{"name":"groupsToRemove","value":"{{form.memberships.rightToLeft.toJsonString}}","secret":false,"typeConstraint":"string"},{"name":"userPrincipalName","value":"{{form.gridUsers.UserPrincipalName}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
AzureAD-user-update-groupmemberships
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
