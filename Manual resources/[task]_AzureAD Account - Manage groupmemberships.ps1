$groupsToAdd = $form.memberships.leftToRight
$groupsToRemove = $form.memberships.RightToLeft
$userPrincipalName = $form.gridUsers.UserPrincipalName

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
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

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName"
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    Write-Information "Finished searching AzureAD user [$userPrincipalName]"
} catch {
    Write-Error "Could not find AzureAD user [$userPrincipalName]. Error: $($_.Exception.Message)"
}

try {
    foreach($group in $groupsToAdd){
        try{
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
            Write-Information "Successfully added AzureAD user [$userPrincipalName] to AzureAD group $($group.name)"

            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully added AzureAD user [$userPrincipalName] to AzureAD group $($group.name)." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $userPrincipalName # optional (free format text) 
                TargetIdentifier  = $([string]$group.id) # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        } catch {
            if($_ -like "*One or more added object references already exist for the following modified properties*"){
                Write-Information "AzureAD user [$userPrincipalName] is already a member of group $($group.name)"
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "AzureActiveDirectory" # optional (free format text) 
                    Message           = "AzureAD user [$userPrincipalName] is already a member of group $($group.name)." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $userPrincipalName # optional (free format text) 
                    TargetIdentifier  = $([string]$group.id) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }else{
                Write-Warning "Could not add AzureAD user [$userPrincipalName] to AzureAD group $($group). Error: $($_.Exception.Message)"
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "AzureActiveDirectory" # optional (free format text) 
                    Message           = "Could not add AzureAD user [$userPrincipalName] to AzureAD group $($group.name)." # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $userPrincipalName # optional (free format text) 
                    TargetIdentifier  = $([string]$group.id) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
        }
    }
} catch {
    Write-Error "Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAdd). Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAdd)." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $userPrincipalName # optional (free format text) 
        TargetIdentifier  = $($groupsToAdd) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}

try {
    foreach($group in $groupsToRemove){
        try{
            #Add the authorization header to the request
            $authorization = @{
                Authorization = "Bearer $accesstoken";
                'Content-Type' = "application/json";
                Accept = "application/json";
            }

            $baseGraphUri = "https://graph.microsoft.com/"
            $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($group.id)/members/$($azureADUser.id)" + '/$ref'

            $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $authorization -Verbose:$false
            Write-Information "Successfully removed AzureAD user [$userPrincipalName] from AzureAD group $($group.name)"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully removed AzureAD user [$userPrincipalName] from AzureAD group $($group.name)." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $userPrincipalName # optional (free format text) 
                TargetIdentifier  = $([string]$group.id) # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        } catch {
            if($_ -like "*Resource '$($group.id)' does not exist or one of its queried reference-property objects are not present*"){
                Write-Information "AzureAD user [$userPrincipalName] is already no longer a member or AzureAD group $($group.name) does not exist anymore";
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "AzureActiveDirectory" # optional (free format text) 
                    Message           = "AzureAD user [$userPrincipalName] is already no longer a member or AzureAD group $($group.name) does not exist anymore." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $userPrincipalName # optional (free format text) 
                    TargetIdentifier  = $([string]$group.id) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }else{
                Write-Warning "Could not remove AzureAD user [$userPrincipalName] from AzureAD group $($group.name). Error: $($_.Exception.Message)"
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "AzureActiveDirectory" # optional (free format text) 
                    Message           = "Could not remove AzureAD user [$userPrincipalName] from AzureAD group $($group.name)." # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $userPrincipalName # optional (free format text) 
                    TargetIdentifier  = $([string]$group.id) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
        }
    }
} catch {
    Write-Error "Could not remove AzureAD user [$userPrincipalName] from AzureAD groups $($groupsToRemove). Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Could not remove AzureAD user [$userPrincipalName] from AzureAD groups $($groupsToRemove)." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $userPrincipalName # optional (free format text) 
        TargetIdentifier  = $($groupsToRemove) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
