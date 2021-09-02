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
