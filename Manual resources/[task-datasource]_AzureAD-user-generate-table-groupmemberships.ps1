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
