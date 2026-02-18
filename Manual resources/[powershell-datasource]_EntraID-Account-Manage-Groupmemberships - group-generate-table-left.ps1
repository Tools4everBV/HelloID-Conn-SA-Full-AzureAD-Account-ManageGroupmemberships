# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')
	
	# Extract the private key from the certificate
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

try {
    # Setup Connection with Entra/Exo
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $entraToken"
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
    

    #$response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
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
    
    $searchUri = $baseSearchUri + "v1.0/groups?" +
    "`$filter=onPremisesSyncEnabled eq null and " +
    "mailEnabled eq false and " +
    "securityEnabled eq true" +
    $select +
    "&`$count=true"

    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    #$searchUri = $searchUri + "&`$count=true"

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
