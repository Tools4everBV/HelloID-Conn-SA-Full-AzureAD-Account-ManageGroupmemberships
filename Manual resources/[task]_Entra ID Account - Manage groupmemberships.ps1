# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

$groupsToAdd = $form.memberships.leftToRight
$groupsToRemove = $form.memberships.RightToLeft
$userPrincipalName = $form.gridUsers.UserPrincipalName

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
        Authorization = "Bearer $entraToken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    } 

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName"
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    Write-Information "Finished searching EntraID user [$userPrincipalName]"
} catch {
    Write-Error "Could not find EntraID user [$userPrincipalName]. Error: $($_.Exception.Message)"
}

try {
    foreach($group in $groupsToAdd){
        try{
            #Add the authorization header to the request
            $authorization = @{
                Authorization = "Bearer $entraToken";
                'Content-Type' = "application/json";
                Accept = "application/json";
            }

            $baseGraphUri = "https://graph.microsoft.com/"
            $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($group.id)/members" + '/$ref'
            $body = @{ "@odata.id"= "https://graph.microsoft.com/v1.0/users/$($azureADUser.id)" } | ConvertTo-Json -Depth 10

            $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $authorization -Verbose:$false
            Write-Information "Successfully added EntraID user [$userPrincipalName] to EntraID group $($group.name)"

            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "EntraID" # optional (free format text) 
                Message           = "Successfully added EntraID user [$userPrincipalName] to EntraID group $($group.name)." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $userPrincipalName # optional (free format text) 
                TargetIdentifier  = $([string]$group.id) # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        } catch {
            if($_ -like "*One or more added object references already exist for the following modified properties*"){
                Write-Information "EntraID user [$userPrincipalName] is already a member of group $($group.name)"
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "EntraID" # optional (free format text) 
                    Message           = "EntraID user [$userPrincipalName] is already a member of group $($group.name)." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $userPrincipalName # optional (free format text) 
                    TargetIdentifier  = $([string]$group.id) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }else{
                Write-Warning "Could not add EntraID user [$userPrincipalName] to EntraID group $($group). Error: $($_.Exception.Message)"
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "EntraID" # optional (free format text) 
                    Message           = "Could not add EntraID user [$userPrincipalName] to EntraID group $($group.name)." # required (free format text) 
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
    Write-Error "Could not add EntraID user [$userPrincipalName] to EntraID groups $($groupsToAdd). Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "EntraID" # optional (free format text) 
        Message           = "Could not add EntraID user [$userPrincipalName] to EntraID groups $($groupsToAdd)." # required (free format text) 
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
            Write-Information "Successfully removed EntraID user [$userPrincipalName] from EntraID group $($group.name)"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "EntraID" # optional (free format text) 
                Message           = "Successfully removed EntraID user [$userPrincipalName] from EntraID group $($group.name)." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $userPrincipalName # optional (free format text) 
                TargetIdentifier  = $([string]$group.id) # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        } catch {
            if($_ -like "*Resource '$($group.id)' does not exist or one of its queried reference-property objects are not present*"){
                Write-Information "EntraID user [$userPrincipalName] is already no longer a member or EntraID group $($group.name) does not exist anymore";
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "EntraID" # optional (free format text) 
                    Message           = "EntraID user [$userPrincipalName] is already no longer a member or EntraID group $($group.name) does not exist anymore." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $userPrincipalName # optional (free format text) 
                    TargetIdentifier  = $([string]$group.id) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }else{
                Write-Warning "Could not remove EntraID user [$userPrincipalName] from EntraID group $($group.name). Error: $($_.Exception.Message)"
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "EntraID" # optional (free format text) 
                    Message           = "Could not remove EntraID user [$userPrincipalName] from EntraID group $($group.name)." # required (free format text) 
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
    Write-Error "Could not remove EntraID user [$userPrincipalName] from EntraID groups $($groupsToRemove). Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "EntraID" # optional (free format text) 
        Message           = "Could not remove EntraID user [$userPrincipalName] from EntraID groups $($groupsToRemove)." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $userPrincipalName # optional (free format text) 
        TargetIdentifier  = $($groupsToRemove) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
