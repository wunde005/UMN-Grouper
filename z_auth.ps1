param(
    [parameter(Position=0,Mandatory=$false)][string]$auth_file
)


<#
<#
Import-Module ..\UMN-Grouper\UMN-Grouper -force
$pscred = Get-Credential -username wunde005
$gheader = New-GrouperHeader -psCreds $pscred
#>

#>

$authfileused = $false
write-host "auth_file:$auth_file"
$auth = $null
if([string]::IsNullOrWhiteSpace($auth_file)){
  write-warning "Auth file not submitted.  Either re-import with the auth file specified or follow the prompts to create a new one."
  write-host "Example import with auth file: import-module CanvasPS -ArgumentList .\tmp\auth.xml`n"
}
else{
  write-host "Loading auth from: $auth_file"
  try {
    $auth = import-clixml ($auth_file)
  }
  catch{ [System.IO.FileNotFoundException]
    Write-Warning "File not found. Make sure xml config exists: $auth_file"   
    throw
  }
  $authfileused = $true
#  Set-Variable defaultset -Option Constant -Value "noConfig" -force -Scope Global
}

if($null -eq $auth){
  $auth = New-Object -TypeName psobject
}

#no uri, ask for uri
if($null -eq $auth.uri){
  $systemUri = Read-Host "Canvas Url:"#'uri?'

  $auth | Add-Member -MemberType NoteProperty -name uri -Value $systemUri.tostring()  
}
else{
  $systemUri = $auth.uri
}
seturi -systemuri $systemuri

#no API key, ask for API key
#if($null -eq $auth.Authorization){
  #write-host "`nInfo on the API can be found here: $systemUri/api/v1/`$metadata#top`n"

  #write-host "Go here to create a API key: $systemUri/api/Docs/ApiKeyRegistration.aspx`n"
  
  #$sfapikey = Read-Host 'Enter API Key'
  #Authorization: Bearer 
  #$authorization = "Bearer $($sfapikey)"
  #$auth | Add-Member -MemberType NoteProperty -name Authorization -Value $authorization
 
  #$auth | Add-Member -MemberType NoteProperty -name sfapikey -Value $sfapikey.tostring()
#  $authfromconfig = $false
#}
#else{
#  $sfapikey = $auth.sfapikey
#}
<#
  $writeauth = Read-host 'write authfile?(Y/n)'
  if($writeauth -eq 'y'){
    $newauthfile = read-host 'auth file'
    $auth | Export-Clixml "$newauthfile"
  }
}
#>

#add secured ticket to auth object
if($null -ne $auth.SecMediasiteApplicationTicketTxt -and $null -eq $auth.SecMediasiteApplicationTicket){
  $auth | Add-Member -MemberType NoteProperty -name SecMediasiteApplicationTicket -Value ($auth.SecMediasiteApplicationTicketTxt | ConvertTo-SecureString) 
}


