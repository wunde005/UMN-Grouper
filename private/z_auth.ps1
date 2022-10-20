#function z_auth{
param(
    [parameter(Mandatory=$false)][string]$auth_file,
    [parameter(Mandatory=$false)][PSCustomObject]$auth_obj
    )

$auth = $null

if($null -ne $auth_obj){
  $auth = $auth_obj
}
elseif([string]::IsNullOrWhiteSpace($auth_file)){
  write-warning "Auth file not submitted.  Use -uri and -header switches." #  Either re-import with the auth file specified or follow the prompts to create a new one."
  #write-host "Example import with auth file: import-module CanvasPS -ArgumentList .\tmp\auth.xml`n"
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
}

if($null -eq $auth){
  $auth = New-Object -TypeName psobject
  $auth | Add-Member -MemberType NoteProperty -Name 'uri' -Value "" -force
  #$auth.uri = ""
}

