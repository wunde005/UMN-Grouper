#region createcredentialfile

#function createcredentialfile{
        <#
            .SYNOPSIS
                Create credential file that can be used during modue load

            .DESCRIPTION
                Create credential file that can be used during modue load
				All inputs are optional.  Script will prompt for missing values and password if pscred not supplied

            .PARAMETER psCreds
                PScredential composed of your username/password to Server

			.PARAMETER uri
				Grouper base uri

			.PARAMETER username
			    username for group
			
			.PARAMETER filename
				name of xml file to save credentials to
			
			.PARAMETER outputobject
				return credential info as PS object

            .NOTES
                Author: Eric Wunderlin
                LASTEDIT: 9/21/2022

            .EXAMPLE

        #>

param(
	[string]$uri,
	[string]$username,
	[PSCredential]$pscred,
	[switch]$outputobject,
	[string]$filename
)

	[PSCustomObject]$credentials = [PSCustomObject]@{
		uri = "";
		pscred = "";
	}

	if([string]::IsNullOrEmpty($uri)){
		$uri = Read-Host -Prompt 'Grouper URI'
	}

	$credentials | Add-Member -MemberType NoteProperty -Name 'uri' -Value $uri -force
	
	
	if($null -eq $pscred){
		if([string]::IsNullOrEmpty($username)){
			$lpscred = Get-Credential
		}
		else{
			$lpscred = Get-Credential -UserName $username
		}
	}
	else{
		$lpscred = $pscred
	}
	
	$credentials | Add-Member -MemberType NoteProperty -Name 'pscred' -Value $lpscred -force
	if(-not $outputobject){	
		if([string]::IsNullOrEmpty($filename)){
			$filename = Read-Host -Prompt 'File to save credentials'
		}

		$credentials | Export-Clixml $filename
	}
	else{
		return $credentials
	}
#}