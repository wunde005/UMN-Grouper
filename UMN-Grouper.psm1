#region License
    # Copyright 2017 University of Minnesota, Office of Information Technology

    # This program is free software: you can redistribute it and/or modify
    # it under the terms of the GNU General Public License as published by
    # the Free Software Foundation, either version 3 of the License, or
    # (at your option) any later version.

    # This program is distributed in the hope that it will be useful,
    # but WITHOUT ANY WARRANTY; without even the implied warranty of
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    # GNU General Public License for more details.

    # You should have received a copy of the GNU General Public License
    # along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#endregion

param(
    [parameter(Position=0,Mandatory=$false)]$modargument
    #$auth_file
)

write-verbose "type:$($modargument.gettype())"
$ptype=$modargument.gettype()
if($ptype.name -eq "Hashtable"){
    write-host "got hashtable"
    $usehash = $true
}
elseif($ptype.name -eq "PSCustomObject" ){
    $usepsobj = $true
}
elseif($ptype.name -eq "String"){
    $auth_file = $modargument
}

#$auth.uri = ""

$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )
write-verbose "Private files:$($Private.name)"
Foreach($import in @($Private + $public + $Public_gen))
    {
        Try
        {
            if($null -eq $import.fullname){
                
            }

            elseif($import.name -eq "z_auth.ps1"){
                try{
                    write-host "load config:$usepsobj"
                    if($usepsobj){
                        . $import.fullname -auth_obj $modargument
                    }
                    else{
                        . $import.fullname -auth_file $auth_file
                    }
                }
                catch{
                    Write-Warning "Failed auth load"
                    return
                }
            }
            else{
                . $import.fullname
            }
        }
        Catch
        {
            Write-Error -Message "Failed to import function $($import.fullname): $_"
        }
    }

if(-NOT [string]::IsNullOrEmpty($auth_file)){
   #z_auth $auth_file
    # .  $authload $auth_file
    #write-host "auth:$($auth | convertto-json -Depth 10)"
}

#region New-GrouperHeader
    function New-GrouperHeader
    {
        <#
            .SYNOPSIS
                Create Header to be consumed by all other functions

            .DESCRIPTION
                Create Header to be consumed by all other functions

            .PARAMETER psCreds
                PScredential composed of your username/password to Server

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 6/20/2018

            .EXAMPLE

        #>
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory)]
            [System.Management.Automation.PSCredential]$psCreds
        )
        $authstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($psCreds.UserName+':'+$psCreds.GetNetworkCredential().Password))
        return (@{"Authorization" = "Basic $authstring"})
    }
#endregion


#region Get-GrouperGroup
function Get-GrouperGroup
{
    <#
        .SYNOPSIS
            Get Grouper Group(s)

        .DESCRIPTION
            Get Grouper Group(s)

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER groupName
            Use this if you know the exact name

        .PARAMETER stemName
            Use this to get a list of groups in a specific stem.  Use Get-GrouperStem to find stem

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        #[Parameter(Mandatory)]
        [string]$uri,

        #[Parameter(Mandatory)]
        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory,ParameterSetName='groupName')]
        [string]$groupName,

        [Parameter(ParameterSetName='groupName')]
        [switch]$search,

        [Parameter(Mandatory,ParameterSetName='stemName')]
        [string]$stemName,

        #FIND_BY_GROUP_UUID
        [Parameter(Mandatory,ParameterSetName='uuid')]
        [string]$uuid,

        [string]$subjectId,
        [switch]$rawoutput
    )

    Begin
    {
        
        $luri = rtnuri -uri $uri -target "groups"

        $body = @{}
    }

    Process
    {

        if ($groupName)
        {
            if ($search){
                $body['WsRestFindGroupsRequest'] = @{
                    wsQueryFilter = @{
                        groupName = $groupName;
                        queryFilterType = 'FIND_BY_GROUP_NAME_APPROXIMATE'
                    }
                }
            }
            else{
                $body['WsRestFindGroupsRequest'] = @{
                    wsQueryFilter = @{
                            groupName = $groupName;
                            queryFilterType = 'FIND_BY_GROUP_NAME_EXACT';
                            #IgnoreCase = $false
                        };
                        
                    }
                }

            }
        elseif($uuid){
            $body['WsRestFindGroupsRequest'] = @{
                wsQueryFilter = @{
                    groupUuid = $uuid;
                    queryFilterType = 'FIND_BY_GROUP_UUID'
                }
            }

        }

        else
        {
            $body['WsRestFindGroupsRequest'] = @{
                wsQueryFilter = @{
                    stemName = $stemName;
                    queryFilterType = 'FIND_BY_STEM_NAME'
                }
            }
        }
        if ($subjectId)
        {

            $body['WsRestFindGroupsRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
        }
        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose -Message $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        if($rawoutput){
            return $response
        }
        else{
            return ($response.Content | ConvertFrom-Json).WsFindGroupsResults.groupResults
        }
    }

    End{}
}
#endregion

function Get-GrouperSubjects
{
    <#
        .SYNOPSIS
            Get Grouper Group(s)

        .DESCRIPTION
            Get Grouper Group(s)

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER groupName
            Use this if you know the exact name

        .PARAMETER stemName
            Use this to get a list of groups in a specific stem.  Use Get-GrouperStem to find stem

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        #[Parameter(Mandatory)]
        [string]$uri,

        #[Parameter(Mandatory)]
        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        #[Parameter(Mandatory,ParameterSetName='groupName')]
        #[string]$groupName,

        #[Parameter(ParameterSetName='groupName')]
        #[switch]$search,

        #[Parameter(Mandatory,ParameterSetName='stemName')]
        #[string]$stemName,

        #FIND_BY_GROUP_UUID
        #[Parameter(Mandatory,ParameterSetName='uuid')]
        #[string]$uuid,

        [string]$subject,
        [switch]$rawoutput
    )

    Begin
    {
        
        $luri = rtnuri -uri $uri -target "subjects"
        $subjectSourceId = "umnldap"
        $body = @{
            WsRestGetSubjectsRequest = @{
                wsSubjectLookups = @(@{subjectIdentifier = $subject;subjectSourceId = $subjectSourceId})
            }
        }
        #$body = @{}
    }

    Process
    {

        if ($subject)
        {
         #   $luri = $luri + "/" + $subject
        }    
        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose -Message $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -body $body -Method POST -UseBasicParsing -ContentType $contentType
        if($rawoutput){
            return $response
        }
        else{
            return ($response.Content | ConvertFrom-Json).WsFindGroupsResults.groupResults
        }
    }

    End{}
}
#endregion


#region Get-GrouperGroupMembers
    function Get-GrouperGroupMembers
    {
        <#
            .SYNOPSIS
                Get List of Members in a Group

            .DESCRIPTION
                Get List of Members in a Group

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER groupName
                This represents the identifier for the group, it should look like 'stemname:group'
                Example: stem1:substem:supergroup

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            [string]$uri,

            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            [Parameter(Mandatory)]
            [string]$groupName,

            [string]$subjectId,
            [switch]$rawoutput
        )

        Begin{}

        Process
        {
            $luri = rtnuri -uri $uri -target "groups"
           
            $body = @{
                WsRestGetMembersRequest = @{
                    subjectAttributeNames = @("description")
                    wsGroupLookups = @(@{groupName = $groupName})
                }
            }
                     

            if ($subjectId)
            {

                #$body['WsRestGetMembersRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
                $body['WsRestGetMembersRequest']['actAsSubjectLookup'] = @{subjectIdentifier = $subjectId};
            }
            $body = $body | ConvertTo-Json -Depth 5
            Write-Verbose -Message $body
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            if($rawoutput){
                return $response
            }
            else{
                #write-verbose (($response | convertfrom-json).WsGetMembersResults.results.wsSubjects | convertto-json)
            
                $rtnvalue = ($response.Content | ConvertFrom-Json).WsGetMembersResults.results.wsSubjects
                if($null -eq $rtnvalue){
                    return ,@()
                }
                return $rtnvalue
            }    
        }

        End{}
    }
#endregion

#region Get-GrouperGroupsForMember
function Get-GrouperGroupsForMember
{
    <#
        .SYNOPSIS
            Get List of Members in a Group

        .DESCRIPTION
            Get List of Members in a Group

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER memberName
            This represents the member for which you want to retrieve the list of groups by

        .PARAMETER subjectSourceId
            Source location of subjectId, ie ldap

        .PARAMETER memberFilter
            Can base membership list based on memberfilter (e.g. All, Immediate, Effective)
            Immediate = Direct membership, Effective = Inherited

        .PARAMETER stemName
            Limit search to stem

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 6/30/2019

        .EXAMPLE
            Get-GrouperGroupsForMember -uri $uri -header $header -memberName 'ldap_Identifier' -subjectSourceId 'umnldap' -stemName 'umn:itac'
    #>
    [CmdletBinding()]
    param
    (
        [string]$uri,

        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory,ParameterSetName='subjectId')]
        [string]$subjectId,

        [Parameter(Mandatory,ParameterSetName='subjectIdentifier')]
        [string]$subjectIdentifier,

        [string]$actAsSubjectId,

        [Parameter(Mandatory)]
        [string]$subjectSourceId,

        [string]$stemName,

        [ValidateSet("All", "Immediate", "Effective")]
        [string]$memberFilter
    )

    Begin{}

    Process
    {
        $luri = rtnuri -uri $uri
        $luri = "$luri/memberships"
        $body = @{
            WsRestGetMembershipsRequest = @{
                fieldName = 'members'
                wsSubjectLookups = @(@{subjectId = $memberName;subjectSourceId = $subjectSourceId})
            }
        }
        if ($subjectIdentifier){$body['WsRestGetMembershipsRequest']['wsSubjectLookups'] = @(@{subjectIdentifier = $subjectIdentifier;subjectSourceId = $subjectSourceId})}
        else{$body['WsRestGetMembershipsRequest']['wsSubjectLookups'] = @(@{subjectId = $subjectId;subjectSourceId = $subjectSourceId})}
        if ($actAsSubjectId)
        {

            $body['WsRestGetMembershipsRequest']['actAsSubjectLookup'] = @{subjectId = $actAsSubjectId};
        }
        if($memberFilter)
        {
            $body['WsRestGetMembershipsRequest']['memberFilter'] = $memberFilter;
        }
        if($stemName)
        {
            $body['WsRestGetMembershipsRequest']['wsStemLookup'] = @{stemName = $stemName}
            $body['WsRestGetMembershipsRequest']['stemScope'] = 'ALL_IN_SUBTREE'
        }
        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose -Message $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        return ($response.Content | ConvertFrom-Json).WsGetMembershipsResults.wsGroups
    }

    End{}
}
#endregion

#region Get-GrouperPrivileges
function Get-GrouperPrivileges
{
    <#
        .SYNOPSIS
            Get Grouper Privileges

        .DESCRIPTION
            Get Grouper Privileges

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER stemName
            stemName

        .PARAMETER subjectId
            Filter result for a specific user

        .PARAMETER actAsSubjectId
            User security context to restrict search to.  ie search as this user

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        [string]$uri,

        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory,ParameterSetName='stem')]
        [string]$stemName,

        [Parameter(Mandatory,ParameterSetName='group')]
        [string]$groupName,

        [string]$actAsSubjectId,

        [string]$subjectId
    )

    Begin{}
    Process
    {
        $luri = rtnuri -uri $uri -target "grouperPrivileges"
        $body = @{
            WsRestGetGrouperPrivilegesLiteRequest = @{}
        }
        if ($subjectId)
        {

            $body['WsRestGetGrouperPrivilegesLiteRequest']['subjectId'] = $subjectId
        }
        if ($actAsSubjectId)
        {

            $body['WsRestGetGrouperPrivilegesLiteRequest']['actAsSubjectId'] = $actAsSubjectId
        }
        if ($groupName)
        {

            $body['WsRestGetGrouperPrivilegesLiteRequest']['groupName'] = $groupName
        }
        if ($stemName)
        {

            $body['WsRestGetGrouperPrivilegesLiteRequest']['stemName'] = $stemName
        }

        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        Write-Verbose ($response.Content | ConvertFrom-Json).WsGetGrouperPrivilegesLiteResult
        return ($response.Content | ConvertFrom-Json).WsGetGrouperPrivilegesLiteResult.privilegeResults
    }
    End{}
}
#endregion

#region Get-GrouperStem
    function Get-GrouperStem
    {
        <#
            .SYNOPSIS
                Get Grouper Stem(s)

            .DESCRIPTION
                Get a Grouper Stem or use the -search switch to get all Grouper Stem(s) that match stem pattern
                From API docs -- find by approx name, pass the name in. stem name is required

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER stemName
                stemName

            .PARAMETER search
                Switch to do a search.  Use with the caution, results from grouper API are not very reliable

            .PARAMETER subjectId
                Set this to a username to search as that user if you have access to

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            #[Parameter(Mandatory)]
            [string]$uri,

            #[Parameter(Mandatory)]
            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            [Parameter(Mandatory)]
            [string]$stemName,

            [switch]$search,

            [string]$subjectId
        )

        Begin{}

        Process
        {
            $luri = rtnuri -uri $uri -target "stems"
        

            $body = @{
                    WsRestFindStemsRequest = @{
                        wsStemQueryFilter = @{stemName = $stemName}
                    }
            }

            if ($search){$body['WsRestFindStemsRequest']['wsStemQueryFilter']['stemQueryFilterType'] = 'FIND_BY_STEM_NAME_APPROXIMATE'}
            else{$body['WsRestFindStemsRequest']['wsStemQueryFilter']['stemQueryFilterType'] = 'FIND_BY_STEM_NAME'}

            if ($subjectId)
            {
                $body['WsRestFindStemsRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
            }
            $body = $body | ConvertTo-Json -Depth 5
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            if (($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults.count -gt 0)
            {
                ($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults
            }
            else {
                Write-Verbose "NO results found"
            }
        }

        End{}
    }
#endregion

#region Get-GrouperStemByParent
    function Get-GrouperStemByParent
    {
        <#
            .SYNOPSIS
                Get Grouper child Stem(s) of a parent stem

            .DESCRIPTION
                Get Grouper child Stem(s) of a parent stem

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER parentStemName
                stemName of Parent

            .PARAMETER noRecursion
                By default the function will recursivly search for all sub-stems, use this switch to only get stems one level below the parent stem

            .PARAMETER subjectId
                Set this to a username to search as that user if you have access to

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            [string]$uri,

            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            [Parameter(Mandatory)]
            [string]$parentStemName,

            [switch]$noRecursion,

            [string]$subjectId
        )

        Begin{}

        Process
        {
            $luri = rtnuri -uri $uri -target "stems"
       
            $body = @{
                    WsRestFindStemsRequest = @{
                        wsStemQueryFilter = @{parentStemName = $parentStemName;stemQueryFilterType = 'FIND_BY_PARENT_STEM_NAME'}
                    }
            }
            if($noRecursion){$body['WsRestFindStemsRequest']['wsStemQueryFilter']["parentStemNameScope"] = 'ONE_LEVEL'}
            else{$body['WsRestFindStemsRequest']['wsStemQueryFilter']["parentStemNameScope"] = 'ALL_IN_SUBTREE'}

            if ($subjectId)
            {

                $body['WsRestFindStemsRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
            }
            $body = $body | ConvertTo-Json -Depth 5
            Write-Verbose -Message $body
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            if (($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults.count -gt 0)
            {
                ($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults
            }
            else {
                Write-Verbose "NO results found"
            }
        }

        End{}
    }
#endregion

#region Get-GrouperStemByUUID
function Get-GrouperStemByUUID
{
    <#
        .SYNOPSIS
            Get a Grouper Stem by its UUID

        .DESCRIPTION
            Get a Grouper Stem by its UUID

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER uuid
            UUID of the stem to retrieve

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
                [string]$uri,

                [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory)]
        [string]$uuid,

        [string]$subjectId
    )

    Begin{}

    Process
    {
        $luri = rtnuri -uri $uri -target "stems"
       
        $body = @{
                WsRestFindStemsRequest = @{
                    wsStemQueryFilter = @{stemUuid = $uuid;stemQueryFilterType = 'FIND_BY_STEM_UUID'}
                }
        }

        if ($subjectId)
        {

            $body['WsRestFindStemsRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
        }
        $body = $body | ConvertTo-Json -Depth 5
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        if (($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults.count -gt 0)
        {
            ($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults
        }
        else {
            Write-Verbose "NO results found"
        }
    }

    End{}
}
#endregion

<# Redundant use "get-groupergroup -stem stem"
#region Get-GrouperGroupsByStem
function Get-GrouperGroupsByStem
{
    
        .SYNOPSIS
            Create new Group in Grouper

        .DESCRIPTION
            Create new Group in Grouper

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER stem
            This represents the identifier for the group, it should look like 'stemname:group'
            Example: stem1:substem:supergroup

        .PARAMETER description
            The description represents the the Name in the form users in the UI will see the group

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    
    [CmdletBinding()]
    param
    (
                [string]$uri,

                [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory)]
        [string]$stem

        )

    Begin{
        $results =@()
    }

    Process
    {
        if([string]::IsNullOrEmpty($uri)){
            $uri = $auth.uri
        }
       
        $uri = "$uri/groups"
        
        $body = @{ WsRestFindGroupsRequest = @{
                wsQueryFilter = @{queryFilterType = "FIND_BY_STEM_NAME";stemName=$stem;}
                }} | ConvertTo-Json -Depth 5
        $response = Invoke-WebRequest -Uri $uri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        if (($response.Content | ConvertFrom-Json).WsFindGroupsResults.groupResults.Count -gt 0)
        {
            $results = ($response.Content | ConvertFrom-Json).WsFindGroupsResults.groupResults
        }
        else {
            Write-Verbose "NO results found"
        }
        #return $null
    }

    End{
         return $results}
}
#endregion
#>

#region New-GrouperGroup
    function New-GrouperGroup
    {
        <#
            .SYNOPSIS
                Create new Group in Grouper

            .DESCRIPTION
                Create new Group in Grouper

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER groupName
                This represents the identifier for the group, it should look like 'stemname:group'
                Example: stem1:substem:supergroup

            .PARAMETER description
                The description represents the the Name in the form users in the UI will see the group

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            [string]$uri,

            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            #[Parameter(Mandatory)]
            [string]$groupName,

            [string]$description="",
            
            #[Parameter(Mandatory)]
            [string]$displayExtension,
            [string]$bodyin,
            [PSCustomObject[]]$addobj,
            [switch]$createParentStemsIfNotExist=$false


            
            

        )

        Begin{}

        Process
        {
            $luri = rtnuri -uri $uri -target "groups"

            if($bodyin){
                $body = $bodyin 
            }
            else{
            if($addobj.count -gt 0){

            }
            else{
                $addobj = @([PSCustomObject]@{
                    name= $groupName
                    #extension=;
                    displayExtension=$displayExtension;
                    description=$description;
                    <#details=@{
                        attributeNames=@('csom_ad_test');
                        attributeValues=@(123)
                    }#>

                    })
            }

            if($createParentStemsIfNotExist){
                $createParentStemsIfNotExist_text = "T"

            }
            else{
                $createParentStemsIfNotExist_text = "F"
            }

            $wsgrouptosaves = @()
            #csom_ad_test
            foreach ($obj in $addobj){
                $wsGroup = @{
                    
                    wsGroupLookup=@{
                        groupName=$obj.name
                    }
                    wsGroup=$obj;
                    createParentStemsIfNotExist=$createParentStemsIfNotExist_text
                }
                $wsgrouptosaves += $wsgroup
                #return $obj
            }
            #return $wsgrouptosaves
            <#
             {
        "wsGroup":{
          "extension":"whateverGroupLeft",
          "description":"whateverGroupLeftDesc",
          "displayExtension":"whateverGroupLeftDispExt",
          "name":"aStem:whateverGroupLeft"
        },
        "wsGroupLookup":{
          "groupName":"aStem:whateverGroupLeft"
        }
        
      }
      #>
            #return $wsgrouptosaves
        
            
            $body = @{
                WsRestGroupSaveRequest = 
                    #wsGroupToSaves = @(@{wsGroup = @{description = $description;displayExtension = $displayExtension;name = $groupName};wsGroupLookup = @{groupName = $groupName}})
                    @{
                        wsGroupToSaves = $wsgrouptosaves;
                        
                    }
            } | ConvertTo-Json -Depth 10
        }

            #write-verbose $body
            #return $body
            try{
             #   write-host "Invoke-WebRequest -Uri $uri -Headers $((rtnheader $header)) -Method Post -Body $body -UseBasicParsing -ContentType $contentType"
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            }
            catch {
                write-host "error"
                #return $psitem
                if($_.ErrorDetails.Message) {

                    #Write-Host ($_.ErrorDetails.Message | convertfrom-json -Depth 100)
                    $ngresp =  $_.ErrorDetails.Message |convertfrom-json
                    if($ngresp.WsGroupSaveResults.results.resultMetadata.resultMessage.contains("Caused by: edu.internet2.middleware.grouper.exception.StemNotFoundException:")){
                        write-host "bad stem path"
                        Write-Host $psitem     
                    }
                    else {
                        write-host $ngresp.WsGroupSaveResults.results.resultMetadata.resultMessage
                        write-host $psitem
                    }
                } else {
                    Write-Host ($psitem | convertto-json)
                }
            }
            #return $response
            if($null -eq $response.Content){
                return $response
            }
            else{
                return ($response.Content | ConvertFrom-Json).WsGroupSaveResults.results.wsGroup
            }
        }

        End{}
    }
#endregion

#region New-GrouperGroupMember
    function New-GrouperGroupMember
    {
        <#
            .SYNOPSIS
                Add a user to a Group

            .DESCRIPTION
                Add a user to a Group

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER groupName
                This represents the identifier for the group, it should look like 'stemname:group'
                Example: stem1:substem:supergroup

            .PARAMETER subjectId
                Each implemetation of Grouper will determine what this value represents

            .PARAMETER subjectIdentifier
                Alternative way to identify user to be added

            .PARAMETER subjectSourceId
                Source location of subjectId, ie ldap

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            #[Parameter(Mandatory)]
            [string]$uri,

            #[Parameter(Mandatory)]
                [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            #[Parameter(Mandatory)]
            [Parameter(Mandatory,ParameterSetName='subjectIdentifiername')]
            [string]$groupName,

            [Parameter(Mandatory,ParameterSetName='subjectIduuid')]
            [Parameter(Mandatory,ParameterSetName='subjectIdname')]
            [string[]]$subjectId,

            [Parameter(Mandatory,ParameterSetName='subjectIdentifieruuid')]
            [Parameter(Mandatory,ParameterSetName='subjectIdentifiername')]
            [string[]]$subjectIdentifier,

            [string]$subjectSourceId,
            [Parameter(Mandatory,ParameterSetName='subjectIdentifieruuid')]
            [string]$groupUuid,
	    [switch]$replaceallexisting=$false
        )
 
        Begin{}

        Process
        {
        $luri = rtnuri -uri $uri -target "groups"
        if ($subjectIdentifier){
		    $subjectlookups = @()
		    foreach ($i in $subjectidentifier){
			    $subjectLookups += @{subjectIdentifier = $i}
		    }    
        }    
	    else{
		$subjectlookups = @()
		foreach ($i in $subjectid){
			$subjectlookups += @{subjectId = $i}
		}
		#$subjectLookups = @(@{subjectId = $subjectId})
	    }
            if ($subjectSourceId){$subjectLookups[0]['subjectSourceId'] = $subjectSourceId}
            #write-host $subjectlookups
            #write-host $groupname
	    if($replaceallexisting){
	    	$replaceallexistingtxt = "T"
            }
            else{
	    	$replaceallexistingtxt = "F"
            }
            #Either uuid or groupname
            if($groupUuid){
                $wsGroupLookup = @{uuid = $groupuuid}
            }
            else{
                $wsGroupLookup = @{groupName = $groupName}
            }
            $body = @{
                WsRestAddMemberRequest = @{
                    replaceAllExisting = "$replaceallexistingtxt"
                    subjectLookups = $subjectLookups
                    wsGroupLookup = $wsGroupLookup
                    
                }
            
            } | ConvertTo-Json -Depth 5
               
            Write-Verbose $body
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            #trying to avoid json convert errors on invalid returns
            if($response.content){
	            return @(($response.Content | ConvertFrom-Json).WsAddMemberResults.results.wsSubject,($response.Content | ConvertFrom-Json).WsAddMemberResults.wsGroupAssigned)
            }
            else{
                write-host "invalid response content"
                return $response
            }
            }

        End{}
    }
#endregion

#region New-GrouperGroupMember
function Remove-GrouperGroupMember
{
    <#
        .SYNOPSIS
            Add a user to a Group

        .DESCRIPTION
            Add a user to a Group

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER groupName
            This represents the identifier for the group, it should look like 'stemname:group'
            Example: stem1:substem:supergroup

        .PARAMETER subjectId
            Each implemetation of Grouper will determine what this value represents

        .PARAMETER subjectIdentifier
            Alternative way to identify user to be added

        .PARAMETER subjectSourceId
            Source location of subjectId, ie ldap

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        #[Parameter(Mandatory)]
        [string]$uri,

        #[Parameter(Mandatory)]
            [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory)]
        [string]$groupName,

        [Parameter(Mandatory,ParameterSetName='subjectId')]
        [string[]]$subjectId,

        [Parameter(Mandatory,ParameterSetName='subjectIdentifier')]
        [string[]]$subjectIdentifier,

        [string]$subjectSourceId,
    [switch]$replaceallexisting=$false
    )

    Begin{}

    Process
    {
        $luri = rtnuri -uri $uri -target "groups"
        if ($subjectIdentifier){
    $subjectlookups = @()
    foreach ($i in $subjectidentifier){
        $subjectLookups += @{subjectIdentifier = $i}
    }
            
        
        }
        
    else{
    $subjectlookups = @()
    foreach ($i in $subjectid){
        $subjectlookups += @{subjectId = $i}
    }
    #$subjectLookups = @(@{subjectId = $subjectId})
    }
        if ($subjectSourceId){$subjectLookups[0]['subjectSourceId'] = $subjectSourceId}
        #write-host $subjectlookups
        #write-host $groupname
        <#
        {
  "WsRestDeleteMemberRequest":{
    "subjectLookups":[
        {
        "subjectIdentifier":"000000000"
        },
        {
        "subjectIdentifier":"name"
        }
    ],
    "wsGroupLookup":{
      "groupName":"subfolder1:examples:group1"
    }
  }
}
        #>

        $body = @{
            WsRestDeleteMemberRequest = @{
                subjectLookups = $subjectLookups
                wsGroupLookup = @{groupName = $groupName}
            }
        } | ConvertTo-Json -Depth 5
        Write-Verbose $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        
    return @(($response.Content | ConvertFrom-Json).WsAddMemberResults.results.wsSubject,($response.Content | ConvertFrom-Json).WsAddMemberResults.wsGroupAssigned)
    }

    End{}
}
#endregion


#region Set-GrouperPrivileges/New-GrouperPrivileges
function Set-GrouperPrivileges
{
    <#
        .SYNOPSIS
            Set Grouper Privileges, either Add or Remove based on 'allowed' paramter

        .DESCRIPTION
            Set Grouper Privileges, either Add or Remove based on 'allowed' paramter

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER stemName
            stemName

        .PARAMETER subjectId
            User to apply Privilege to

        .PARAMETER actAsSubjectId
            User security context to use to apply change

        .PARAMETER privilegeName
            Name of privilege to apply, see Get-GrouperPrivileges for examples

        .PARAMETER allowed
            Setting this to 'T' (true) will ADD the priviledge, while setting it to 'F' (false) will remove the Privilege

        .PARAMETER subjectIdIsAGroup
            Use this switch (set to true) if the subjectID is actually a GroupName.  The default assumption is that the subjectID is a users ID

        .NOTES
            Author: Travis Sobeck
            LASTEDIT: 7/30/2018

        .EXAMPLE
    #>
    [CmdletBinding()]
    [Alias('New-GrouperPrivileges')]
    param
    (
                [string]$uri,

                [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Parameter(Mandatory,ParameterSetName='stem')]
        [string]$stemName,

        [Parameter(Mandatory,ParameterSetName='group')]
        [string]$groupName,

        [string]$actAsSubjectId,

        [Parameter(Mandatory)]
        [string]$subjectId,

        [switch]$subjectIdIsAGroup = $false,

        [Parameter(Mandatory)]
        [string]$privilegeName,

        [ValidateSet("T","F")]
        [string]$allowed = 'T'
    )

    Begin{}
    Process
    {
        $luri = rtnuri -uri $uri -target "grouperPrivileges"
        $body = @{
            WsRestAssignGrouperPrivilegesLiteRequest = @{
                allowed = $allowed
                privilegeName = $privilegeName
            }
        }
        if ($subjectIdIsAGroup)
        {
            $body['WsRestAssignGrouperPrivilegesLiteRequest']['subjectIdentifier'] = $subjectId
            $body['WsRestAssignGrouperPrivilegesLiteRequest']['subjectSourceId'] = "g:gsa"
        }
        else {$body['WsRestAssignGrouperPrivilegesLiteRequest']['subjectId'] = $subjectId}

        if ($actAsSubjectId)
        {

            $body['WsRestAssignGrouperPrivilegesLiteRequest']['actAsSubjectId'] = $actAsSubjectId
        }
        if ($groupName)
        {

            $body['WsRestAssignGrouperPrivilegesLiteRequest']['groupName'] = $groupName
            $body['WsRestAssignGrouperPrivilegesLiteRequest']['privilegeType'] = 'access'
        }
        if ($stemName)
        {

            $body['WsRestAssignGrouperPrivilegesLiteRequest']['stemName'] = $stemName
            $body['WsRestAssignGrouperPrivilegesLiteRequest']['privilegeType'] = 'naming'
        }

        $body = $body | ConvertTo-Json -Depth 5
        
        $response = Invoke-WebRequest -Uri $iuri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        return ($response.Content | ConvertFrom-Json).WsGetGrouperPrivilegesLiteResult.privilegeResults
        #need to fix?
        if (($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults.count -gt 0)
        {
            ($response.Content | ConvertFrom-Json).WsFindStemsResults.stemResults
        }
        else {
            Write-Verbose "NO results found"
        }
    }
    End{}
}
#endregion

#region New-GrouperStem
    function New-GrouperStem
    {
        <#
            .SYNOPSIS
                Create new Stem in Grouper

            .DESCRIPTION
                Create new Stem in Grouper

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER stemName
                This represents the identifier for the stem, it should look like 'stemParentA:stemParentB:stemname'
                Example: stem1:substem:newstem

            .PARAMETER description
                The description represents the the Name in the form users in the UI will see the group

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
     #       [Parameter(Mandatory)]
            [string]$uri,

      #      [Parameter(Mandatory)]
            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

             [Parameter(Mandatory)]
            [string]$stemName,

            [string]$description="",
            [Parameter(Mandatory)]
            
            [string]$displayExtension
        )

        Begin{}

        Process
        {
        $luri = rtnuri -uri $uri -target "stems"
       
            $body = @{
                WsRestStemSaveRequest = @{
                    wsStemToSaves = @(@{wsStem = 
                                    @{  description = $description;
                                        displayExtension = $displayExtension;
                                        name = $stemName};
                                    wsStemLookup = @{stemName = $stemName}})
                }
            } | ConvertTo-Json -Depth 5
            #write-host "$uri"
            #write-host "$body"
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            return ($response.Content | ConvertFrom-Json).WsStemSaveResults.results.wsStem
        }

        End{}
    }
#endregion

#region Remove-GrouperGroup
    function Remove-GrouperGroup
    {
        <#
            .SYNOPSIS
                Remove a Grouper Group

            .DESCRIPTION
                Remove a Grouper Group

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER groupName
                The groupName, use Get-GrouperGroup to the get the "name" field

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            #[Parameter(Mandatory)]
            [string]$uri,

            #[Parameter(Mandatory)]
            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            [Parameter(Mandatory)]
            [string[]]$groupName
        )

        Begin{}

        Process
        {
            $luri = rtnuri -uri $uri -target "groups"
            <# This didn't seem to work :()
                foreach ($gn in $groupName)
                {
                    $gnArray = $gnArray + @{groupName = $gn}
                }
                $body = @{
                    WsRestGroupDeleteRequest = @{
                        wsGroupLookups = $gnArray
                    }
                } | ConvertTo-Json -Depth 5
            #>
            foreach ($gn in $groupName)
            {
                $body = @{
                    WsRestGroupDeleteRequest = @{
                        wsGroupLookups = @(@{groupName = $gn})
                    }
                } | ConvertTo-Json -Depth 5
                $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
                $deletedGroups = ($response.Content | ConvertFrom-Json).WsGroupDeleteResults.results.wsGroup
                $deletedGroups
            }

            #return ($response.Content | ConvertFrom-Json).WsGroupDeleteResults.results.resultMetadata.resultCode
        }

        End{}
    }
#endregion

#region Remove-GrouperStem
    function Remove-GrouperStem
    {
        <#
            .SYNOPSIS
                Remove a Grouper Stem

            .DESCRIPTION
                Remove a Grouper Stem

            .PARAMETER uri
                Full path to Server plus path to API
                Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

            .PARAMETER header
                Use New-GrouperHeader to get this

            .PARAMETER contentType
                Set Content Type, currently 'text/x-json;charset=UTF-8'

            .PARAMETER stemName
                Use Get-GrouperStem to find name

            .PARAMETER removeGroups
                Grouper will not remove a Stem with other Stems or Groups in it. Set this to remove all the groups first

            .PARAMETER recursive
                Recursively remove all child stems

            .NOTES
                Author: Travis Sobeck
                LASTEDIT: 7/30/2018

            .EXAMPLE
        #>
        [CmdletBinding()]
        param
        (
            #[Parameter(Mandatory)]
            [string]$uri,

            #[Parameter(Mandatory)]
            [System.Collections.Hashtable]$header,

            [string]$contentType = 'text/x-json;charset=UTF-8',

            [Parameter(Mandatory)]
            [string]$stemName,

            [switch]$removeGroups,

            [switch]$recursive
        )

        Begin{}

        Process
        {
            if ($recursive)
            {
                $stemNames = (Get-GrouperStemByParent -uri $uri -header $header -parentStemName $stemName -noRecursion).Name
                Write-Verbose "Child Stems: $stemNames"
                foreach ($stem in $stemNames)
                {
                    (Remove-GrouperStem -uri $uri -header $header -stemName $stem -removeGroups:$removeGroups -recursive:$recursive).name
                }
            }
            if ($removeGroups)
            {
                # Get all the groups
                $groupNames = (Get-GrouperGroup -uri $uri -header $header -stemName $stemName).name
                # Remove the groups
                Write-Verbose "Child groups: $groupNames"
                foreach ($groupName in $groupNames)
                {
                    $null = Remove-GrouperGroup -uri $uri -header $header -groupName $groupName
                }
                Start-Sleep -Seconds 1
            }
           $luri = rtnuri -uri $uri -target "stems"
        
            $body = @{
                WsRestStemDeleteRequest = @{
                    wsStemLookups = @(@{stemName = $stemName})
                }
            } | ConvertTo-Json -Depth 5
            $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
            $removedStems = ($response.Content | ConvertFrom-Json).WsStemDeleteResults.results.wsStem
            return $removedStems
        }

        End{}
    }
#endregion

#region Remove-GrouperStem
function stemfromgroupname{
    <#
    .SYNOPSIS
        Returns stem from group name or group object

    .DESCRIPTION
        Returns stem from group name or group object

    .PARAMETER groupname
        Full path groupname including stem

    .PARAMETER group
        group object with name of group

    .NOTES
        Author: Eric Wunderlin
        LASTEDIT: 9/21/2022

    .EXAMPLE
        >stemfromgroupname -groupname "test:this:group"
        test:this

        >stemfromgroupname -group @{name="test:this:group"}
        test:this
    #>

    param(
        [Parameter(Mandatory,ParameterSetName='groupname')]
        [string]$groupname,
        [Parameter(Mandatory,ParameterSetName='group')]
        [PSCustomObject]$group
        )

    if([string]::IsNullOrEmpty($groupname)){
        $groupname = $group.name
    }
    $namearray = $groupname.split(":")
    
    #remove last item and re-join
    return (($namearray[0..($namearray.length - 2)]) -join ":")
    
}
#endregion


#region Get-GrouperGroupAttributeAssignments
    
function Get-GrouperGroupAttributeAssignments
{
    <#
        .SYNOPSIS
            Get Grouper Attribute Assignments for Group(s)

        .DESCRIPTION
            Get Grouper Attribute Assignments for Group(s) using either group or attribute assignments

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"
            
            Pulls from auth file if loaded

        .PARAMETER header
            Use New-GrouperHeader to get this
            
            Pulls from auth file if loaded

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER groupName
            Get Attributes assigned to this group

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .PARAMETER AttributeAssignDefName
            Use AttributeAssignDefName to get groups assigned to this attribute
        
        .PARAMETER rawoutput
            Return rawoutput from grouper api. Bypasses converting output to object
        
        .PARAMETER inbody
            Specify custom body for rest request

        .NOTES
            Author: Eric Wunderlin
            LASTEDIT: 9/21/2022

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        #[Parameter(Mandatory)]
        [string]$uri,

        #[Parameter(Mandatory)]
        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [string]$groupName,

        [string]$AttributeAssignDefName,
        [string]$subjectId,
        [switch]$rawoutput,
        [Hashtable]$inbody
        )

    Begin
    {    
        if([string]::IsNullOrEmpty($uri)){
            if([string]::IsNullOrEmpty($auth.uri)){
                write-host "no uri"
                $uri = Read-Host -Prompt 'Specify URI'
            }
            else{
                $uri = $auth.uri
            }   
            
        }
     
    }

    Process
    {
        $luri = rtnuri -uri $uri -target "attributeAssignments"
        $body = @{}

        write-verbose $uri
        $body = @{
            WsRestGetAttributeAssignmentsRequest=@{
            #       wsAttributeDefNameName=$AttributeAssignDefName;
                attributeAssignType="group";
                includeAssignmentsOnAssignments="T"
                #"actAsSubjectId":"GrouperSystem"
                #wsOwnerStemLookups
            }
        }
        
        if($subjectId -ne ""){
            write-verbose "adding specified actAsSubjectId"
            $body.actAsSubjectId = $subjectId
        }

        if($null -ne $inbody){
            write-verbose "running body from input"
            $body = $inbody
        }
        elseif("" -ne $groupname){
            write-verbose "running with groupname"
            $body.WsRestGetAttributeAssignmentsRequest.wsOwnerGroupLookups = @(@{groupName = $groupname})

        }
        else{
            Write-Verbose "running defaults"
            $body.WsRestGetAttributeAssignmentsRequest.wsAttributeDefNameLookups=@(@{name=$AttributeAssignDefName;})
        }

        $body = $body | ConvertTo-Json -Depth 5
        
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        
        if($rawoutput){
            return $response
        }
        else{
            return ,($response.content | convertfrom-json).WsGetAttributeAssignmentsResults.wsAttributeAssigns
        }
    }

    End{}
}
#endregion

#region Get-GrouperattributeDefNames

function Get-GrouperAttributeDefNames
{
    <#
        .SYNOPSIS
            Get Grouper Attribute Names

        .DESCRIPTION
            Get Grouper Attribute Names

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER scope
            Scope to look for attribute definintions

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .NOTES
            Author: Eric Wunderlin
            LASTEDIT: 9/21/2022

        .EXAMPLE
    #>
    [CmdletBinding()]
    param
    (
        [string]$uri,

        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        [Alias('stem')]
        [string]$scope,

        [string]$subjectId
    )

    Begin
    {
        
        $luri = rtnuri -uri $uri -target "attributeDefNames"
        
    }

    Process
    {
        $body = @{}
        write-host $luri
        <#
        {
            "WsRestFindAttributeDefNamesLiteRequest":{
                "scope":"test:"
            }
        }#>
        $body['WsRestFindAttributeDefNamesLiteRequest'] = @{scope = $scope}
        
        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose -Message $body
        
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
        
        if($rawoutput){
            return $response
        }
        return ($response.Content | ConvertFrom-Json).WsFindAttributeDefNamesResults.attributeDefNameResults

    }

    End{}
}
#endregion


#region Set-GrouperGroupAttributeAssignments

function Set-GrouperGroupAttributeAssignments
{
    <#
        .SYNOPSIS
            Set Grouper Group attributes with values

        .DESCRIPTION
            Get Grouper Group attributes with values

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER groupName
            Use this if you know the exact name

        .PARAMETER stemName
            Use this to get a list of groups in a specific stem.  Use Get-GrouperStem to find stem

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .NOTES
            Author: Eric Wunderlin
            LASTEDIT: 9/21/2022

        .EXAMPLE
    #>
    
    [CmdletBinding()]
    param
    (
        #[Parameter(Mandatory)]
        [string]$uri,

        #[Parameter(Mandatory)]
        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        #[Parameter(Mandatory,ParameterSetName='groupName')]
        [string]$groupName,

        #[Parameter(ParameterSetName='groupName')]
        [switch]$search,

        #[Parameter(Mandatory,ParameterSetName='stemName')]
        [string]$stemName,

        #[string]$scope,

        [string]$subjectId,
        [switch]$ReplaceValue,
        $value,
        [string]$AttributeAssignDefName,
        [switch]$rawoutput
            
    )

    Begin
    {
        
        if($replacevalue){
            $replacevaluetxt="replace_values";
        }
        else{
            #improve error handling when add value used with existing attributes?
            $replacevaluetxt = "add_value";
        }

        $luri = rtnuri -uri $uri -target "attributeAssignments"
        $body = @{}
    }

    Process
    {
        #swrite-host $uri
            <#
            "values":[
    {
    "valueSystem":"63"
    }
]             #>
            $body['WsRestAssignAttributesRequest']=@{
                values=@(
                    @{valueSystem=$value};
                    )
                attributeAssignType="group";
                wsAttributeDefNameLookups=@(
                    @{
                    name=$AttributeAssignDefName;
                    uuid=""}
                    );
                    #attributeAssignValueOperation="add_value";
                    attributeAssignValueOperation=$replacevaluetxt;
                    wsOwnerGroupLookups=@(
                        @{
                            groupName=$groupName;
                        };
                        
                    );
                    attributeAssignOperation="assign_attr"

                }
            
            
            #$body['WsRestFindAttributeDefNamesLiteRequest'] = @{scope = $scope}
            #if ($search){$body['WsRestFindGroupsRequest'] = @{wsQueryFilter = @{groupName = $groupName;queryFilterType = 'FIND_BY_GROUP_NAME_APPROXIMATE'}}}
            #else{$body['WsRestFindGroupsRequest'] = @{wsQueryFilter = @{groupName = $groupName;queryFilterType = 'FIND_BY_GROUP_NAME_EXACT'}}}
            #else{$body['WsRestFindGroupsRequest'] = @{wsQueryFilter = @{groupName = $groupName;queryFilterType = 'FIND_BY_GROUP_NAME_EXACT'}}}
        <#
        if ([string]::IsNullOrEmpty($subjectId))
        {
            $body['WsRestAssignAttributesRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
        }
        #>
        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose -Message $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
     
        if($rawoutput){
            return $response
        }
        else{
            $content = ($response.Content | ConvertFrom-Json)
            if($content.WsAssignAttributesResults.resultMetadata.success -eq 'T'){
                write-verbose "success"
            }
            else{
                write-warning "error?"
            }
            return $content.WsAssignAttributesResults
        }
    }
    End{}
}

    #$f= get-grouperattributeAssignments -rawout -groupname "app:csom_cloud_access:msba_6331:MSBA_6330_001_GROUP_4" -AttributeAssignDefName "app:csom_cloud_access:msba_6331:csom_ad_test" -value 123
#endregion


#region remove-GrouperGroupAttributeAssignments

function Remove-GrouperGroupAttributeAssignments
{
    <#
        .SYNOPSIS
            Set Grouper Group attributes with values

        .DESCRIPTION
            Get Grouper Group attributes with values

        .PARAMETER uri
            Full path to Server plus path to API
            Example "https://<FQDN>/grouper-ws/servicesRest/json/v2_2_100"

        .PARAMETER header
            Use New-GrouperHeader to get this

        .PARAMETER contentType
            Set Content Type, currently 'text/x-json;charset=UTF-8'

        .PARAMETER groupName
            Use this if you know the exact name

        .PARAMETER stemName
            Use this to get a list of groups in a specific stem.  Use Get-GrouperStem to find stem

        .PARAMETER subjectId
            Set this to a username to search as that user if you have access to

        .NOTES
            Author: Eric Wunderlin
            LASTEDIT: 9/21/2022

        .EXAMPLE
    #>
    
    [CmdletBinding()]
    param
    (
        #[Parameter(Mandatory)]
        [string]$uri,

        #[Parameter(Mandatory)]
        [System.Collections.Hashtable]$header,

        [string]$contentType = 'text/x-json;charset=UTF-8',

        #[Parameter(Mandatory,ParameterSetName='groupName')]
        [string]$groupName,

        #[Parameter(ParameterSetName='groupName')]
       # [switch]$search,

        #[Parameter(Mandatory,ParameterSetName='stemName')]
      #  [string]$stemName,

        #[string]$scope,

        [string]$subjectId,
       # [switch]$ReplaceValue,
       # $value,
        [string]$AttributeAssignDefName,
        [switch]$rawoutput
            
    )

    Begin
    {
        

        $luri = rtnuri -uri $uri -target "attributeAssignments"
        $body = @{}
    }

    Process
    {
        #swrite-host $uri
            <#
 {
  "WsRestAttributeDefNameDeleteRequest":{
    "actAsSubjectLookup":{
      "subjectId":"GrouperSystem"
    },
    "wsAttributeDefNameLookups":[
      {
        "name":"test:testAttributeAssignDefNameToDeleteRest1_json"
      },
      {
        "name":"test:testAttributeAssignDefNameToDeleteRest2_json"
      }
    ]
  }
}             #>


$body['WsRestAssignAttributesRequest']=@{
                attributeAssignType="group";
                wsAttributeDefNameLookups=@(
                    @{
                    name=$AttributeAssignDefName;
                    uuid=""}
                    );
                    #attributeAssignValueOperation="add_value";
                    #attributeAssignValueOperation=$replacevaluetxt;
                    wsOwnerGroupLookups=@(
                        @{
                            groupName=$groupName;
                        };
                        
                    );
                    attributeAssignOperation="remove_attr"

                }
            
            
            #$body['WsRestFindAttributeDefNamesLiteRequest'] = @{scope = $scope}
            #if ($search){$body['WsRestFindGroupsRequest'] = @{wsQueryFilter = @{groupName = $groupName;queryFilterType = 'FIND_BY_GROUP_NAME_APPROXIMATE'}}}
            #else{$body['WsRestFindGroupsRequest'] = @{wsQueryFilter = @{groupName = $groupName;queryFilterType = 'FIND_BY_GROUP_NAME_EXACT'}}}
            #else{$body['WsRestFindGroupsRequest'] = @{wsQueryFilter = @{groupName = $groupName;queryFilterType = 'FIND_BY_GROUP_NAME_EXACT'}}}
        <#
        if ([string]::IsNullOrEmpty($subjectId))
        {
            $body['WsRestAssignAttributesRequest']['actAsSubjectLookup'] = @{subjectId = $subjectId};
        }
        #>
        $body = $body | ConvertTo-Json -Depth 5
        Write-Verbose -Message $body
        $response = Invoke-WebRequest -Uri $luri -Headers (rtnheader -header $header) -Method Post -Body $body -UseBasicParsing -ContentType $contentType
     
        if($rawoutput){
            return $response
        }
        else{
            $content = ($response.Content | ConvertFrom-Json)
            if($content.WsAssignAttributesResults.resultMetadata.success -eq 'T'){
                write-verbose "success"
            }
            else{
                write-warning "error?"
            }
            return $content.WsAssignAttributesResults
        }
    }
    End{}
}

    #$f= get-grouperattributeAssignments -rawout -groupname "app:csom_cloud_access:msba_6331:MSBA_6330_001_GROUP_4" -AttributeAssignDefName "app:csom_cloud_access:msba_6331:csom_ad_test" -value 123
#endregion