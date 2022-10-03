function rtnuri{
    param(
        [string]$uri,
        [string]$target
        )
    
    write-verbose "uri:$uri $([string]::IsNullOrEmpty($uri))"
    write-verbose "target:$target $([string]::IsNullOrEmpty($target))"
    if([string]::IsNullOrEmpty($target)){
        $uriEnd = ""
    }
    else{
        $uriEnd = "/$target"
    }
    write-verbose "uriend:$uriend"
    if([string]::IsNullOrEmpty($uri)){
        if([string]::IsNullOrEmpty($auth.uri)){
            return ((Read-Host -Prompt 'Grouper URI') + $uriEnd)
        }
        else{
            return ($auth.uri + $uriEnd)
        }
    }
    else{
        return ($uri + $uriEnd)
    }
}
