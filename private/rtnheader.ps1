function rtnheader{
    param([Hashtable]$header)
    
    if([string]::IsNullOrEmpty($header)){
        return New-GrouperHeader -psCreds $auth.pscred
    }
    else{
        return $header
    }
}
