$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain

# Only return members of the Domain Admins group
$Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,$DistinguishedName))"

$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    Write-Host "------------------------"
}

#Note that the Filter parameter of the DirectorySearcher object has been modified to look for members of the Domain Admins group by specifying the group's distinguished name in the memberOf attribute of the filter. The decimal value for Domain Admins is 516 in the samAccountType attribute, but it's better to search for group membership using the memberOf attribute to avoid false positives.
#https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

