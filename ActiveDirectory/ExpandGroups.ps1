$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString)

function Expand-Groups($group) {
    # Check if the group has been expanded already
    if ($group.Properties["Member"].Count -eq 0) { return }
    
    foreach ($member in $group.Properties["Member"]) {
        $memberObj = [ADSI]("LDAP://" + $member)
        if ($memberObj.SchemaClassName -eq "Group") {
            Expand-Groups $memberObj
        } else {
            $memberObj.Properties["Name"]
        }
    }
}

$searcher = New-Object System.DirectoryServices.DirectorySearcher($objDomain)
$searcher.Filter = "(objectClass=group)"
$searcher.PropertiesToLoad.Add("member")
$searcher.PageSize = 1000

$groups = $searcher.FindAll()

foreach ($group in $groups) {
    $groupObj = $group.GetDirectoryEntry()
    Write-Host "Group: $($groupObj.Properties["Name"])"
    Expand-Groups $groupObj
}
