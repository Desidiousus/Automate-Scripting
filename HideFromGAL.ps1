##########################This will prompt you for a single AD username, and update that object's attributes to hide it from the GAL
Import-Module ActiveDirectory 
#If you dont know where the AD location is, run DIR after you run ">Set-Location AD:" to see a list of possible distinguished names.
#Set-Location AD:
#DIR
#Then type the DistinguishedName and press enter. Example:"DC=Contoso,DC=com"
#If you know the DistinguishedName enter it as shown below.
Set-Location "DC=SafirRosetti,DC=local"

$SOMEUSER = Read-Host -Prompt 'What is your username?'
######This will set the supplied AD user object's attributes to the email from the GAL 
Set-adUser $SOMEUSER -REPLACE @{msExchHideFromAddressLists="TRUE"} -Verbose
Set-adUser $SOMEUSER -Clear showInAddressbook -Verbose
Set-ADUser $SOMEUSER -Replace @{MailNickName = "$SOMEUSER"} -Verbose

##########################Set all user objects' attributes within an OU to be hidden from the GAL

#Prompts you for OU. Expected input is 'OU=FirstLevelOU' or 'OU=ParentOU,OU=ChildOU' (dont include quotes)
$SOMEOU= Read-Host -Prompt "What OU should we check? `nFor sub-directory OU:`nOU=ParentOU,OU=ChildOU`nFor top-level OU:`nOU=SingleOU`n"
Get-ADUser -SearchBase "$SOMEOU,DC=SafirRosetti,DC=local" -Filter * | Set-adUser -REPLACE @{msExchHideFromAddressLists="TRUE"} -Verbose
Get-ADUser -SearchBase "$SOMEOU,DC=SafirRosetti,DC=local" -Filter *| Set-adUser -Clear showInAddressbook -Verbose
##Setting MailNickName is tricky.
Get-ADUser -Filter * -SearchScope Subtree -SearchBase "$SOMEOU,DC=SafirRosetti,DC=local" |  ForEach-Object {Set-ADUser -Identity $_ -Replace @{mailNickname=$_.samaccountname}}

##Get a list of all users in ANY OU that contains the word "disabled" (table)
Get-ADOrganizationalUnit -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} | Format-Table Name, DistinguishedName -A 
##Get a list of all users in all FIRST-LEVEL OUs that contains the word "disabled" (table)
Get-ADOrganizationalUnit -SearchScope OneLevel -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} | Format-Table Name, DistinguishedName -A 

##Export Name, msExchHideFromAddressLists, mailNickname, DistinguishedName of users in "*Disabled*" OU where msExchHideFromAddressLists -eq TRUE
Get-ADOrganizationalUnit -Filter 'Name -like "*Disabled*"' | ForEach-Object {Get-ADUser -SearchScope Subtree -SearchBase $_.distinguishedname -Filter * -Properties * | Where msExchHideFromAddressLists -eq $true } | Select Name,msExchHideFromAddressLists,mailNickname,DistinguishedName |  Export-Csv -Path C:\Users\witadmin\Documents\FilesWmiData.csv -NoTypeInformation
##Export Name, msExchHideFromAddressLists, mailNickname, DistinguishedName of users in "*Disabled*" OU where msExchHideFromAddressLists -eq FALSE
Get-ADOrganizationalUnit -Filter 'Name -like "*Disabled*"' | ForEach-Object {Get-ADUser -SearchScope Subtree -SearchBase $_.distinguishedname -Filter * -Properties * | Where msExchHideFromAddressLists -eq $false } | Select Name,msExchHideFromAddressLists,mailNickname,DistinguishedName |  Export-Csv -Path C:\Users\witadmin\Documents\FilesWmiData.csv -NoTypeInformation

##########################Set all user objects' attributes within an OU to be hidden from the GAL
##Setting all three HideFromGAL attributes for all adUser objects within First-Level OUs containing "*Disabled*" 
Get-ADOrganizationalUnit -SearchScope OneLevel -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} |ForEach-Object {Set-ADUser -Identity $_ -Replace @{mailNickname=$_.samaccountname} -Verbose}
Get-ADOrganizationalUnit -SearchScope OneLevel -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} |ForEach-Object {SetSet-adUser -REPLACE @{msExchHideFromAddressLists="TRUE"} -Verbose}
Get-ADOrganizationalUnit -SearchScope OneLevel -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} |ForEach-Object {SetSet-adUser -Clear showInAddressbook -Verbose}
##Setting all three HideFromGAL attributes for all adUser objects within OUs containing "*Disabled*" 
Get-ADOrganizationalUnit -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} |ForEach-Object {Set-ADUser -Identity $_ -Replace @{mailNickname=$_.samaccountname}}
Get-ADOrganizationalUnit -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} |ForEach-Object {SetSet-adUser -REPLACE @{msExchHideFromAddressLists="TRUE"} -Verbose}
Get-ADOrganizationalUnit -Filter 'Name -like "*Disabled*"' |ForEach-Object {Get-ADUser -Filter * -SearchScope Subtree -SearchBase $_.distinguishedname} |ForEach-Object {SetSet-adUser -Clear showInAddressbook -Verbose}
