PARAM ($AddAuditing = $false, $RemoveAuditing = $false, $ShowAuditing = $true)
#************************************************
# SetCertStoreAudit.ps1
# Version 1.0
# Date: 05-27-2016
# Author: Tim Springston
# Description: This script will configure security auditing, show security (permissions), 
#  or remove security auditing on all Personal aka My Store certificates for the current logged on user. The script 
#  does not configure auditing for computer aka System or Service certificates.
#************************************************

function RemoveCertAudit
	{
	#Remove audit SACL to personal cert store
	$AppDataFolder = $env:appdata
	$PersonalCertificateFolder = $AppDataFolder + "\Microsoft\SystemCertificates\My"
	$ACL = Get-Acl -Audit $PersonalCertificateFolder
	$ACE = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","FullControl","ContainerInherit, ObjectInherit","None","Success, Failure")
	$Acl.RemoveAuditRule($ACE) 
	$ACL | Set-Acl
	$Children = Get-ChildItem -Path $PersonalCertificateFolder -Recurse
	$ChildAce = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","FullControl","None","None","Success, Failure")
	foreach ($Child in $Children)
		{
		$Acl = Get-Acl -Audit $Child.FullName
		$AuditRules = $acl.GetAuditRules("true","true",[System.Security.Principal.NTAccount])
		$Acl.RemoveAuditRule($AuditRules[0])
		$Acl | Set-Acl -erroraction silentlycontinue
		}
	}

function ShowCertStorePerms
	{
	#Show audit SACL to personal cert store
	$AppDataFolder = $env:appdata
	$PersonalCertificateFolder = $AppDataFolder + "\Microsoft\SystemCertificates\My"
	$ACL = Get-Acl -Audit $PersonalCertificateFolder
	$PersonalCertificateFolder.FullName | FL
	$ACL | FL
	$Children = Get-ChildItem -Path $PersonalCertificateFolder -Recurse
	foreach ($Child in $Children)
		{
		$Acl = Get-Acl -Audit $Child.FullName
		$Child.FullName | FL
		$Acl | FL
		}
	}
function AddCertAudit
	{
	#Add audit SACL to personal cert store
	$AppDataFolder = $env:appdata
	$PersonalCertificateFolder = $AppDataFolder + "\Microsoft\SystemCertificates\My"
	$ACL = Get-Acl -Audit $PersonalCertificateFolder
	$ACE = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","FullControl","ContainerInherit, ObjectInherit","None","Success, Failure")
	$ACL | Set-Acl
	$Children = Get-ChildItem -Path $PersonalCertificateFolder -Recurse
	$ChildAce = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","FullControl","None","None","Success, Failure")
	foreach ($Child in $Children)
		{
		$Acl = Get-Acl -Audit $Child.FullName
		$Acl.AddAuditRule($ChildAce)
		$Acl | Set-Acl
		}
	}

cls
if ($AddAuditing)
	{AddCertAudit}
if ($RemoveAuditing)
	{RemoveCertAudit}
if ($ShowAuditing)
	{ShowCertStorePerms}
