function Get-MFShareACL {
    [CmdletBinding()]
    param(
        # Target Path
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)] $Path,
        [Parameter(Mandatory = $false, Position = 1)] $OutputPath = "C:\Powershell\LOGS",
        [Parameter(Mandatory = $false, Position = 2)][String] $domain
    )

    begin {

        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        . $PSScriptRoot\Get-LocalGroup.ps1

        $Script:userSID = ''
        $Script:user = ''
        $domains = @($domain.split(',')) #Insert AD Domain name to split from usernames in here.

        if (!(Get-PSDrive "P" -ErrorAction SilentlyContinue)) {
            Remove-PSDrive "P"
            New-PSDrive -Name "P" -PSProvider FileSystem -Root $Path
        } else {
            New-PSDrive -Name "P" -PSProvider FileSystem -Root $Path
        }

        Write-Host "Gathering Folders from $Path..."
  
        $date = Get-Date -Format yyyMMddhhmmss
        $parentFolder = Get-Item -Path P: -ErrorAction SilentlyContinue -ErrorVariable err
        $childFolders = Get-ChildItem -Path P: -Directory -Recurse -ErrorAction SilentlyContinue -ErrorVariable err
        $folderName = [System.IO.Path]::GetFileName($Path)
        Write-Host "Total folders to scan:" ($parentFolder.Count + $childFolders.Count)
  
        foreach ($errorRecord in $err) {
            if ($errorRecord.Exception -is [System.IO.PathTooLongException]) {
                $message = "Path too long in directory '$($errorRecord.TargetObject)'."
                Write-Warning $message
                Out-File -InputObject $message -FilePath C:\Powershell\LOGS\$folderName-$date-Errors.txt -Append
            }
            elseif ($errorRecord.Exception -is [System.UnauthorizedAccessException]) {
                $message = "Access to path '$($errorRecord.TargetObject)' denied."
                Write-Warning $message
                Out-File -InputObject $message -FilePath C:\Powershell\LOGS\$folderName-$date-Errors.txt -Append
            }
            elseif ($errorRecord.Exception -is [System.IO.DirectoryNotFoundException]) {
                $message = "Could not find: '$($errorRecord.TargetObject)'. Path may be too long (Length:" + ($errorRecord.TargetObject).length + ")."
                Write-Warning $message
                Out-File -InputObject $message -FilePath C:\Powershell\LOGS\$folderName-$date-Errors.txt -Append
            }
            else {
                $error = Write-Error -ErrorRecord $errorRecord
            }
        }

        Write-Host "Gathering Groups..."
        $serverFileCache = "C:\Powershell\LOGS\ServerGroupsCache"
        if ((Test-Path $serverFileCache)) {
            $groups = Get-LocalGroup -ComputerName $Path.Split("\")[2]
            $groups | Out-File "C:\Powershell\LOGS\ServerGroupsCache\$($Path.Split("\")[2]).txt" -Force
        }

        if (!(Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory
        }

        function Start-Processing ($folders) {
            # $i = 0
            $access = (Get-Acl -Path $f.FullName -ErrorAction -ErrorVariable procErr)
            foreach ($procErrorRecord in $procErr) {
                if ($procErrorRecord.Exception -is [System.IO.PathTooLongException]) {
                    $message = "Path too long in directory '$($procErrorRecord.TargetObject)'."
                    Write-Warning $message
                    Out-File -InputObject $message -FilePath C:\Powershell\LOGS\$folderName-$date-Errors.txt -Append
                }
                elseif ($procErrorRecord.Exception -is [System.UnauthorizedAccessException]) {
                    $message = "Access to path '$($procErrorRecord.TargetObject)' denied."
                    Write-Warning $message
                    Out-File -InputObject $message -FilePath C:\Powershell\LOGS\$folderName-$date-Errors.txt -Append
                }
                elseif ($procErrorRecord.Exception -is [System.IO.DirectoryNotFoundException]) {
                    $message = "Could not find: '$($procErrorRecord.TargetObject)'. Path may be too long (Length:" + ($procErrorRecord.TargetObject).length + ")."
                    Write-Warning $message
                    Out-File -InputObject $message -FilePath C:\Powershell\LOGS\$folderName-$date-Errors.txt -Append
                }
                else {
                    $error = Write-Error -ErrorRecord $errorRecord
                }
            }
            foreach ($u in $access.Access) {
                Write-Verbose "Identity Reference: $($u.IdentityReference.Value)"
                if (($u.IdentityReference.Value).contains($domains)) {
                    try {
                        [string]$uIdent = $u.IdentityReference
                        $displayName = Get-ADUser $uIdent.Split("\")[1] -Properties DisplayName, Name | Select-Object DisplayName, Name
                        $user = "$($displayName.DisplayName) ($($displayName.Name))"
                        $userType = "User"
                    }
                    catch {
                        $user = $u.IdentityReference
                        $userType = "Group"
                    }

                }
                elseif (($u.IdentityReference.Value).contains("S-*")) {
                    # Figure out a way to use the Get-LocalGroups function here to convert local group SIDs to group names. 
                    # Only required if folder permissions are set via local groups with domain groups as members.
                    foreach ($g in $groups) {
                        if ($g.SID -like $u.IdentityReference) {
                            $userSID = $g.Name
              
                        }
                        else {
                            $userSID = $u.IndentityReference
                        }
                    }
                    $user = $userSID
                    $userType = "Group"
                }
                else {
                    $user = "$($u.IdentityReference) (Else case)"
                }

                $output = [ordered]@{
                    FullName         = $f.FullName
                    Directory        = $f.Name
                    User             = $user
                    UserType         = $userType
                    Access           = $u.FileSystemRights
                    AccessType       = $u.AccessControlType
                    Inherited        = $u.IsInherited
                    InheritanceFlags = $u.InheritanceFlags
                }

                New-Object psobject -Property $output | Export-Csv $OutputPath\$folderName-$date.csv -Append -NoTypeInformation

            }
            # $i++
            # Write-Progress -activity "Processing Folders..." -status "Processed: $i of $($access.count)" -PercentComplete (($i / $access.count) * 100)
        }
    }

    process {

        Write-Host "Processing Folders..."

        foreach ($f in $parentFolder) {
            Start-Processing ($f)
        }

        foreach ($f in $childFolders) {
            Start-Processing ($f)
        }
    }

    end {
        $stopWatch.Stop()
        Write-Output "Script completed in: $($stopWatch.Elapsed.Hours):$($stopWatch.Elapsed.Minutes):$($stopWatch.Elapsed.Seconds)"
    }
}
