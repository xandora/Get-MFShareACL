function Get-GSKShareACL {
    [CmdletBinding()]
    Param(
        # Target Path
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)] $Path,
        [Parameter(Mandatory = $false)]                                                   $OutputPath = "C:\Powershell\LOGS"
    )

    Begin {

        . C:\Powershell\Get-LocalGroup.ps1

        $Script:userSID = ''
        $Script:user = ''


        Write-Host "Gathering Folders..."

        $date = get-date -Format yyyMMddhhmmss
        $folders = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue -ErrorVariable err
        $folderName = [System.IO.Path]::GetFileName($Path)

        foreach ($errorRecord in $err) {
            if ($errorRecord.Exception -is [System.IO.PathTooLongException]) {
                Write-Warning "Path too long in directory '$($errorRecord.TargetObject)'."
            }
            else {
                Write-Error -ErrorRecord $errorRecord
            }
        }
        
        Write-Host "Gathering Groups..."
        $groups = Get-LocalGroup -Computername $Path.Split("\")[2]

        # WRITE A TEST TO CHECK THE $OUTPUTPATH FOLDER ACTUALLY EXISTS. PROMPT FOR CREATION IF IT DOES NOT.

    }

    Process {


        Write-Host "Processing Folders..."
        foreach ($folder in $folders) {
            $access = (get-acl -Path $folder.FullName)

            foreach ($u in $access.Access) {

                if ($u.IdentityReference -like "WMSERVICE*") {
                    Try {
                        [String]$uIdent = $u.IdentityReference
                        $displayName = get-aduser $uIdent.split("\")[1] -Properties DisplayName | Select-Object DisplayName
                        $user = "$($displayName.DisplayName) ($MUDID)"
                    }
                    Catch {
                        $user = "$($u.IdentityReference) (User not found)"
                    }

                }
                elseif ($u.IdentityReference -like "S-*") {
                    #Figure out a way to use the Get-LocalGroups function here to convert local group SIDs to group names.
                    write-host "SID"
                    foreach ($g in $groups) {
                        if ($g.SID -like $u.IdentityReference) {
                            Write-Host $u.IdentityReference
                            Write-Host $g.SID
                            Write-Host $g.Name
                            $userSID = $g.Name

                        }
                        else {
                            $userSID = $u.IndentityReference
                        }
                    }
                    $user = $userSID
                    Write-Host "User: $user"
                }
                else {
                    $user = $u.IdentityReference
                }

                $output = [ordered]@{
                    FullName         = $folder.FullName
                    Directory        = $folder.Name
                    User             = $user
                    AccessType       = $u.AccessControlType
                    Inherited        = $u.IsInherited
                    InheritanceFlags = $u.InheritanceFlags
                }

                New-Object psobject -property $output | Export-Csv $OutputPath\$folderName-$date.csv -Append -NoTypeInformation
                #$results = @(New-Object psobject -property $output)

            }

        }

    }

}

Measure-Command {Get-GSKShareACL}