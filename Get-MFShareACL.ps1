function Get-MFShareACL {
  [CmdletBinding()]
  param(
    # Target Path
    [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,Position = 0)] $Path,
    [Parameter(Mandatory = $false)] $OutputPath = "C:\Powershell\LOGS"
  )

  begin {

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    . $PSScriptRoot\Get-LocalGroup.ps1

    $Script:userSID = ''
    $Script:user = ''
    $domain = 'BAT' #Insert AD Domain name to split from usernames in here.

    Write-Host "Gathering Folders from $Path..."

    $date = Get-Date -Format yyyMMddhhmmss
    $parentFolder = Get-Item -Path $Path -ErrorAction SilentlyContinue -ErrorVariable err
    $childFolders = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue -ErrorVariable err
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
    $groups = Get-LocalGroup -ComputerName $Path.Split("\")[2]

    if (!(Test-Path $OutputPath)) {
      New-Item -Path $OutputPath -ItemType Directory
    }

  }

  process {

    Write-Host "Processing Folders..."
    function Process-Folders($folders) {
      $access = (Get-Acl -Path $f.FullName)

      foreach ($u in $access.Access) {

        if ($u.IdentityReference -like "$domain") {
          try {
            [string]$uIdent = $u.IdentityReference
            $displayName = Get-ADUser $uIdent.Split("\")[1] -Properties DisplayName | Select-Object DisplayName
            $user = "$($displayName.DisplayName) ($MUDID)"
          }
          catch {
            $user = "$($u.IdentityReference) (User not found)"
          }

        }
        elseif ($u.IdentityReference -like "S-*") {
          # Figure out a way to use the Get-LocalGroups function here to convert local group SIDs to group names.
          foreach ($g in $groups) {
            if ($g.SID -like $u.IdentityReference) {
              $userSID = $g.Name

            }
            else {
              $userSID = $u.IndentityReference
            }
          }
          $user = $userSID
        }
        else {
          $user = $u.IdentityReference
        }

        $output = [ordered]@{
          FullName = $f.FullName
          Directory = $f.Name
          User = $user
          Access = $u.FileSystemRights
          AccessType = $u.AccessControlType
          Inherited = $u.IsInherited
          InheritanceFlags = $u.InheritanceFlags
        }

        New-Object psobject -Property $output | Export-Csv $OutputPath\$folderName-$date.csv -Append -NoTypeInformation

      }

    }

    foreach ($f in $parentFolder) {
      Process-Folders($f)
    }

    foreach ($f in $childFolders) {
      Process-Folders($f)
    }
  }

  end {
    $stopWatch.Stop()
    Write-Output "Script completed in: $($stopWatch.Elapsed.Hours) : $($stopWatch.Elapsed.Minutes) : $($stopWatch.Elapsed.Seconds)"
  }

}

Get-MFShareACL
