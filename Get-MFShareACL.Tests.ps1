$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
. "$here${directorySeparatorChar}$sut"

Describe "Get-MFShareACL" {
    It "gets share ACLs" {
        Get-MFShareACL | Should Be ""
    }
}
