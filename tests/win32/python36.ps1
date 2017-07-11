if ((Get-Command "git.exe" -ErrorAction SilentlyContinue) -eq $null) 
{ 
   Write-Host "Unable to find git.exe in your PATH"
   exit 1
}

function Get-ScriptDirectory
{
  $Invocation = (Get-Variable MyInvocation -Scope 1).Value
  Split-Path $Invocation.MyCommand.Path
}

$ScriptDir = Get-ScriptDirectory
cd $env:TEMP
if (-not (Test-Path "cpython")) 
{ 
    Write-Host "checking out cpython to $env:TEMP\cpython"
    git clone -q --branch=3.6 https://github.com/python/cpython
} else {
    Write-Host "cpython already checked out to $env:TEMP\cpython"
}

cd $ScriptDir