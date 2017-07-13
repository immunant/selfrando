# Check that $executable is in $env:PATH
function Have-Executable($executable)
{  
    if ((Get-Command $executable -ErrorAction SilentlyContinue) -eq $null) 
    { 
    Write-Host "Unable to find $executable in your PATH"
    exit 1
    }
}

Have-Executable("git.exe")
Have-Executable("python.exe")

function Get-ScriptDirectory
{
  $Invocation = (Get-Variable MyInvocation -Scope 1).Value
  Split-Path $Invocation.MyCommand.Path
}

$ScriptDir = Get-ScriptDirectory
$SelfrandoHome = split-path -parent (split-path -parent $ScriptDir)
# Sanity check $selfrandoHome
if (-not (Test-Path (Join-Path -Path $SelfrandoHome -ChildPath "LICENSE")))
{ 
   Write-Host 'Unable to find $selfrandoHome\LICENSE'
   exit 1
}

cd $env:TEMP
if (-not (Test-Path "cpython")) 
{ 
    Write-Host "checking out cpython to $env:TEMP\cpython"
    git clone -q --branch=3.6 https://github.com/python/cpython
} else {
    Write-Host "cpython already checked out to $env:TEMP\cpython"
}
cd "$env:TEMP\cpython\PCBuild"

python.exe "$SelfrandoHome\scripts\update_vcxproj.py" --inplace -i python.vcxproj
python.exe "$SelfrandoHome\scripts\update_vcxproj.py" --inplace -i pythoncore.vcxproj
python.exe "$SelfrandoHome\scripts\update_vcxproj.py" --inplace -i python3dll.vcxproj

# show the contents of rewritten pythoncore.vcxproj
git --no-pager diff pythoncore.vcxproj

# build python for Windows. -e fetches exernals as needed.
.\build.bat -e

# check that the python binaries contains a .txtrp section
if ((Get-Command "dumpbin.exe" -ErrorAction SilentlyContinue))
{ 
    dumpbin /section:.txtrp win32\python.exe
    dumpbin /section:.txtrp win32\python3.dll
} else {
    Write-Host "Unable to find dumpbin.exe in your PATH; not checking for trap info."
}

# run python testsuite. -q means quick (single) run.
.\rt.bat -q  

cd $ScriptDir