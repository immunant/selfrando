cd $env:TEMP
$GIT="$env:github_git\cmd\git.exe"
& $GIT clone -b 3.6 https://github.com/python/cpython
