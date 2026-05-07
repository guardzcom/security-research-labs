$ErrorActionPreference='Stop'
$pidE=[int](Get-CimInstance Win32_Process -Filter "Name='msedge.exe'"|? {$_.CommandLine -and $_.CommandLine -notmatch '--type='}|select -First 1).ProcessId
if(-not $pidE){throw "Edge not running."}
"PID: $pidE"
Add-Type -Namespace N -Name K -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);
[System.Runtime.InteropServices.DllImport("dbghelp.dll",SetLastError=true)]public static extern bool MiniDumpWriteDump(IntPtr h,uint p,IntPtr f,int t,IntPtr a,IntPtr b,IntPtr c);
'@ -ErrorAction SilentlyContinue
$h=[N.K]::OpenProcess(0x0450,$false,$pidE);if($h-eq0){throw "OpenProcess: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"}
$d="$env:TEMP\edge_$($pidE)_$(Get-Date -f HHmmss).dmp";$f=[IO.File]::Create($d)
try{if(-not[N.K]::MiniDumpWriteDump($h,$pidE,$f.SafeFileHandle.DangerousGetHandle(),0x2,0,0,0)){throw "Dump: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"}}finally{$f.Close();[void][N.K]::CloseHandle($h)}
"Dump saved: $d  ($([math]::Round((Get-Item $d).Length/1MB,1)) MB)"
