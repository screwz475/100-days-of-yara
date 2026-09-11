rule Win32_keypass
{
  meta:
    date = "2026-09-12"
    description = "Detects win32_keypass"
    reference = "https://github.com/ytisf/theZoo/tree/master/malware/Binaries/Win32.KeyPass"
      
  strings:
    $s1 = "IsolationAware function" ascii wide
    $s2 = "G:\Doc\My work (C++)\_New 2018\Encryption" ascii wide
    $s3 = ".KEYPASS"
    $s4 = /.*\.ua.*/
  
  condition:
    all of them    
}
