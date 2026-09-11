rule Win32_infostealer_dexter
{
  meta:
    date = "2026-09-12"
    description = "Detects win32_infostealer_dexter"
    reference = "https://github.com/ytisf/theZoo/tree/master/malware/Binaries/Win32.Infostealer.Dexter"
      
  strings:
    $s1 = "(wa_~_~" ascii wide
    $s2 = /w1921813174.*/gateway\.php/ ascii wide
        
  
  condition:
    $uint16(0) == 0x5A4D and all of them
}
