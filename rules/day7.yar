rule W32_swen
{
  meta:
    date = "2026-09-12"
    description = "Detects W32_swen"
    reference = "https://github.com/ytisf/theZoo/tree/master/malware/Binaries/W32.Swen"
      
  strings:
    $s1 = "%s\swen1.dat" ascii wide
    $s2 = "%s\swen0.dat" ascii wide
    $path1 = "Software\Microsoft\Windows\CurrentVersion\Policies\System" ascii wide
    $html_s1 = "<BR>I'm afraid =" ascii wide
    $html_s2 = "<BR>I'm sorry =" ascii wide
  condition:
    uint16(0) == 0x5A4D and all of them
}
