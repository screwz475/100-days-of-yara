rule W32_swen
{
  meta:
    date = "2026-09-12"
    description = "Detects W32_swen"
    reference = "https://github.com/ytisf/theZoo/tree/master/malware/Binaries/W32.Swen"
      
  strings:
    $s1 = "%s\swen1.dat"
    $s2 = "%s\swen0.dat"
    $path1 = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $html_s1 = "<BR>I'm afraid ="
    $html_s2 = "<BR>I'm sorry ="
  condition:
    uint16(0) == 0x5A4D and all of them
}
