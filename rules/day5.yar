rule QuasarRAT
{
  meta:
    date = "2026-09-06"
    description = "Detects QuasarRAT aka CinaRAT"
      
  strings:
    $reg_path = "Software\Microsoft\Windows\CurrentVersion\Run" ascii wide 
    $bat_1 = "echo DONT CLOSE THIS WINDOW!\"" ascii wide
    $wmi_1 = "SELECT * FROM Win32_BIOS" ascii wide
    $wmi_2 = "SELECT * FROM Win32_BaseBoard" ascii wide
  condition:
    any of ($wmi_*) and $reg_path and $bat_1    
}
