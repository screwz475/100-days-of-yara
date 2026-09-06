rule AmethystStealer
{
  meta:
    date = "2026-09-06"
    description = "Detects AmethystStealer of the SapphireStealer family"
    reference = ""
      
  strings:
    $path_1 = "%AppData%\\Telegram Desktop\\tdata" ascii wide
    $path_2 = "%UserProfile%\/Downloads\/Telegram Desktop" ascii wide
    $task = "MicrosoftEdgeUpdateTaskMachineCore" ascii wide
  
  condition:
    $task and any of ($path_*)    
}
