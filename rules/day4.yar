rule NetMedved_dropper
{
  meta:
    date = "2026-09-04"
    description = "Detects NetMedved .lnk dropper"
    reference = "https://habr.com/ru/companies/pt/articles/1050722/"
      
  strings:
    $lnk_path = "C:\Windows\System32\notepad.exe" ascii wide nocase
    $ioc_1 = "magazine=\"https://crop.sh\"" base64wide // в команде файла содержится base64 строка закодированная в UTF-16LE. В теории base64wide такую строку декодирует
    $ioc_2 = "(gcm *vo*p*s*n).name" base64wide
  
  condition:
    all of them    
}
