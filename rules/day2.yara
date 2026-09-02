rule rat_c2
{
    meta:
        date = "2026-09-02"
    
    strings:
        $mutex = "85160392" ascii wide base64 xor // поиск строки, поиск строки в b64, поиск строки, зашифрованной всеми вариантами однобайтового xor
        $hash1 = "e4cec6c174d5d85002f6df6bd5852cd5" ascii wide
        $hash2 = "dbb4bfed20e761731890b117efd6158f" ascii wide
        $hash3 = "fb08a876f88542d56a648f8263aea737" ascii wide
        
    condition:
        uint16(0) == 0x5A4D 
        and
        any of ($hash*)
        and
        $mutex
}
