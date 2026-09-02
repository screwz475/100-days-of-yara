rule rat_stager
{
    meta:
        date = "2026-09-02"
    
    strings:
        $dropped_exe_1 = "VC_new1.exe" ascii wide
        $dropped_exe_2 = "VC_new2.exe" ascii wide
        $cmd = "/c ping" ascii wide 
    condition:
        uint16(0) == 0x5A4D 
        and
        (($dropped_exe_1 or $dropped_exe_2) and $cmd)
}
