rule MAL_SugarWraith_Loader
{
          meta:
                    author = "Greg Lesnewich"
                    description = "detect the SugarWraith loader DLL used by UNK_SweetSpector"
                    date = "2025-01-10"
                    version = "1.0"
                    hash = "b1d17ee661faa8198fa04801aeef142f09f603fc0971cde4621b32720b5c8d12"

          strings:

                    $s1 = "CreateProcess failed!" ascii wide
                    $s2 = "CreatePipe failed!" ascii wide
                    $s3 = "[LAN]%s|[OS]%s|[DISK]%.0fG|[CPU]%d*%.2fGHz|[MEM]%.1fG|[VER]%s|[CAM]%s|[LANG]%u|" ascii wide
                    $s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii wide
                    $s5 = "ngrok-skip-browser-warning" ascii wide
                    $s6 = "SecureProtocols" ascii wide
          condition:
                    4 of them
}
