# PECheck
Check Windows PE file protection.

## Usege:
         .\PECheck.exe [options] path
         options:
            -f,--file
            -d,--directory
            -h,--help

## Example:
         .\PECheck.exe "C:\\Windows\\notepad.exe"
         .\PECheck.exe -f "C:\\Windows\\notepad.exe"
         .\PECheck.exe -d "C:\\Windows\\System32"
