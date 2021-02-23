# PECheck
Check Windows PE file protection, including SAFESEH, ASLR, DEP, GS, CFG, Signatrue.
<p align="center">
  <a title="'Build' workflow Status" href="https://github.com/CynricXu/PECheck/actions?query=workflow/MSBuild"><img alt="'Build' workflow Status" src="https://img.shields.io/github/workflow/status/CynricXu/PECheck/MSBuild?longCache=true&style=for-the-badge&label=Build&logoColor=fff&logo=GitHub%20Actions"></a>
</p>

## Usege:
         .\PECheck.exe [options] path
         options:
            -f,--file
            -d,--directory
            -h,--help

## Example:
         .\PECheck.exe "C:\\Windows\\notepad.exe"
         .\PECheck.exe -f "C:\\Windows\\notepad.exe"
         .\PECheck.exe "C:\\Windows\\System32"
         .\PECheck.exe -d "C:\\Windows\\System32"

## Output:
```
.\PECheck.exe -f ".\PECheck.exe"

    File: .\PECheck.exe
           │
           ├ SAFESEH:      Yes
           ├ DEP:          Yes
           ├ ASLR:         Yes
           ├ GS:           Yes
           ├ CFG:          No
           └ Signatrue:    No

```
