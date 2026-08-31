@echo off
rem Wrapper to run WSL Suricata from Windows CMD, converting Windows paths to WSL paths.
for /f "tokens=*" %%i in ('wsl wslpath -u "%~2"') do set WSL_PCAP=%%i
for /f "tokens=*" %%i in ('wsl wslpath -u "%~4"') do set WSL_LOG=%%i
wsl suricata -r "%WSL_PCAP%" -l "%WSL_LOG%" -q
