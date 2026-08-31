@echo off
rem Wrapper to run WSL Zeek from Windows CMD, converting Windows paths to WSL paths.
for /f "tokens=*" %%i in ('wsl wslpath -u "%~2"') do set WSL_PCAP=%%i
wsl zeek -r "%WSL_PCAP%"
