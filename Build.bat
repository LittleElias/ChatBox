@echo off

:: Copy precompiled icon object
copy /Y ".\ChatBox\App\Icon\Icon.o" ".\Icon.o" >nul

:: Build ChatBox with all required libraries
g++ ChatBox.cpp AES-32.c Icon.o -o ChatBox.exe ^
    -std=c++11 -O2 ^
    -static ^
    -lws2_32 -liphlpapi -lcomdlg32 -lshell32 -lcomctl32 -lgdi32 -luser32 -lmpr -ladvapi32 -lcrypt32 ^
    -mwindows

del /Q Icon.o

:: Pause to view any errors
pause

:: Launch the application
start ChatBox.exe

exit