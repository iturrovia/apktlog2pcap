@echo off
set PATH=%PATH%;"C:\Program Files (x86)\Java\jre7\bin"
java -cp %~dp0\apktlog2pcap.jar apktlog2pcap.Cli %*
pause
