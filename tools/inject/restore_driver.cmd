@echo off
REM ============================================================
REM 恢复相机 USB 驱动：把 libusb 换回 Windows 默认驱动
REM
REM 什么时候用：给普通模式（054C:0D99）误装了 libusb 驱动，
REM             导致资源管理器看不到相机、不能直接拷照片。
REM
REM 用法：
REM   1. 先查出你自己相机的设备实例号：
REM        powershell -c "Get-PnpDevice -PresentOnly | ? InstanceId -like '*VID_054C*' | select InstanceId"
REM      形如 USB\VID_054C&PID_0D99\xxxxxxxxxxxx
REM   2. 把下面的 DEVICE 换成你查到的那个（保留前面 USB\VID_054C&PID_0D99\ 部分）
REM   3. 以管理员身份运行本脚本
REM
REM 注意：本脚本只处理普通模式。服务模式（054C:0336）的 libusb 驱动
REM       是项目需要的，不要卸载。
REM ============================================================

setlocal

REM ▼▼▼ 改成你自己的设备实例号 ▼▼▼
set DEVICE=USB\VID_054C&PID_0D99\你的设备实例号
REM ▲▲▲ 改成你自己的设备实例号 ▲▲▲

set LOG=%~dp0..\..\logs\restore_driver.log
if not exist "%~dp0..\..\logs" mkdir "%~dp0..\..\logs"

echo ==== start %DATE% %TIME% ==== > "%LOG%"

echo [1] 先列出当前驱动，找到对应的 oemNN.inf >> "%LOG%"
pnputil /enum-drivers >> "%LOG%" 2>&1

echo [2] 移除设备 >> "%LOG%"
pnputil /remove-device "%DEVICE%" >> "%LOG%" 2>&1
if errorlevel 1 (
    echo    失败：设备实例号可能不对，或者相机没插着 >> "%LOG%"
    echo    先运行：powershell -c "Get-PnpDevice -PresentOnly | ? InstanceId -like '*VID_054C*'" >> "%LOG%"
)

echo [3] 重新扫描设备，让 Windows 装回默认驱动 >> "%LOG%"
pnputil /scan-devices >> "%LOG%" 2>&1

echo [4] 如果第 3 步没装回默认驱动，在设备管理器里手动卸载并勾选"删除驱动程序软件" >> "%LOG%"
echo ==== done %DATE% %TIME% ==== >> "%LOG%"

type "%LOG%"
echo.
echo 日志：%LOG%
