# 构建环境清单(内核端点 100% 收尾所需)

两个内核端点在本仓库的开发工作站上**源码已全量落地、但无法编译验证**,
因为该机器缺少固定工具链。要把它们推到与用户态链路同等的"已验证"
状态,需要以下两套环境(物理机或虚拟机均可)。

## Windows WDM 驱动(LayeredGuard,.sys)

| 项 | 要求 |
|---|---|
| 编译器 | Visual Studio 2010(v100 平台工具集) |
| WDK | Windows Driver Kit 7600.16385.1(装到 `C:\WinDDK\7600.16385.1`,或改 `LayeredGuard.vcxproj` 里的 `WDKDir`) |
| 目标机 | Win7 SP1 – Win11 的测试虚拟机,开启测试签名(`bcdedit /set testsigning on` 后重启) |
| 构建步骤 | `tools\CreateTestCert.cmd`(管理员,一次)→ VS2010 打开 `LayeredGuard.sln` → Win32/x64 各构建一次(PostBuild 自动 signtool 签名) |
| 部署 | 拷贝 `Release_x64\LayeredGuard.sys` + `Install.bat` 到目标机,管理员运行 |
| 验收 | `agents/win_wdm_driver/README.md` 引用的验收清单(spec §15):sc create 用任意服务名可加载、同名进程 PID 全变 4、Process 规则收缩 5 秒内恢复、netstat 在 x64 与 x86 都过滤、目录树/注册表树隐藏、5 秒热更新、关机后 .sys 仍在、sc stop 干净卸载、WinDbg `!drvobj` 显示伪装名 |

注:仓库内已完成的注册表层验证(模拟驱动键)证明 agent→沙箱→Config
合并链路正确;上表验收针对驱动本体行为。

## Linux LKM(veilcore,.ko)

| 项 | 要求 |
|---|---|
| 构建机 | 任意 x86/x86_64 Linux,装有与目标机内核匹配的 `gcc` + `make` + 内核头(` /lib/modules/$(uname -r)/build`) |
| 构建 | `cd agents/linux_lkm && make` |
| 目标机 | 测试虚拟机/容器(建议快照),内核 2.6.x–6.x |
| 加载 | `sudo insmod veilcore.ko ko_path=$(pwd)/veilcore.ko` |
| 验收 | `agents/linux_lkm/README.md` 的操作手册:insmod 后 lsmod 不可见、`kill -36 0` 可见、`veil_` 前缀文件 ls 不可见、`kill -34 <pid>` 进程从 ps/proc 消失、`kill -37 <port>` /proc/net/tcp 不含该端口、`kill -35 0` id 为 0、rmmod 后 .ko 仍在、重启后 rc.local 自动加载 |

## 用户态部分(参考)

以下已在本仓库开发机上全量验证,无需额外环境:Go 服务、NASS、
ASM agent(PLAIN/TLS 双模式)、no_std 沙箱(11 项直连测试)、
crypto 互操作(7/7)、控制台前端构建与 tauri_core cargo check。
