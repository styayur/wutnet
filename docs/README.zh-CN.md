# WUTNet 中文说明

武汉理工大学校园网轻量自动认证工具：一次配置，验证当前网络，按需登录，执行完退出。

[English README](../README.md) · [Windows 命令与恢复](WINDOWS.md) · [现场记录](FIELD_VALIDATION.md)

Windows 正式版为 v1.4.0 单文件 PowerShell 客户端；Android 为独立实验版，不能将 Windows 现场验证推广到 Android。

## 快速开始

需要 Windows 10/11、PowerShell 7.2+ Core (`pwsh.exe`) 与授权校园网账号。现场记录为 Windows 11 / PowerShell 7.6.6，不支持 Windows PowerShell 5.1。

从 [v1.4.0 Release](https://github.com/styayur/wutnet/releases/tag/v1.4.0) 下载 `whut-net.ps1` 和 `SHA256SUMS.txt`，审查脚本、核对文件名对应的完整哈希后，先执行离线帮助：

```powershell
Get-FileHash ./whut-net.ps1 -Algorithm SHA256
Get-Content ./SHA256SUMS.txt
pwsh -NoProfile -File ./whut-net.ps1 help
```

**当前观察到的 WHUT 门户使用 HTTP，密码在传输中不加密。DPAPI 只保护本地存储；网络/协议指纹不是密码学服务器认证。** 请先阅读[安全边界](../SECURITY.md)。

连接校园网后：

```powershell
./whut-net.ps1 diagnose
./whut-net.ps1 setup -Username '<学号>'
./whut-net.ps1 login
./whut-net.ps1 status
```

密码在安全提示中输入。诊断与状态不发送密码，但会联网、可能写日志和迁移旧配置，不是纯只读命令。`help` 不联网、不创建状态。没有通用 Dry Run 参数，不要默认更改系统执行策略。

## 使用与退出

`run` 按需连接，新验证网络会询问 Trust & Connect；`trust-current -Label 'WHUT-DORM'` 显式追加信任网络，`networks -Json` 查看登记。配置与追加均保留已有网络；SSID 名称不会自动授予信任。

手动登录成功后可按需运行 `install`，创建当前用户登录/网络重连时触发的 **WHUT-Net AutoLogin** 任务。默认不安装常驻服务、计划任务或快捷方式；`auto` 不提示、不自动登记新网络。

每次命令执行完退出，**没有 logout 子命令**。退出脚本、删除网络登记或卸载不会结束校园网服务端会话，请通过学校门户退出。

可先在任务计划程序停用该任务，保留密码与配置。`uninstall` 尝试删除任务后，会删除本地配置、DPAPI 密码及日志；**任务删除失败也可能返回 0**，必须另行确认任务消失。没有自动备份或撤销，重新 `setup` 可重建配置，DPAPI 密文不能当作跨账号/机器的便携备份。详见[卸载与恢复限制](WINDOWS.md#stop-automation-remove-trust-or-uninstall)。

## 已验证范围

Windows 现场记录与离线测试分别保留在[验证文档](FIELD_VALIDATION.md)。VPN/TUN 仍可能改变路由，未来门户变更或不明确的物理网络会使认证停止，不承诺所有校区永久兼容。

[Android](ANDROID.md) 提供 debug 签名测试 APK，JVM/Lint/构建通过不代表真机认证已完成。真实 WHUT 设备登录仍未验证；不同签名可能要求卸载旧包并丢失本地数据。

[协议](protocol.md) · [架构](architecture/README.md) · [MIT](../LICENSE) · [贡献与测试](../CONTRIBUTING.md) · [安全报告](../SECURITY.md)
