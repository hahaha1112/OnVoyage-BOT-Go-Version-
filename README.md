# OnVoyage Auto BOT（Go 版）

Go语言版本，实现多账号每日签到，支持代理与失效代理轮换。

**环境要求**
- Go 1.20+

**运行**
在仓库根目录执行：
```bash
go run .
```

**文件说明**
- `tokens.txt`：每行一个 JWT（必需）
- `proxy.txt`：代理列表（可选）

程序会优先读取当前目录的 `tokens.txt`/`proxy.txt`，若不存在则尝试读取上一级目录（方便你把数据文件放在外层统一管理）。

**代理格式支持**
- `host:port`（默认按 `http://` 处理）
- `http://host:port`
- `http://user:pass@host:port`
- `socks4://host:port`（user 可选）
- `socks5://host:port`（user/pass 可选）

**示例**
`tokens.example.txt`
```
eyJhbGciOi...your.jwt.token
eyJhbGciOi...your.jwt.token
```

`proxy.example.txt`
```
127.0.0.1:7897
http://user:pass@1.2.3.4:8080
socks5://user:pass@5.6.7.8:1080
```

**注意事项**
- 请勿提交真实的 `tokens.txt` / `proxy.txt`（已在 `.gitignore` 中忽略）。
- 如果 `https://api.ipify.org` 被网络策略拦截，连接检测会失败；建议切换可用网络或使用代理。
- 运行后会进入 24 小时循环等待；需要停止可直接 `Ctrl + C`。
- 终端支持真彩色 ANSI 时日志会以霓虹紫风格输出；如需关闭颜色请设置 `NO_COLOR=1`。
