# 安装与部署指南

本文档说明如何在 Linux 等系统上安装、运行 SCEP Server，并配置 systemd 开机自启与 Nginx 反向代理。

---

## 一、环境准备

### 1.1 系统要求

- 能运行 **Python 3.10+** 的操作系统（推荐 Linux）
- 可访问外网以下载 pip 依赖（或提前离线安装 wheel 包）

### 1.2 安装 Python（Debian / Ubuntu 示例）

```bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 --version
```

### 1.3 上传项目文件

将项目目录上传至服务器，例如：

```bash
/root/scep
```

目录内应包含 `requirements.txt`、`scep_server/` 等文件。

---

## 二、安装依赖

进入项目目录：

```bash
cd /root/scep
```

安装 Python 依赖：

```bash
python3 -m pip install -r requirements.txt --break-system-packages --ignore-installed
```

> **说明**
>
> - `--break-system-packages`：在 Debian/Ubuntu 等系统上允许 pip 安装到系统 Python 环境
> - `--ignore-installed`：忽略已安装的旧版本，确保依赖版本正确
>
> 若使用虚拟环境（推荐），可改为：
>
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt
> ```
>
> 后续启动与 systemd 中的 `ExecStart` 需指向 `venv/bin/python3`。

---

## 三、首次启动测试

```bash
cd /root/scep
python3 -m scep_server --port 9001 --challenge 123456 --cert-validity 365 --ca-cn "CDMH SCEP" --ca-o "瓷都名汇" --ca-c CN
```

看到类似输出表示启动成功：

```
INFO [scep_server.main] SCEP server listening on http://0.0.0.0:9001/scep
INFO [werkzeug] Press CTRL+C to quit
```

另开终端测试：

```bash
curl "http://127.0.0.1:9001/scep?operation=GetCACaps"
curl -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:9001/scep?operation=GetCACert"
```

确认返回 `200` 后，按 `Ctrl+C` 停止测试进程。

---

## 四、启动参数说明

| 参数 | 示例 | 说明 |
|------|------|------|
| `--port` | `9001` | SCEP 服务监听端口 |
| `--host` | `0.0.0.0` | 监听地址（默认所有网卡） |
| `--depot` | `depot` | CA 证书存储目录 |
| `--challenge` | `123456` | 注册挑战码，MDM SCEP Payload 必须一致 |
| `--cert-validity` | `365` | 签发客户端证书有效期（天） |
| `--ca-cn` | `"CDMH SCEP"` | CA 通用名称（CN），仅首次创建 CA 生效 |
| `--ca-o` | `"瓷都名汇"` | CA 组织名称（O），仅首次创建 CA 生效 |
| `--ca-c` | `CN` | CA 国家代码 |
| `--capass` | 省略 | micromdm/scep 默认空密码 CA 可省略 |
| `--debug` | — | 开启调试日志 |

### 挑战码与 CA 私钥密码的区别

| 参数 | 用途 |
|------|------|
| `--challenge` | SCEP 客户端（MDM 设备）注册时使用的挑战码 |
| `--capass` | 解密 `depot/ca.key` 的 CA 私钥密码（与 micromdm/scep 的 `-key-password` / `-capass` 对应） |

---

## 五、使用 micromdm/scep 已有 CA

若 CA 由 micromdm/scep 创建：

```bash
/root/scepserver-linux-amd64 ca -init \
  -organization "MyMDM" \
  -country "CN" \
  -common_name "MyMDM SCEP CA"
```

将生成的 `ca.pem`、`ca.key` 复制到项目的 `depot/` 目录：

```bash
cp depot/ca.pem depot/ca.key /root/scep/depot/
```

启动时**无需** `--capass`（未指定 `-key-password` 时默认为空密码）：

```bash
python3 -m scep_server --port 9001 --challenge 123456 --depot depot
```

---

## 六、systemd 后台服务（Linux 开机自启）

### 6.1 创建服务文件

```bash
sudo nano /etc/systemd/system/scep_server.service
```

写入以下内容（**请按实际路径修改 `WorkingDirectory` 和 `ExecStart`**）：

```ini
[Unit]
Description=SCEP Server Service
After=network.target

[Service]
User=root
WorkingDirectory=/root/scep
ExecStart=/usr/bin/python3 -m scep_server --port 9001 --challenge 123456 --cert-validity 365 --ca-cn "CDMH SCEP" --ca-o "瓷都名汇" --ca-c CN
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> 若使用虚拟环境，将 `ExecStart` 改为：
>
> ```ini
> ExecStart=/root/scep/venv/bin/python3 -m scep_server --port 9001 --challenge 123456 --cert-validity 365 --ca-cn "CDMH SCEP" --ca-o "瓷都名汇" --ca-c CN
> ```

### 6.2 启用并启动

```bash
sudo systemctl daemon-reload
sudo systemctl enable scep_server
sudo systemctl start scep_server
```

### 6.3 查看状态与日志

```bash
# 查看运行状态
sudo systemctl status scep_server

# 实时日志
journalctl -u scep_server -f
```

### 6.4 常用管理命令

```bash
# 停止服务
sudo systemctl stop scep_server

# 重启服务
sudo systemctl restart scep_server

# 取消开机自启
sudo systemctl disable scep_server
```

---

## 七、Nginx 反向代理

生产环境建议通过 Nginx 提供 HTTPS，并将 `/scep` 转发到本地 SCEP 服务。

### 7.1 反向代理配置

```nginx
location /scep {
    proxy_pass http://127.0.0.1:9001;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    # SCEP PKIOperation 可能携带较大 CMS 报文
    client_max_body_size 4m;
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;
}
```

> **注意**：`proxy_pass` 端口需与 `--port` 一致（示例为 `9001`）。

### 7.2 HTTPS 示例（片段）

```nginx
server {
    listen 443 ssl;
    server_name mdm.example.com;

    ssl_certificate     /etc/ssl/certs/mdm.example.com.pem;
    ssl_certificate_key /etc/ssl/private/mdm.example.com.key;

    location /scep {
        proxy_pass http://127.0.0.1:9001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        client_max_body_size 4m;
    }
}
```

MDM SCEP Payload 中的 URL 应填写：

```
https://mdm.example.com/scep
```

重载 Nginx：

```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## 八、Windows 安装（简要）

### 8.1 安装 Python

从 [python.org](https://www.python.org/downloads/) 安装 Python 3.10+，安装时勾选 “Add Python to PATH”。

### 8.2 安装依赖并启动

```powershell
cd "C:\path\to\scep"
pip install -r requirements.txt
python -m scep_server --port 9001 --challenge 123456 --cert-validity 365 --ca-cn "CDMH SCEP" --ca-o "瓷都名汇" --ca-c CN
```

> PowerShell 中**不要**使用 `--capass ""`（会被错误解析）。micromdm/scep 默认空密码 CA 直接省略 `--capass` 即可。

---

## 九、备份与安全

### 9.1 必须备份的目录

```bash
/root/scep/depot/
```

包含：

- `ca.pem` — CA 根证书
- `ca.key` — CA 私钥（极其重要）
- `serial.txt` — 签发序号
- `issued/` — 已签发证书

### 9.2 安全建议

- 限制 `depot/` 目录权限（如 `chmod 700 depot`）
- 生产环境使用 HTTPS
- 定期备份 `depot/`
- 挑战码 `--challenge` 使用足够复杂的字符串
- 不要将 `ca.key` 提交到公开代码仓库

---

## 十、常见问题

### Q1：启动报 `Password was not given but private key is encrypted`

**原因**：`ca.key` 为 micromdm/scep 加密格式，旧版代码或错误传参导致无法解密。

**解决**：

1. 省略 `--capass`（micromdm/scep 默认空密码）
2. 若创建时设置过 `-key-password`，使用 `--capass "你的密码"`
3. 确保使用最新版项目代码（含 `pem_legacy.py` 兼容模块）

### Q2：PowerShell 报 `argument --capass: expected one argument`

**原因**：PowerShell 中 `--capass ""` 会被错误解析。

**解决**：直接省略 `--capass`，或仅写 `--capass`（无后续值）。

### Q3：`--ca-cn` 修改后 CA 主题未变化

**原因**：CA 已在 `depot/` 中存在，主题参数仅首次创建时生效。

**解决**：备份后删除 `depot/` 重新启动，或使用已有 CA 文件。

### Q4：MDM 注册失败

检查项：

1. MDM SCEP URL 是否可访问（含 HTTPS 证书是否有效）
2. Challenge 是否与 `--challenge` 一致
3. 防火墙是否放行 9001 端口（或 Nginx 443 端口）
4. 查看服务日志：`journalctl -u scep_server -f`

### Q5：端口被占用

```bash
ss -tlnp | grep 9001
```

更换端口或停止占用进程后重启服务。

---

## 十一、卸载

```bash
sudo systemctl stop scep_server
sudo systemctl disable scep_server
sudo rm /etc/systemd/system/scep_server.service
sudo systemctl daemon-reload
```

按需删除项目目录：

```bash
rm -rf /root/scep
```

> 删除前请确认已备份 `depot/` 目录。
