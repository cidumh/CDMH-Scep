# SCEP Server (Python)

基于 [micromdm/scep](https://github.com/micromdm/scep)（社区常称 NanoSCEP）服务端思路，使用 Python 实现的 **SCEP（Simple Certificate Enrollment Protocol）** 证书注册服务，适用于 **Apple MDM** 设备证书下发场景。

本项目已通过 Apple MDM 注册测试，可在任何能运行 Python 的系统上使用（Linux、Windows、macOS 等）。

---

## 功能特性

- 符合 RFC 8894 SCEP 协议（HTTP + CMS/PKCS#7）
- 支持 `GetCACaps`、`GetCACert`、`PKIOperation`（PKCSReq 证书申请）
- 首次启动自动生成本地 CA 根证书（存储于 `depot/`）
- 支持 SCEP 挑战码（Challenge Password）校验
- 兼容 [micromdm/scep](https://github.com/micromdm/scep) 创建的加密 `ca.key`（默认空密码）
- 默认监听 `9001` 端口，SCEP 路径为 `/scep`

---

## 环境要求

| 项目 | 要求 |
|------|------|
| Python | 3.10 及以上 |
| 操作系统 | 支持 Python 的任意系统 |
| 网络 | MDM 客户端需能访问 SCEP 服务地址 |

---

## 快速开始

### 1. 安装依赖

```bash
python3 -m pip install -r requirements.txt --break-system-packages --ignore-installed
```

> Windows 可省略 `--break-system-packages`，使用：
>
> ```powershell
> pip install -r requirements.txt
> ```

### 2. 启动服务

```bash
python3 -m scep_server --port 9001 --challenge 123456 --cert-validity 365 --ca-cn "CDMH SCEP" --ca-o "瓷都名汇" --ca-c CN
```

启动成功后，SCEP 地址为：

```
http://<服务器IP>:9001/scep
```

健康检查：

```
http://<服务器IP>:9001/health
```

### 3. MDM 配置示例

在 Apple MDM 的 SCEP Payload 中填写：

| 配置项 | 示例值 |
|--------|--------|
| URL | `https://your-domain.com/scep`（生产环境建议 HTTPS + 反代） |
| Challenge | `123456`（与 `--challenge` 一致） |
| Name | 自定义，如 `CDMH SCEP` |

---

## 启动参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--port` | `9001` | SCEP 服务监听端口 |
| `--host` | `0.0.0.0` | 监听地址 |
| `--depot` | `depot` | CA 证书与私钥存储目录 |
| `--challenge` | 无 | SCEP 注册挑战码；客户端申请证书时必须携带 |
| `--cert-validity` | `365` | 签发给客户端证书的有效期（天） |
| `--ca-cn` | `SCEP CA` | CA 证书通用名称（CN），**仅首次创建 CA 时生效** |
| `--ca-o` | `scep-ca` | CA 证书组织名称（O），**仅首次创建 CA 时生效** |
| `--ca-c` | `CN` | CA 证书国家代码（C），**仅首次创建 CA 时生效** |
| `--capass` | 自动 | CA 私钥 `ca.key` 解密密码；使用 micromdm/scep 默认空密码时可省略 |
| `--debug` | 关闭 | 开启调试日志 |

### 参数示例

```bash
python3 -m scep_server \
  --port 9001 \
  --challenge 123456 \
  --cert-validity 365 \
  --ca-cn "CDMH SCEP" \
  --ca-o "瓷都名汇" \
  --ca-c CN
```

### 核心作用

1. **自动生成自签名 CA 根证书**（首次运行，写入 `depot/ca.pem`、`depot/ca.key`）
2. **监听指定端口提供 SCEP 服务**
3. **校验挑战码**：客户端必须携带与 `--challenge` 一致的密码才能申请证书

---

## API 接口说明

服务默认基址：

```
http://<host>:<port>
```

示例：`http://127.0.0.1:9001`

### 接口总览

| 路径 | 方法 | 说明 | 状态 |
|------|------|------|------|
| `/scep?operation=GetCACaps` | GET | 获取 CA 能力列表 | ✅ 已实现 |
| `/scep?operation=GetCACert` | GET | 获取 CA 根证书 | ✅ 已实现 |
| `/scep?operation=PKIOperation` | GET / POST | 证书注册（PKCSReq） | ✅ 已实现 |
| `/scep?operation=GetNextCACert` | GET | 获取下一级 CA 证书 | ❌ 未实现（501） |
| `/health` | GET | 服务健康检查 | ✅ 已实现 |

> SCEP 标准接口均通过 **`/scep`** 路径访问，通过 Query 参数 **`operation`** 区分操作类型，与 [micromdm/scep](https://github.com/micromdm/scep/tree/main/server) 保持一致。

---

### 1. 健康检查

检测服务是否正常运行，可用于负载均衡或监控探活。

| 项目 | 说明 |
|------|------|
| **URL** | `/health` |
| **方法** | `GET` |
| **请求参数** | 无 |
| **成功响应** | `200 OK` |
| **Content-Type** | `application/json` |

**响应示例：**

```json
{
  "status": "ok"
}
```

**请求示例：**

```bash
curl http://127.0.0.1:9001/health
```

---

### 2. GetCACaps — 获取 CA 能力

客户端用于探测 CA 支持的算法与能力（如是否支持 POST、AES、SHA-256 等）。

| 项目 | 说明 |
|------|------|
| **URL** | `/scep?operation=GetCACaps` |
| **方法** | `GET` |
| **请求参数** | `operation=GetCACaps` |
| **成功响应** | `200 OK` |
| **Content-Type** | `text/plain` |

**响应体（每行一项能力）：**

```
Renewal
SHA-1
SHA-256
AES
DES3
SCEPStandard
POSTPKIOperation
```

| 能力项 | 含义 |
|--------|------|
| `Renewal` | 支持证书续期请求 |
| `SHA-1` / `SHA-256` | 支持的摘要算法 |
| `AES` / `DES3` | 支持的对称加密算法 |
| `SCEPStandard` | 符合 SCEP 标准 |
| `POSTPKIOperation` | 支持 HTTP POST 方式提交 PKIOperation |

**请求示例：**

```bash
curl "http://127.0.0.1:9001/scep?operation=GetCACaps"
```

---

### 3. GetCACert — 获取 CA 证书

客户端获取 CA 根证书，用于验证 SCEP 响应及后续 TLS/证书链校验。

| 项目 | 说明 |
|------|------|
| **URL** | `/scep?operation=GetCACert` |
| **方法** | `GET` |
| **请求参数** | `operation=GetCACert`，可选 `message`（本服务忽略该参数） |
| **成功响应** | `200 OK` |
| **Content-Type** | `application/x-x509-ca-cert`（单证书） |

**响应体：** CA 根证书的 **DER** 二进制数据（非 PEM 文本）。

**请求示例：**

```bash
curl "http://127.0.0.1:9001/scep?operation=GetCACert" --output ca.der
```

---

### 4. PKIOperation — 证书注册

SCEP 核心接口，处理客户端提交的 PKCS#10 证书申请（PKCSReq），签发设备证书并返回 CertRep。

| 项目 | 说明 |
|------|------|
| **URL** | `/scep?operation=PKIOperation` |
| **方法** | `GET` 或 `POST`（**推荐 POST**） |
| **成功响应** | `200 OK` |
| **Content-Type** | `application/x-pki-message` |
| **最大报文** | 2 MB |

#### GET 方式

| 参数 | 必填 | 说明 |
|------|------|------|
| `operation` | 是 | 固定为 `PKIOperation` |
| `message` | 是 | Base64 编码的 CMS/SCEP 报文（PKCSReq） |

```bash
# message 为 Base64 编码后的 SCEP 请求体
curl "http://127.0.0.1:9001/scep?operation=PKIOperation&message=<BASE64>"
```

#### POST 方式（推荐）

| 参数 / Header | 必填 | 说明 |
|---------------|------|------|
| Query: `operation` | 是 | 固定为 `PKIOperation` |
| Body | 是 | 原始 CMS/SCEP 二进制报文 |
| `Content-Type` | 建议 | `application/octet-stream` |

```bash
curl -X POST "http://127.0.0.1:9001/scep?operation=PKIOperation" \
  --data-binary @request.bin \
  -H "Content-Type: application/octet-stream" \
  --output response.bin
```

#### 响应体

返回 **CertRep** CMS 报文（DER 二进制）：

| PKI 状态 | 说明 |
|----------|------|
| 成功 | 响应中包含加密签发的客户端证书 |
| 失败 | CMS 报文中 `pkiStatus=FAILURE`，含 `failInfo` 错误码 |

#### 业务规则

- 支持消息类型：`PKCSReq`（19）、`RenewalReq`（17）
- 若启动时设置了 `--challenge`，CSR 中必须携带相同挑战码，否则返回失败 CertRep
- 客户端证书有效期由 `--cert-validity` 控制（默认 365 天）

#### Apple MDM 典型调用顺序

```
GetCACert → GetCACaps → PKIOperation (POST)
```

---

### 5. GetNextCACert — 获取下一级 CA（未实现）

用于 CA 证书轮换场景，当前版本尚未实现。

| 项目 | 说明 |
|------|------|
| **URL** | `/scep?operation=GetNextCACert` |
| **方法** | `GET` |
| **响应** | `501 Not Implemented` |
| **响应体** | `not implemented` |

---

### HTTP 状态码

| 状态码 | 场景 |
|--------|------|
| `200` | 请求成功 |
| `404` | 未知的 `operation` 参数 |
| `500` | 服务端内部错误（如 CMS 解析失败） |
| `501` | `GetNextCACert` 尚未实现 |

---

### 错误响应

SCEP 业务失败（如挑战码错误、CSR 无效）时，`PKIOperation` 仍返回 **HTTP 200**，但在 CMS **CertRep** 报文中携带失败状态：

| failInfo | 含义 |
|----------|------|
| `0` | 不支持的算法 |
| `1` | 消息完整性校验失败 |
| `2` | 请求不被允许（如挑战码错误） |
| `3` | 时间戳无效 |
| `4` | 证书 ID 无效 |

非 SCEP 路径或未知 `operation` 返回纯文本错误，HTTP 状态码见上表。

---

## 目录结构

```
.
├── requirements.txt       # Python 依赖
├── run_server.py          # 启动脚本（可选）
├── depot/                 # CA 存储目录（运行后自动生成）
│   ├── ca.pem             # CA 根证书
│   ├── ca.key             # CA 私钥
│   ├── serial.txt         # 签发序号
│   └── issued/            # 已签发客户端证书
└── scep_server/           # 服务源码
    ├── main.py            # 入口与命令行
    ├── service.py         # SCEP 业务逻辑
    ├── transport.py       # HTTP 接口
    ├── ca.py              # CA 管理
    ├── pem_legacy.py      # micromdm/scep 加密私钥兼容
    └── cms/               # CMS/SCEP 消息处理
```

---

## 使用已有 CA（micromdm/scep）

若已用 micromdm/scep 创建 CA，可将 `ca.pem`、`ca.key` 放入 `depot/` 目录后直接启动：

```bash
# micromdm/scep 未指定 -key-password 时，默认空密码，无需 --capass
python3 -m scep_server --port 9001 --challenge 123456 --depot depot
```

若创建时指定了 `-key-password`：

```bash
python3 -m scep_server --port 9001 --challenge 123456 --capass "你的CA私钥密码"
```

> **注意**：`--ca-cn`、`--ca-o`、`--ca-c` 不会修改已有 CA，仅在新创建 CA 时生效。

---

## 生产部署

生产环境建议：

1. 使用 **systemd** 设置开机自启与进程守护（见 [Install.md](./Install.md)）
2. 使用 **Nginx** 反向代理并配置 **HTTPS**
3. 妥善备份 `depot/` 目录（含 CA 私钥）
4. Flask 内置服务器仅适合测试；高并发场景可改用 gunicorn 等 WSGI 服务器

详细安装、systemd、Nginx 配置请参阅 **[Install.md](./Install.md)**。

---

## 参考项目

- [micromdm/scep](https://github.com/micromdm/scep) — Go 语言 SCEP 服务端参考实现
- [RFC 8894](https://datatracker.ietf.org/doc/html/rfc8894) — SCEP 协议规范

---

## 致谢

本项目在开发过程中使用了 [Cursor](https://cursor.com) AI 编程工具辅助编写部分代码。
