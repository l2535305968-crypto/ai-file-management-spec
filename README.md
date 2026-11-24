# AI 文件管理规范 & 安全校验 API

提供通用版 [AI文件管理规范.md](./AI文件管理规范.md)（v2.1）及其配套的 **FastAPI HTTP 接口**，用于统一约束各类 AI Agent（Codex、Claude Code、ChatGPT 等）的文件读写、命名、归档与安全边界。

## 安全边界设计

1. **工作区沙箱隔离**：所有路径操作强制限制在 `AI_FM_WORKSPACE_ROOT` 范围内，阻断 `../` 路径穿越、绝对路径访问、空字节注入及符号链接逃逸。
2. **命名红线拦截**：正式交付物禁止包含 `_final`、`_最终版`、`_new`、`_v2` 等模糊副本后缀，禁止全角括号及 Windows 保留设备名。
3. **禁止物理删除**：归档接口默认复制（可选移动）至 `_archive/`，写入 `archive_index.jsonl` 并校验 SHA-256，不提供删除接口。
4. **敏感信息扫描**：内置上架前/提交前扫描接口，自动检测密钥/Token、硬编码本地绝对路径、手机号与邮箱。
5. **可选鉴权与本地绑定**：默认仅监听 `127.0.0.1`；设置环境变量 `AI_FM_API_KEY` 后，所有 `/api/v1/*` 接口强制校验 `X-API-Key` 请求头。

## 快速启动

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 启动本地服务（默认仅监听本机）
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

启动后访问交互式文档：`http://127.0.0.1:8000/docs`

## API 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 服务健康检查 |
| `GET` | `/api/v1/spec` | 获取完整《AI 文件管理规范》正文与版本 |
| `GET` | `/api/v1/prompt` | 获取可直接复制给 AI 的短指令 |
| `POST` | `/api/v1/validate/path` | 校验目标路径与文件名是否符合安全边界与命名规范 |
| `POST` | `/api/v1/archive` | 安全归档指定文件到 `_archive/` 并生成 SHA-256 索引 |
| `POST` | `/api/v1/security/scan` | 扫描工作区内的密钥、硬编码本地路径及敏感信息 |

## 运行测试

```bash
pytest -v
```
