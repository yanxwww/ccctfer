# ccctfer

一个基于 Docker 的 CTF 自动化执行框架：
- 容器内启动 `python_terminal_mcp`（MCP 服务）
- 使用 `run_task.py` 生成任务工作区并调用 `claude` 执行主流程
- 通过受限工具集（`Task/Read/Grep/Glob` + `mcp__sandbox__*`）完成 observation/exploitation 流程
- 默认通过 challenge MCP 为 main agent 接入比赛平台工具；如需关闭，显式传入 `--disable-challenge-mcp`

## 项目结构

```text
ccctfer/
├── Dockerfile
├── requirements.txt
├── run_task.py
├── app/
│   └── python_terminal_mcp.py
├── .claude/
└── workspace/
```

## 前置要求

- macOS / Linux（已安装 Docker）
- Python 3.10+
- 本机可执行 `docker` 命令
- 可用的 Claude 运行环境（容器内会调用 `claude`）
- 在 `.env` 或当前 shell 中提供 Anthropic 相关配置

## 环境变量

`run_task.py` 会优先读取仓库根目录的 `.env`，并允许被当前 shell 同名变量覆盖。

### 必填

- `CHALLENGE_ENTRYPOINT`：目标入口（可逗号分隔多个）

### 常用可选

- `SERVER_HOST`
- `CHALLENGE_CODE`
- `CHALLENGE_TITLE`
- `CHALLENGE_DESCRIPTION`
- `CHALLENGE_HINT`
- `AGENT_TOKEN`
- `ANTHROPIC_BASE_URL`
- `ANTHROPIC_AUTH_TOKEN`
- `ANTHROPIC_MODEL`

### 运行参数可选（环境变量）

- `IMAGE_NAME`（默认 `ccctfer-mcp:latest`）
- `RUN_TIMEOUT_SECONDS`（默认 `7200`）
- `MCP_READY_TIMEOUT_SECONDS`（默认 `60`）
- `MCP_POLL_INTERVAL_SECONDS`（默认 `1`）
- `DEBUG_MCP_PORT`（不设置则不映射）
- `DOCKER_PLATFORM`（例如 `linux/amd64`）

## 快速开始

### 1) 构建镜像

```bash
docker build -t ccctfer-mcp:latest .
```

### 2) 准备 `.env`

```bash
CHALLENGE_ENTRYPOINT=http://127.0.0.1:8080
SERVER_HOST=127.0.0.1:8080
AGENT_TOKEN=your-agent-token
CHALLENGE_CODE=demo
CHALLENGE_TITLE=Demo CTF
CHALLENGE_DESCRIPTION=Demo description
CHALLENGE_HINT=Demo hint

ANTHROPIC_BASE_URL=https://your-base-url
ANTHROPIC_AUTH_TOKEN=your-token
ANTHROPIC_MODEL=your-model
```

### 3) 执行任务

```bash
python3 run_task.py
```

默认会给 main agent 开启 `submit_flag` / `view_hint` / `stop_challenge` 对应的比赛平台 MCP 集成，因此需要确保 `.env` 或当前 shell 中同时存在：

- `SERVER_HOST`：比赛平台主机或其 `/api`、`/mcp` 地址
- `AGENT_TOKEN`
- `CHALLENGE_CODE`

如果当前不是在比赛环境，或者暂时不希望接入比赛平台 MCP，可以显式关闭：

```bash
python3 run_task.py --disable-challenge-mcp
```

也可以指定参数：

```bash
python3 run_task.py \
	--image ccctfer-mcp:latest \
	--workspace-root workspace \
	--timeout-seconds 7200 \
	--ready-timeout-seconds 60
```

## 运行机制（简版）

1. `run_task.py` 创建任务目录：`workspace/<timestamp>-<slug>/`
2. 写入输入与目录骨架（`.inputs/`、`reports/`、`.artifacts/`、`.results/`）
3. 将任务目录挂载到容器 `/home/kali/workspace`
4. 容器内启动 `python_terminal_mcp.py`（监听 `0.0.0.0:8000`）
5. 等待 `http://127.0.0.1:8000/mcp` 就绪后执行 `claude`
6. 任务结束后归档最小产物并停止容器

## 任务产物目录

每次运行会在 `workspace/` 下生成独立目录，例如：

```text
workspace/0411-120000-demo/
├── .inputs/
│   └── challenge.json
├── reports/
│   ├── observation_report.json
│   └── exploitation/
│       └── exploitation_report.json (或 exploitation_*.json)
├── .artifacts/
│   ├── observation/
│   └── exploitation/
├── .results/
│   ├── flag.txt
│   ├── final_report.md
│   ├── blocker_report.md
│   └── claude_output.txt
├── runtime_v2/
├── .claude/
└── token_usage.txt
```

## MCP 服务说明

- 服务地址：`http://127.0.0.1:8000/mcp`（容器内）
- 默认端口：`8000`
- `run_task.py` 会生成并使用：`/home/kali/.claude/mcp.json`
- 默认包含本地 `sandbox` MCP 与远程 `platform` MCP；只有显式传入 `--disable-challenge-mcp` 时，才会只保留本地 `sandbox` MCP
- 启动命令来自 `Dockerfile` 的 `CMD`，实际进程为：
	- `/home/kali/python-terminal-mcp/.venv/bin/python /home/kali/python-terminal-mcp/app/python_terminal_mcp.py ...`

## `.results` 说明

- `.results/` 主要放规范结果产物，不要求每次都必须有 `final_report.md` 或 `blocker_report.md`
- 若 agent 明确完成最终落盘，会写入 `flag.txt`、`final_report.md` 或 `blocker_report.md`
- 无论是否生成强制总结，`run_task.py` 都会保存本次 Claude CLI 的输出到 `.results/claude_output.txt`，可作为任务结束时的自然总结与审计补充

## 常见问题

### 1) `Missing required environment variable: CHALLENGE_ENTRYPOINT`

在 `.env` 或当前 shell 设置 `CHALLENGE_ENTRYPOINT`。

### 2) `Docker image 'xxx' was not found`

先构建镜像，或在 `--image` 指向正确镜像名。

### 3) MCP readiness 超时

- 检查容器日志：

```bash
docker logs <container_name>
```

- 适当增大 `MCP_READY_TIMEOUT_SECONDS`。

### 4) Claude 执行超时

- 增大 `RUN_TIMEOUT_SECONDS` 或 `--timeout-seconds`
- 检查目标环境可达性与认证信息

## 安全提示

- 仅在授权场景下使用
- 不要将真实密钥提交到仓库
- 建议将 `.env` 保持在 `.gitignore` 中
