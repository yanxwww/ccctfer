ARG FFUF_VERSION=2.1.0
ARG HTTPX_VERSION=1.9.0
ARG KATANA_VERSION=1.5.0
ARG DALFOX_VERSION=2.12.0
ARG ARJUN_VERSION=2.2.7
ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=off

# FROM issyy/ccctfer:latest
FROM issyy/xbow-kail:latest

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=kali
ARG USER_UID=1000
ARG USER_GID=1000
ARG USER_HOME=/home/${USERNAME}
ARG APP_HOME=${USER_HOME}/python-terminal-mcp
ARG WORKSPACE_DIR=${USER_HOME}/workspace
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ARG PIP_EXTRA_INDEX_URL=
ARG ARJUN_VERSION
ARG FFUF_VERSION
ARG HTTPX_VERSION
ARG KATANA_VERSION
ARG DALFOX_VERSION
ARG GOPROXY
ARG GOSUMDB

ENV HOME=${USER_HOME} \
    APP_HOME=${APP_HOME} \
    WORKSPACE_DIR=${WORKSPACE_DIR} \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHON_TERMINAL_MCP_ROOT=${APP_HOME} \
    PYTHON_TERMINAL_MCP_HOST=0.0.0.0 \
    PYTHON_TERMINAL_MCP_PORT=8000 \
    PYTHON_TERMINAL_MCP_PYTHON=${APP_HOME}/.venv/bin/python \
    PYTHON_TERMINAL_MCP_WORKSPACE_DIR=${WORKSPACE_DIR} \
    PATH=${APP_HOME}/.venv/bin:${PATH}

ENV PYTHON_TERMINAL_MCP_RUNTIME_DIR=${WORKSPACE_DIR}/runtime_v2

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        python3-venv \
        sudo \
    && rm -rf /var/lib/apt/lists/*

RUN if getent group "${USERNAME}" >/dev/null; then \
        groupmod -o -g "${USER_GID}" "${USERNAME}"; \
    else \
        groupadd -g "${USER_GID}" "${USERNAME}"; \
    fi \
    && if id -u "${USERNAME}" >/dev/null 2>&1; then \
        usermod -o -u "${USER_UID}" -g "${USER_GID}" -d "${USER_HOME}" -s /bin/bash "${USERNAME}"; \
    else \
        useradd -m -d "${USER_HOME}" -s /bin/bash -u "${USER_UID}" -g "${USER_GID}" "${USERNAME}"; \
    fi \
    && usermod -aG sudo "${USERNAME}" \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME} \
    && mkdir -p "${APP_HOME}" "${WORKSPACE_DIR}"

COPY requirements.txt ${APP_HOME}/requirements.txt
COPY app/ ${APP_HOME}/app/

RUN python3 -m venv "${APP_HOME}/.venv" \
    && install_args=(--no-cache-dir --prefer-binary) \
    && if [ -n "${PIP_INDEX_URL:-}" ]; then install_args+=(--index-url "${PIP_INDEX_URL}"); fi \
    && if [ -n "${PIP_EXTRA_INDEX_URL:-}" ]; then install_args+=(--extra-index-url "${PIP_EXTRA_INDEX_URL}"); fi \
    && "${APP_HOME}/.venv/bin/pip" --version \
    && "${APP_HOME}/.venv/bin/pip" install "${install_args[@]}" -r "${APP_HOME}/requirements.txt" "arjun==${ARJUN_VERSION}" \
    && printf '%s\n' '#!/bin/sh' "exec \"${APP_HOME}/.venv/bin/python\" \"\$@\"" > /usr/local/bin/python \
    && cp /usr/local/bin/python /usr/local/bin/python3 \
    && chmod 0755 /usr/local/bin/python /usr/local/bin/python3 \
    && ln -sf "${APP_HOME}/.venv/bin/pip" /usr/local/bin/pip \
    && ln -sf "${APP_HOME}/.venv/bin/arjun" /usr/local/bin/arjun \
    && mkdir -p "${PYTHON_TERMINAL_MCP_RUNTIME_DIR}" "${WORKSPACE_DIR}" \
    && chown -R "${USERNAME}:${USERNAME}" "${USER_HOME}"

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends golang-go; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "${arch}" in \
        amd64|arm64) ;; \
        *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    export GO111MODULE=on; \
    export GOOS=linux; \
    export GOARCH="${arch}"; \
    export CGO_ENABLED=0; \
    export GOPROXY="${GOPROXY}"; \
    export GOSUMDB="${GOSUMDB}"; \
    export GOBIN=/tmp/go-tools/bin; \
    mkdir -p "${GOBIN}"; \
    go install github.com/ffuf/ffuf/v2@v${FFUF_VERSION}; \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@v${HTTPX_VERSION}; \
    export CGO_ENABLED=1; \
    go install github.com/projectdiscovery/katana/cmd/katana@v${KATANA_VERSION}; \
    export CGO_ENABLED=0; \
    go install github.com/hahwul/dalfox/v2@v${DALFOX_VERSION}; \
    install -m 0755 "${GOBIN}/ffuf" /usr/local/bin/ffuf; \
    install -m 0755 "${GOBIN}/httpx" /usr/local/bin/httpx; \
    install -m 0755 "${GOBIN}/katana" /usr/local/bin/katana; \
    install -m 0755 "${GOBIN}/dalfox" /usr/local/bin/dalfox; \
    install -m 0755 "${GOBIN}/httpx" "${APP_HOME}/.venv/bin/httpx"; \
    ffuf -V >/dev/null \
    && httpx -version >/dev/null \
    && HOME=/tmp katana -version >/dev/null \
    && dalfox version >/dev/null; \
    apt-get purge -y --auto-remove golang-go; \
    rm -rf /var/lib/apt/lists/* /tmp/go-tools /root/go /root/.cache/go-build

RUN npm install -g ccusage \
    && ccusage --version >/dev/null

WORKDIR ${WORKSPACE_DIR}
USER ${USERNAME}

EXPOSE 8000
CMD ["/home/kali/python-terminal-mcp/.venv/bin/python", "/home/kali/python-terminal-mcp/app/python_terminal_mcp.py", "--host", "0.0.0.0", "--port", "8000", "--runtime-dir", "/home/kali/workspace/runtime_v2", "--workspace-dir", "/home/kali/workspace", "--allow-remote"]
