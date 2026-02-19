#!/bin/bash
set -e

WARP_READY=false

# mihomo 优先于 WARP
if [ "$ENABLE_MIHOMO" = "true" ]; then
    if [ -z "$MIHOMO_SUB_URL" ]; then
        echo "[FaceProxy] ERROR: ENABLE_MIHOMO=true but MIHOMO_SUB_URL is empty, falling back to direct"
        export ENABLE_MIHOMO=false
    elif ! command -v mihomo >/dev/null 2>&1; then
        echo "[FaceProxy] ERROR: ENABLE_MIHOMO=true but mihomo binary not found, falling back to direct"
        export ENABLE_MIHOMO=false
    else
        # 覆盖 WARP，互斥
        export ENABLE_AUTOWARP=false

        echo "[FaceProxy] Fetching mihomo subscription..."
        if ! curl -fsSL "$MIHOMO_SUB_URL" -o /tmp/sub_full.yaml; then
            echo "[FaceProxy] ERROR: Failed to fetch subscription, falling back to direct"
            export ENABLE_MIHOMO=false
        else
            mkdir -p /etc/mihomo

            # 从订阅中提取 proxies 段写入 provider 文件
            # 匹配从 "proxies:" 到下一个顶级 key 之间的内容
            sed -n '/^proxies:/,/^[a-zA-Z]/{/^proxies:/p;/^[a-zA-Z]/!p;}' /tmp/sub_full.yaml > /etc/mihomo/proxies.yaml

            # 检查提取结果是否有效
            if [ ! -s /etc/mihomo/proxies.yaml ] || ! grep -q "proxies:" /etc/mihomo/proxies.yaml; then
                echo "[FaceProxy] ERROR: Failed to extract proxies from subscription, falling back to direct"
                export ENABLE_MIHOMO=false
            else
                # 构建健康检查 URL
                HC_URL="https://${HF_SPACE_USER}-${HF_SPACE_NAME}.hf.space"

                # 生成 mihomo 配置
                cat > /etc/mihomo/config.yaml <<MIHOMO_EOF
mixed-port: 7890
mode: global
log-level: warning
ipv6: false

proxy-providers:
  sub:
    type: file
    path: /etc/mihomo/proxies.yaml
    health-check:
      enable: true
      url: "${HC_URL}"
      interval: 180

proxy-groups:
  - name: "lb"
    type: load-balance
    strategy: round-robin
    use:
      - sub
    url: "${HC_URL}"
    interval: 180

rules:
  - MATCH,lb
MIHOMO_EOF

                echo "[FaceProxy] Starting mihomo..."
                mihomo -d /etc/mihomo &

                # 等待 mihomo 就绪（检测 7890 端口）
                MIHOMO_READY=false
                for i in $(seq 1 15); do
                    if ss -tlnp 2>/dev/null | grep -q ":7890 " || \
                       bash -c "echo >/dev/tcp/127.0.0.1/7890" 2>/dev/null; then
                        echo "[FaceProxy] mihomo is ready on port 7890"
                        MIHOMO_READY=true
                        break
                    fi
                    echo "[FaceProxy] Waiting for mihomo to be ready... ($i/15)"
                    sleep 2
                done

                if [ "$MIHOMO_READY" = "false" ]; then
                    echo "[FaceProxy] WARNING: mihomo failed to start, falling back to direct"
                    export ENABLE_MIHOMO=false
                fi
            fi
        fi
    fi
fi

if [ "$ENABLE_MIHOMO" != "true" ] && [ "$ENABLE_AUTOWARP" = "true" ]; then
    if ! command -v warp-svc >/dev/null 2>&1; then
        echo "[FaceProxy] ERROR: ENABLE_AUTOWARP=true but warp-svc not found, running without WARP"
        export ENABLE_AUTOWARP=false
    else
        # warp-svc 依赖 dbus
        mkdir -p /run/dbus
        if command -v dbus-daemon >/dev/null 2>&1; then
            dbus-daemon --system --nofork &
            sleep 1
        fi

        echo "[FaceProxy] Starting Cloudflare WARP daemon..."
        warp-svc &
        sleep 3

        # 等待 warp-cli 可用
        for i in $(seq 1 10); do
            if warp-cli --accept-tos status >/dev/null 2>&1; then
                break
            fi
            echo "[FaceProxy] Waiting for warp-svc to be ready... ($i/10)"
            sleep 2
        done

        # 注册（已注册则跳过）
        if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
            warp-cli --accept-tos registration new
            echo "[FaceProxy] WARP registered"
        fi

        # Proxy 模式，不需要 TUN 设备
        warp-cli --accept-tos mode proxy
        warp-cli --accept-tos proxy port 40000
        warp-cli --accept-tos connect

        # 等待连接就绪
        for i in $(seq 1 30); do
            if warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
                echo "[FaceProxy] WARP connected"
                WARP_READY=true
                break
            fi
            sleep 1
        done

        if [ "$WARP_READY" = "false" ]; then
            echo "[FaceProxy] WARNING: WARP failed to connect, disabling WARP"
            export ENABLE_AUTOWARP=false
        fi
    fi
fi

exec /faceproxy
