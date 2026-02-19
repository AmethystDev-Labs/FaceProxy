#!/bin/bash
set -e

if [ "$ENABLE_AUTOWARP" = "true" ]; then
    if ! command -v warp-svc >/dev/null 2>&1; then
        echo "[FaceProxy] ERROR: ENABLE_AUTOWARP=true but warp-svc not found, running without WARP"
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
                break
            fi
            if [ "$i" -eq 30 ]; then
                echo "[FaceProxy] WARNING: WARP connection timeout, continuing without WARP"
            fi
            sleep 1
        done
    fi
fi

exec /faceproxy
