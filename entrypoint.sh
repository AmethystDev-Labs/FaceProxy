#!/bin/bash
set -e

WARP_READY=false

if [ "$ENABLE_AUTOWARP" = "true" ]; then
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
