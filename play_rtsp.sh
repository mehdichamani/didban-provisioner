#!/usr/bin/env bash

# Default configurations
DEFAULT_PREFIX="172.20.2."
DEFAULT_USER="admin"
# Load password from .env or environment variable if available
ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
    ENV_PASS=$(grep -E '^CAMERA_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2- | tr -d '\r"')
fi
DEFAULT_PASS="${CAMERA_PASSWORD:-${ENV_PASS:-}}"

echo "=========================================="
echo "      Hikvision RTSP Quick Player         "
echo "=========================================="

# 1. Ask for IP (last octet or full IP)
read -e -i "${DEFAULT_PREFIX}" -p "Camera IP [default: ${DEFAULT_PREFIX}X]: " INPUT_IP
if [[ -z "$INPUT_IP" ]]; then
    echo "Error: IP address cannot be empty."
    exit 1
fi

# If user just typed the last octet (e.g. 187)
if [[ "$INPUT_IP" =~ ^[0-9]{1,3}$ ]]; then
    CAMERA_IP="${DEFAULT_PREFIX}${INPUT_IP}"
else
    CAMERA_IP="$INPUT_IP"
fi

# 2. Ask for Password (hidden input if typing, or use default if found in .env)
if [[ -n "$DEFAULT_PASS" ]]; then
    read -e -i "$DEFAULT_PASS" -p "Password (from .env): " CAMERA_PASS
else
    read -s -p "Password: " CAMERA_PASS
    echo ""
fi

# 3. Ask for Stream Type (Main or Sub)
echo ""
echo "Select Stream Type:"
echo "  1) Main Stream (101 - High Quality) [Default]"
echo "  2) Sub Stream  (102 - Fast / Low Bandwidth)"
read -p "Choice [1/2] (default: 1): " STREAM_CHOICE

if [[ "$STREAM_CHOICE" == "2" ]]; then
    CHANNEL="102"
    STREAM_NAME="Sub Stream"
else
    CHANNEL="101"
    STREAM_NAME="Main Stream"
fi

# URL-encode password (especially '@', ':', '/', '#', etc.)
ENCODED_PASS=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$CAMERA_PASS")

RTSP_URL="rtsp://${DEFAULT_USER}:${ENCODED_PASS}@${CAMERA_IP}:554/Streaming/Channels/${CHANNEL}"

echo ""
echo "------------------------------------------"
echo "Target IP   : ${CAMERA_IP}"
echo "Stream      : ${STREAM_NAME} (${CHANNEL})"
echo "Connecting via ffplay..."
echo "------------------------------------------"

# Play with low latency flags
ffplay -rtsp_transport tcp -fflags nobuffer -flags low_delay -framedrop -window_title "Hikvision (${CAMERA_IP} - ${STREAM_NAME})" "$RTSP_URL"
