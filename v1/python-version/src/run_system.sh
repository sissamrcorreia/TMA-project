#!/bin/bash

# Launch script for File-based Flow Monitoring System
# Runs capture and aggregation as separate processes

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INTERFACE=""
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

print_usage() {
    echo "Usage: $0 [INTERFACE]"
    echo ""
    echo "Example:"
    echo "  sudo $0 eth0"
    echo "  sudo $0        # Auto-detect interface"
}

# Parse arguments
if [[ $# -gt 0 ]]; then
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        print_usage
        exit 0
    fi
    INTERFACE="$1"
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check and compile capture program
if [ ! -f "$SCRIPT_DIR/capture/flow_capture_json" ]; then
    echo -e "${YELLOW}Compiling capture program...${NC}"
    cd "$SCRIPT_DIR/capture"
    gcc -o flow_capture_json flow_capture_json.c -lpcap
    if [ $? -ne 0 ]; then
        echo -e "${RED}Compilation failed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}Compilation successful!${NC}"
    cd "$SCRIPT_DIR"
fi

# Create output directories
mkdir -p output/flows
mkdir -p output/aggregated_flows

echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Decentralized Flow Monitoring System         ║${NC}"
echo -e "${GREEN}║  File-based Architecture                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo "Configuration:"
echo "  Interface:       ${INTERFACE:-auto-detect}"
echo "  Flow file:       output/flows/current_flows.json"
echo "  Summaries:       output/aggregated_flows/"
echo ""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    kill $CAPTURE_PID 2>/dev/null || true
    kill $AGGREGATOR_PID 2>/dev/null || true
    wait 2>/dev/null
    echo -e "${GREEN}Done!${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start capture process
echo -e "${GREEN}[1/2] Starting capture process...${NC}"
if [ -z "$INTERFACE" ]; then
    "$SCRIPT_DIR/capture/flow_capture_json" > /dev/null 2>&1 &
else
    "$SCRIPT_DIR/capture/flow_capture_json" "$INTERFACE" > /dev/null 2>&1 &
fi
CAPTURE_PID=$!
echo "  Capture PID: $CAPTURE_PID"

# Wait a moment for capture to start
sleep 2

# Start aggregation process
echo -e "${GREEN}[2/2] Starting aggregation process...${NC}"
python3 "$SCRIPT_DIR/aggregation/file_aggregation_engine.py" \
    --poll-interval 5 \
    --stats-interval 30 &
AGGREGATOR_PID=$!
echo "  Aggregator PID: $AGGREGATOR_PID"

echo ""
echo -e "${GREEN}✅ System running!${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Wait for both processes
wait