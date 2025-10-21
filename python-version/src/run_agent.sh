#!/bin/bash

# Launch script for Decentralized Flow Monitoring Agent
# Runs both capture and aggregation together

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
INTERFACE=""
CMS_WIDTH=2048
CMS_DEPTH=5
HLL_PRECISION=14
OUTPUT_DIR="output/aggregated_flows"
EXPORT_INTERVAL=60

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

print_usage() {
    echo "Usage: $0 [OPTIONS] [INTERFACE]"
    echo ""
    echo "Options:"
    echo "  -i, --interface IFACE     Network interface to capture (default: auto-detect)"
    echo "  --cms-width WIDTH         CMS width (default: 2048)"
    echo "  --cms-depth DEPTH         CMS depth (default: 5)"
    echo "  --hll-precision PREC      HLL precision (default: 14)"
    echo "  --output-dir DIR          Output directory (default: output/aggregated_flows)"
    echo "  --export-interval SEC     Export interval in seconds (default: 60)"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Example:"
    echo "  sudo $0 eth0"
    echo "  sudo $0 --interface wlan0 --export-interval 30"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        --cms-width)
            CMS_WIDTH="$2"
            shift 2
            ;;
        --cms-depth)
            CMS_DEPTH="$2"
            shift 2
            ;;
        --hll-precision)
            HLL_PRECISION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --export-interval)
            EXPORT_INTERVAL="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            INTERFACE="$1"
            shift
            ;;
    esac
done

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if capture binary exists
if [ ! -f "$SCRIPT_DIR/capture/flow_capture" ]; then
    echo -e "${YELLOW}Capture binary not found. Compiling...${NC}"
    cd "$SCRIPT_DIR/capture"
    gcc -o flow_capture flow_capture.c -lpcap
    if [ $? -ne 0 ]; then
        echo -e "${RED}Compilation failed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}Compilation successful!${NC}"
    cd "$SCRIPT_DIR"
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Print configuration
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Decentralized Flow Monitoring Agent          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo "Configuration:"
echo "  Interface:       ${INTERFACE:-auto-detect}"
echo "  CMS Width:       $CMS_WIDTH"
echo "  CMS Depth:       $CMS_DEPTH"
echo "  HLL Precision:   $HLL_PRECISION"
echo "  Output Dir:      $OUTPUT_DIR"
echo "  Export Interval: ${EXPORT_INTERVAL}s"
echo ""
echo -e "${YELLOW}Starting agent... Press Ctrl+C to stop${NC}"
echo ""

# Trap Ctrl+C for graceful shutdown
trap 'echo -e "\n${YELLOW}Shutting down agent...${NC}"; exit 0' SIGINT SIGTERM

# Run the pipeline
if [ -z "$INTERFACE" ]; then
    # Auto-detect interface
    stdbuf -oL "$SCRIPT_DIR/capture/flow_capture" 2>&1 | \
        python3 -u "$SCRIPT_DIR/aggregation/aggregation_engine.py" \
            --cms-width "$CMS_WIDTH" \
            --cms-depth "$CMS_DEPTH" \
            --hll-precision "$HLL_PRECISION" \
            --output-dir "$OUTPUT_DIR" \
            --export-interval "$EXPORT_INTERVAL"
else
    # Use specified interface
    stdbuf -oL "$SCRIPT_DIR/capture/flow_capture" "$INTERFACE" 2>&1 | \
        python3 -u "$SCRIPT_DIR/aggregation/aggregation_engine.py" \
            --cms-width "$CMS_WIDTH" \
            --cms-depth "$CMS_DEPTH" \
            --hll-precision "$HLL_PRECISION" \
            --output-dir "$OUTPUT_DIR" \
            --export-interval "$EXPORT_INTERVAL"
fi