#!/usr/bin/env python3
"""
Main Aggregation Engine
Combines CMS and HLL aggregators to process network flows.
Reads from C capture program and produces compact summaries.
"""

import sys
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
import argparse

from cms_aggregator import CMSAggregator
from hll_aggregator import HLLAggregator


class FlowParser:
    """Parse flow exports from C capture program."""
    
    @staticmethod
    def parse_flow_export(lines: list) -> list:
        """
        Parse flow export block from capture program output.
        
        Args:
            lines: List of output lines
        
        Returns:
            List of flow record dictionaries
        """
        flows = []
        current_flow = {}
        in_export = False
        
        for line in lines:
            line = line.strip()
            
            # Detect start of export block
            if "FLOW EXPORT" in line:
                in_export = True
                continue
            
            if not in_export:
                continue
            
            # Detect start of new flow
            if line.startswith("Flow "):
                # Save previous flow if exists
                if current_flow and all(k in current_flow for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_count', 'byte_count']):
                    flows.append(current_flow)
                current_flow = {}
                continue
            
            # Parse flow line: "  63.140.62.139:443 -> 10.0.2.8:38602"
            if "->" in line and ":" in line and not line.startswith(("Protocol:", "Packets:", "Duration:", "First")):
                # Remove leading whitespace and parse
                match = re.match(r'\s*(.+):(\d+)\s*->\s*(.+):(\d+)', line)
                if match:
                    current_flow['src_ip'] = match.group(1).strip()
                    current_flow['src_port'] = int(match.group(2))
                    current_flow['dst_ip'] = match.group(3).strip()
                    current_flow['dst_port'] = int(match.group(4))
                continue
            
            # Parse protocol line: "  Protocol: TCP"
            if line.startswith("Protocol:"):
                protocol = line.split(":")[-1].strip()
                current_flow['protocol'] = protocol
                continue
            
            # Parse packets/bytes line: "  Packets: 12, Bytes: 6623"
            if line.startswith("Packets:"):
                match = re.search(r'Packets:\s*(\d+),\s*Bytes:\s*(\d+)', line)
                if match:
                    current_flow['packet_count'] = int(match.group(1))
                    current_flow['byte_count'] = int(match.group(2))
                continue
            
            # Detect end of flow (line with "---")
            if line.startswith("---"):
                if current_flow and all(k in current_flow for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_count', 'byte_count']):
                    flows.append(current_flow)
                    current_flow = {}
                continue
            
            # Detect end of export block
            if line.startswith("==="):
                # Save last flow if exists
                if current_flow and all(k in current_flow for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_count', 'byte_count']):
                    flows.append(current_flow)
                in_export = False
                current_flow = {}
                break
        
        return flows


class AggregationEngine:
    """
    Main aggregation engine combining CMS and HLL.
    Processes flows and generates compact summaries.
    """
    
    def __init__(self, 
                 cms_width: int = 2048,
                 cms_depth: int = 5,
                 hll_precision: int = 14,
                 output_dir: str = "output/aggregated_flows"):
        """
        Initialize aggregation engine.
        
        Args:
            cms_width: Count-Min Sketch width
            cms_depth: Count-Min Sketch depth
            hll_precision: HyperLogLog precision
            output_dir: Directory for output files
        """
        self.cms_aggregator = CMSAggregator(width=cms_width, depth=cms_depth)
        self.hll_aggregator = HLLAggregator(precision=hll_precision)
        self.parser = FlowParser()
        
        # Create output directory
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.flows_processed = 0
        self.exports_received = 0
        self.start_time = datetime.now()
    
    def process_flows(self, flows: list):
        """Process a batch of flows through both aggregators."""
        for flow in flows:
            # Validate flow has required fields
            required = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 
                       'protocol', 'packet_count', 'byte_count']
            if all(field in flow for field in required):
                self.cms_aggregator.add_flow(flow)
                self.hll_aggregator.add_flow(flow)
                self.flows_processed += 1
        
        self.exports_received += 1
    
    def generate_summary(self) -> Dict:
        """Generate comprehensive summary from both aggregators."""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'runtime_seconds': (datetime.now() - self.start_time).total_seconds(),
            'flows_processed': self.flows_processed,
            'exports_received': self.exports_received,
            
            # CMS metrics
            'cms': {
                'summary': self.cms_aggregator.get_summary(),
                'heavy_hitters_bytes': [
                    {'flow': flow, 'bytes': count} 
                    for flow, count in self.cms_aggregator.get_heavy_hitters(10, 'bytes')
                ],
                'heavy_hitters_packets': [
                    {'flow': flow, 'packets': count}
                    for flow, count in self.cms_aggregator.get_heavy_hitters(10, 'packets')
                ]
            },
            
            # HLL metrics
            'hll': {
                'summary': self.hll_aggregator.get_summary(),
                'cardinalities': self.hll_aggregator.get_cardinalities(),
                'port_scanners': [
                    {'ip': ip, 'unique_ports': count}
                    for ip, count in self.hll_aggregator.detect_port_scanners(20)
                ],
                'popular_services': [
                    {'port': port, 'unique_clients': count}
                    for port, count in self.hll_aggregator.get_popular_services(10)
                ]
            },
            
            # Combined metrics
            'total_memory_bytes': (self.cms_aggregator.get_memory_usage() + 
                                  self.hll_aggregator.get_memory_usage()),
            'compression_ratio': self._estimate_compression_ratio()
        }
        
        return summary
    
    def _estimate_compression_ratio(self) -> float:
        """Estimate compression ratio vs raw flow storage."""
        if self.flows_processed == 0:
            return 0.0
        
        # Assume ~200 bytes per raw flow record (JSON)
        raw_size = self.flows_processed * 200
        compressed_size = (self.cms_aggregator.get_memory_usage() + 
                          self.hll_aggregator.get_memory_usage())
        
        if compressed_size == 0:
            return 0.0
        
        return raw_size / compressed_size
    
    def export_summary(self, filename: Optional[str] = None):
        """Export summary to JSON file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"summary_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        summary = self.generate_summary()
        
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n[✓] Summary exported to: {filepath}")
        return filepath
    
    def export_full_state(self, filename: Optional[str] = None):
        """Export complete aggregator state (for merging with other nodes)."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"state_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        state = {
            'timestamp': datetime.now().isoformat(),
            'cms': self.cms_aggregator.export(),
            'hll': self.hll_aggregator.export(),
            'metadata': {
                'flows_processed': self.flows_processed,
                'exports_received': self.exports_received
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f)
        
        print(f"[✓] Full state exported to: {filepath}")
        return filepath
    
    def print_live_stats(self):
        """Print live statistics to console."""
        print("\n" + "="*60)
        print(f"LIVE STATISTICS - {datetime.now().strftime('%H:%M:%S')}")
        print("="*60)
        
        print(f"\nFlows Processed: {self.flows_processed}")
        print(f"Exports Received: {self.exports_received}")
        
        # CMS stats
        print(f"\n--- Count-Min Sketch ---")
        cms_summary = self.cms_aggregator.get_summary()
        print(f"Total Bytes: {cms_summary['total_bytes']:,}")
        print(f"Total Packets: {cms_summary['total_packets']:,}")
        print(f"Memory: {cms_summary['memory_bytes']:,} bytes")
        
        print(f"\nTop 5 Heavy Hitters (by bytes):")
        for flow, count in self.cms_aggregator.get_heavy_hitters(5, 'bytes'):
            print(f"  {flow}: {count:,} bytes")
        
        # HLL stats
        print(f"\n--- HyperLogLog ---")
        cardinalities = self.hll_aggregator.get_cardinalities()
        print(f"Unique Source IPs: {cardinalities['unique_src_ips']}")
        print(f"Unique Destination IPs: {cardinalities['unique_dst_ips']}")
        print(f"Unique Flows: {cardinalities['unique_flows']}")
        print(f"Network Diversity: {self.hll_aggregator.get_network_diversity_score():.2%}")
        
        scanners = self.hll_aggregator.detect_port_scanners(20)
        if scanners:
            print(f"\n⚠ Potential Port Scanners Detected:")
            for ip, ports in scanners[:3]:
                print(f"  {ip}: {ports} unique ports")
        
        # Memory usage
        total_memory = (self.cms_aggregator.get_memory_usage() + 
                       self.hll_aggregator.get_memory_usage())
        print(f"\nTotal Memory Usage: {total_memory:,} bytes ({total_memory/1024:.1f} KB)")
        print(f"Compression Ratio: {self._estimate_compression_ratio():.1f}x")
        
        print("="*60 + "\n")
    
    def run_stdin(self, export_interval: int = 60):
        """
        Run engine reading from stdin (piped from C program).
        
        Args:
            export_interval: Export summary every N seconds
        """
        print("Starting Aggregation Engine...")
        print(f"Reading flows from stdin...")
        print(f"Export interval: {export_interval} seconds\n")
        
        buffer = []
        last_export_time = datetime.now()
        
        try:
            for line in sys.stdin:
                print(line, end='')  # Echo to stdout
                buffer.append(line)
                
                # Check if we got a flow export block
                if "FLOW EXPORT" in line:
                    # Process accumulated flows
                    flows = self.parser.parse_flow_export(buffer)
                    if flows:
                        self.process_flows(flows)
                        self.print_live_stats()
                    
                    # Clear buffer
                    buffer = []
                    
                    # Check if it's time to export
                    now = datetime.now()
                    if (now - last_export_time).total_seconds() >= export_interval:
                        self.export_summary()
                        last_export_time = now
        
        except KeyboardInterrupt:
            print("\n\nShutting down gracefully...")
            self.export_summary()
            self.export_full_state()
            print("Done!")


def main():
    parser = argparse.ArgumentParser(
        description="Network Flow Aggregation Engine"
    )
    parser.add_argument(
        '--cms-width', type=int, default=2048,
        help='Count-Min Sketch width (default: 2048)'
    )
    parser.add_argument(
        '--cms-depth', type=int, default=5,
        help='Count-Min Sketch depth (default: 5)'
    )
    parser.add_argument(
        '--hll-precision', type=int, default=14,
        help='HyperLogLog precision (default: 14)'
    )
    parser.add_argument(
        '--output-dir', type=str, default='output/aggregated_flows',
        help='Output directory for summaries'
    )
    parser.add_argument(
        '--export-interval', type=int, default=60,
        help='Export summary interval in seconds (default: 60)'
    )
    
    args = parser.parse_args()
    
    engine = AggregationEngine(
        cms_width=args.cms_width,
        cms_depth=args.cms_depth,
        hll_precision=args.hll_precision,
        output_dir=args.output_dir
    )
    
    engine.run_stdin(export_interval=args.export_interval)


if __name__ == "__main__":
    main()