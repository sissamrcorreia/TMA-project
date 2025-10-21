#!/usr/bin/env python3
"""
File-based Aggregation Engine
Reads flows from JSON file written by C capture program.
"""

import sys
import json
import time
from datetime import datetime
from pathlib import Path
import argparse

sys.path.insert(0, str(Path(__file__).parent))
from cms_aggregator import CMSAggregator
from hll_aggregator import HLLAggregator


class FileAggregationEngine:
    """
    Aggregation engine that reads flows from JSON file.
    """
    
    def __init__(self, 
                 cms_width: int = 2048,
                 cms_depth: int = 5,
                 hll_precision: int = 14,
                 input_file: str = "output/flows/current_flows.json",
                 output_dir: str = "output/aggregated_flows"):
        """Initialize aggregation engine."""
        self.cms_aggregator = CMSAggregator(width=cms_width, depth=cms_depth)
        self.hll_aggregator = HLLAggregator(precision=hll_precision)
        
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.flows_processed = 0
        self.batches_processed = 0
        self.last_timestamp = 0
        self.start_time = datetime.now()
    
    def read_flows(self):
        """Read flows from JSON file."""
        try:
            if not self.input_file.exists():
                return None
            
            with open(self.input_file, 'r') as f:
                data = json.load(f)
            
            # Check if this is a new batch
            if data['timestamp'] == self.last_timestamp:
                return None
            
            self.last_timestamp = data['timestamp']
            return data
            
        except json.JSONDecodeError as e:
            print(f"[WARNING] Invalid JSON: {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Failed to read file: {e}")
            return None
    
    def process_batch(self, data):
        """Process a batch of flows."""
        flows = data.get('flows', [])
        
        if not flows:
            print(f"[INFO] No flows in batch (timestamp: {data['timestamp']})")
            return
        
        print(f"\n[INFO] Processing batch: {len(flows)} flows")
        
        for flow in flows:
            try:
                self.cms_aggregator.add_flow(flow)
                self.hll_aggregator.add_flow(flow)
                self.flows_processed += 1
            except Exception as e:
                print(f"[WARNING] Failed to process flow: {e}")
                continue
        
        self.batches_processed += 1
    
    def print_stats(self):
        """Print current statistics."""
        print("\n" + "="*70)
        print(f"AGGREGATION STATISTICS - {datetime.now().strftime('%H:%M:%S')}")
        print("="*70)
        
        print(f"\nTotal Flows Processed: {self.flows_processed}")
        print(f"Batches Processed: {self.batches_processed}")
        print(f"Runtime: {(datetime.now() - self.start_time).total_seconds():.1f} seconds")
        
        # CMS statistics
        print(f"\n--- Count-Min Sketch (Heavy Hitters) ---")
        cms_summary = self.cms_aggregator.get_summary()
        print(f"Total Bytes: {cms_summary['total_bytes']:,}")
        print(f"Total Packets: {cms_summary['total_packets']:,}")
        
        print(f"\nTop 10 Flows by Bytes:")
        for i, (flow, count) in enumerate(self.cms_aggregator.get_heavy_hitters(10, 'bytes'), 1):
            print(f"  {i}. {flow}")
            print(f"     → {count:,} bytes")
        
        # HLL statistics
        print(f"\n--- HyperLogLog (Cardinality Estimation) ---")
        cardinalities = self.hll_aggregator.get_cardinalities()
        print(f"Unique Source IPs: {cardinalities['unique_src_ips']}")
        print(f"Unique Destination IPs: {cardinalities['unique_dst_ips']}")
        print(f"Unique Source Ports: {cardinalities['unique_src_ports']}")
        print(f"Unique Destination Ports: {cardinalities['unique_dst_ports']}")
        print(f"Unique Flows: {cardinalities['unique_flows']}")
        print(f"Network Diversity Score: {self.hll_aggregator.get_network_diversity_score():.2%}")
        
        # Anomaly detection
        scanners = self.hll_aggregator.detect_port_scanners(threshold=20)
        if scanners:
            print(f"\n⚠️  Potential Port Scanners Detected:")
            for ip, ports in scanners[:5]:
                print(f"  • {ip}: contacted {ports} unique ports")
        
        popular = self.hll_aggregator.get_popular_services(top_n=5)
        if popular:
            print(f"\n📊 Most Popular Services:")
            for port, clients in popular:
                print(f"  • Port {port}: {clients} unique clients")
        
        # Memory usage
        total_memory = (self.cms_aggregator.get_memory_usage() + 
                       self.hll_aggregator.get_memory_usage())
        print(f"\n--- Memory & Compression ---")
        print(f"Total Memory: {total_memory:,} bytes ({total_memory/1024:.1f} KB)")
        
        if self.flows_processed > 0:
            raw_size = self.flows_processed * 200  # Estimate 200 bytes per flow
            compression_ratio = raw_size / total_memory if total_memory > 0 else 0
            print(f"Estimated Raw Size: {raw_size:,} bytes ({raw_size/1024:.1f} KB)")
            print(f"Compression Ratio: {compression_ratio:.1f}x")
        
        print("="*70 + "\n")
    
    def export_summary(self):
        """Export summary to JSON file."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"summary_{timestamp}.json"
        filepath = self.output_dir / filename
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'runtime_seconds': (datetime.now() - self.start_time).total_seconds(),
            'flows_processed': self.flows_processed,
            'batches_processed': self.batches_processed,
            'cms': {
                'summary': self.cms_aggregator.get_summary(),
                'heavy_hitters_bytes': [
                    {'flow': flow, 'bytes': count} 
                    for flow, count in self.cms_aggregator.get_heavy_hitters(20, 'bytes')
                ],
                'heavy_hitters_packets': [
                    {'flow': flow, 'packets': count}
                    for flow, count in self.cms_aggregator.get_heavy_hitters(20, 'packets')
                ]
            },
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
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"✅ Summary exported to: {filepath}")
        return filepath
    
    def export_state(self):
        """Export full state for P2P sharing."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"state_{timestamp}.json"
        filepath = self.output_dir / filename
        
        state = {
            'timestamp': datetime.now().isoformat(),
            'cms': self.cms_aggregator.export(),
            'hll': self.hll_aggregator.export(),
            'metadata': {
                'flows_processed': self.flows_processed,
                'batches_processed': self.batches_processed
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f)
        
        print(f"✅ State exported to: {filepath}")
        return filepath
    
    def run(self, poll_interval: int = 5, stats_interval: int = 30):
        """
        Run aggregation engine in polling mode.
        
        Args:
            poll_interval: How often to check for new flows (seconds)
            stats_interval: How often to print statistics (seconds)
        """
        print("File-based Aggregation Engine")
        print("="*70)
        print(f"Input file: {self.input_file}")
        print(f"Output directory: {self.output_dir}")
        print(f"Poll interval: {poll_interval}s")
        print(f"Stats interval: {stats_interval}s")
        print("="*70)
        print("\nWaiting for flow data... (Press Ctrl+C to stop)\n")
        
        last_stats_time = time.time()
        
        try:
            while True:
                # Read and process new flows
                data = self.read_flows()
                if data:
                    self.process_batch(data)
                
                # Print stats periodically
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    if self.flows_processed > 0:
                        self.print_stats()
                        self.export_summary()
                    else:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Waiting for flows...")
                    last_stats_time = current_time
                
                # Wait before next poll
                time.sleep(poll_interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Shutting down gracefully...")
            if self.flows_processed > 0:
                self.print_stats()
                self.export_summary()
                self.export_state()
            print("✅ Done!")


def main():
    parser = argparse.ArgumentParser(
        description="File-based Network Flow Aggregation Engine"
    )
    parser.add_argument(
        '--input-file', type=str, default='output/flows/current_flows.json',
        help='Input JSON file from capture program'
    )
    parser.add_argument(
        '--output-dir', type=str, default='output/aggregated_flows',
        help='Output directory for summaries'
    )
    parser.add_argument(
        '--cms-width', type=int, default=2048,
        help='Count-Min Sketch width'
    )
    parser.add_argument(
        '--cms-depth', type=int, default=5,
        help='Count-Min Sketch depth'
    )
    parser.add_argument(
        '--hll-precision', type=int, default=14,
        help='HyperLogLog precision'
    )
    parser.add_argument(
        '--poll-interval', type=int, default=5,
        help='File polling interval in seconds'
    )
    parser.add_argument(
        '--stats-interval', type=int, default=30,
        help='Statistics display interval in seconds'
    )
    
    args = parser.parse_args()
    
    engine = FileAggregationEngine(
        cms_width=args.cms_width,
        cms_depth=args.cms_depth,
        hll_precision=args.hll_precision,
        input_file=args.input_file,
        output_dir=args.output_dir
    )
    
    engine.run(
        poll_interval=args.poll_interval,
        stats_interval=args.stats_interval
    )


if __name__ == "__main__":
    main()