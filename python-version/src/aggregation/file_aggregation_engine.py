#!/usr/bin/env python3
"""
File-based Aggregation Engine
Reads flows from JSON file written by C capture program.
"""

import sys
import json
import time
import hmac
import hashlib
from datetime import datetime
from pathlib import Path
import argparse

sys.path.insert(0, str(Path(__file__).parent))
from cms_aggregator import CMSAggregator
from hll_aggregator import HLLAggregator


class FileAggregationEngine:
    """
    Aggregation engine that reads flows from JSON file.
    Applies privacy preservation (HMAC) and aggregation.
    """
    
    def __init__(self, 
                 cms_width: int = 2048,
                 cms_depth: int = 5,
                 hll_precision: int = 14,
                 input_file: str = "output/flows/current_flows.json",
                 output_dir: str = "output/aggregated_flows",
                 anonymize: bool = True,
                 secret_key: str = "tma_project_secret_2025"):
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
        
        # Privacy settings
        self.anonymize = anonymize
        self.secret_key = secret_key.encode('utf-8')
    
    def _anonymize_ip(self, ip_str: str) -> str:
        """
        Anonymize IP using HMAC-SHA256.
        Produces a deterministic, irreversible hash.
        Truncated to 16 chars for readability in sketches.
        """
        if not self.anonymize:
            return ip_str
        
        return hmac.new(
            self.secret_key, 
            ip_str.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()[:16]

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
            
        except json.JSONDecodeError:
            # File might be currently being written by C program
            return None
        except Exception as e:
            print(f"[ERROR] Failed to read file: {e}")
            return None
    
    def process_batch(self, data):
        """Process a batch of flows."""
        flows = data.get('flows', [])
        
        if not flows:
            return
        
        print(f"\n[INFO] Processing batch: {len(flows)} flows")
        
        for flow in flows:
            try:
                # --- PRIVACY PRESERVATION STEP ---
                # Replace raw IPs with HMACs before aggregation
                if self.anonymize:
                    flow['src_ip'] = self._anonymize_ip(flow['src_ip'])
                    flow['dst_ip'] = self._anonymize_ip(flow['dst_ip'])
                # -------------------------------

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
        print(f"Privacy Mode: {'ENABLED (HMAC)' if self.anonymize else 'DISABLED'}")
        
        # CMS statistics
        print(f"\n--- Count-Min Sketch (Heavy Hitters) ---")
        cms_summary = self.cms_aggregator.get_summary()
        print(f"Total Bytes: {cms_summary['total_bytes']:,}")
        
        print(f"\nTop 10 Flows by Bytes (Anonymized):")
        for i, (flow, count) in enumerate(self.cms_aggregator.get_heavy_hitters(10, 'bytes'), 1):
            print(f"  {i}. {flow}")
            print(f"     → {count:,} bytes")
        
        # HLL statistics
        print(f"\n--- HyperLogLog (Cardinality Estimation) ---")
        cardinalities = self.hll_aggregator.get_cardinalities()
        print(f"Unique Source IPs: {cardinalities['unique_src_ips']}")
        print(f"Unique Destination IPs: {cardinalities['unique_dst_ips']}")
        print(f"Unique Flows: {cardinalities['unique_flows']}")
        
        # Anomaly detection
        scanners = self.hll_aggregator.detect_port_scanners(threshold=20)
        if scanners:
            print(f"\n⚠️  Potential Port Scanners Detected:")
            for ip, ports in scanners[:5]:
                print(f"  • {ip}: contacted {ports} unique ports")
        
        # Memory usage
        total_memory = (self.cms_aggregator.get_memory_usage() + 
                       self.hll_aggregator.get_memory_usage())
        print(f"\n--- Memory & Compression ---")
        print(f"Total Memory: {total_memory:,} bytes ({total_memory/1024:.1f} KB)")
        
        if self.flows_processed > 0:
            raw_size = self.flows_processed * 200  # Estimate 200 bytes per flow
            compression_ratio = raw_size / total_memory if total_memory > 0 else 0
            print(f"Estimated Raw Size: {raw_size:,} bytes")
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
            'privacy_enabled': self.anonymize,
            'cms': {
                'heavy_hitters_bytes': [
                    {'flow': flow, 'bytes': count} 
                    for flow, count in self.cms_aggregator.get_heavy_hitters(20, 'bytes')
                ]
            },
            'hll': {
                'cardinalities': self.hll_aggregator.get_cardinalities(),
                'port_scanners': [
                    {'ip': ip, 'unique_ports': count}
                    for ip, count in self.hll_aggregator.detect_port_scanners(20)
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
                'batches_processed': self.batches_processed,
                'privacy': self.anonymize
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f)
        
        print(f"✅ State exported to: {filepath}")
        return filepath
    
    def run(self, poll_interval: int = 5, stats_interval: int = 30):
        """Run aggregation engine in polling mode."""
        print("File-based Aggregation Engine")
        print("="*70)
        print(f"Input file: {self.input_file}")
        print(f"Anonymization: {self.anonymize}")
        print(f"Stats interval: {stats_interval}s")
        print("="*70)
        
        last_stats_time = time.time()
        
        try:
            while True:
                data = self.read_flows()
                if data:
                    self.process_batch(data)
                
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    if self.flows_processed > 0:
                        self.print_stats()
                        self.export_summary()
                    last_stats_time = current_time
                
                time.sleep(poll_interval)
                
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
            if self.flows_processed > 0:
                self.print_stats()
                self.export_summary()
                self.export_state()
            print("✅ Done!")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', default='output/flows/current_flows.json')
    parser.add_argument('--output-dir', default='output/aggregated_flows')
    parser.add_argument('--cms-width', type=int, default=2048)
    parser.add_argument('--cms-depth', type=int, default=5)
    parser.add_argument('--hll-precision', type=int, default=14)
    parser.add_argument('--poll-interval', type=int, default=5)
    parser.add_argument('--stats-interval', type=int, default=30)
    parser.add_argument('--no-privacy', action='store_true', help="Disable IP anonymization")
    
    args = parser.parse_args()
    
    engine = FileAggregationEngine(
        cms_width=args.cms_width,
        cms_depth=args.cms_depth,
        hll_precision=args.hll_precision,
        input_file=args.input_file,
        output_dir=args.output_dir,
        anonymize=not args.no_privacy
    )
    
    engine.run(poll_interval=args.poll_interval, stats_interval=args.stats_interval)


if __name__ == "__main__":
    main()