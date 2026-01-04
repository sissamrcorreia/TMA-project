"""
Count-Min Sketch Aggregator
Tracks heavy hitters and estimates flow volumes with bounded error.
"""

import hashlib
import json
from typing import Dict, List, Tuple


class CountMinSketch:
    """
    Count-Min Sketch probabilistic data structure.
    Space: O(width * depth)
    Query time: O(depth)
    Error bound: ε = e / width, δ = 1 / 2^depth
    """
    
    def __init__(self, width: int = 2048, depth: int = 5):
        """
        Initialize CMS.
        
        Args:
            width: Number of counters per hash function (more = less error)
            depth: Number of hash functions (more = less probability of error)
        
        Recommended: width=2048, depth=5 gives ~0.1% error with 99.97% confidence
        Memory: width * depth * 8 bytes = ~80KB for these params
        """
        self.width = width
        self.depth = depth
        self.table = [[0] * width for _ in range(depth)]
        self.total_count = 0
        
    def _hash(self, key: str, seed: int) -> int:
        """Generate hash value for given key and seed."""
        hash_input = f"{key}{seed}".encode('utf-8')
        hash_value = int(hashlib.md5(hash_input).hexdigest(), 16)
        return hash_value % self.width
    
    def add(self, key: str, count: int = 1):
        """
        Add count to the sketch for given key.
        
        Args:
            key: Flow identifier (e.g., "192.168.1.1:80->10.0.0.1:443")
            count: Value to add (bytes, packets, etc.)
        """
        for i in range(self.depth):
            j = self._hash(key, i)
            self.table[i][j] += count
        self.total_count += count
    
    def estimate(self, key: str) -> int:
        """
        Estimate count for given key.
        Returns the minimum across all hash functions (conservative estimate).
        """
        estimates = []
        for i in range(self.depth):
            j = self._hash(key, i)
            estimates.append(self.table[i][j])
        return min(estimates)
    
    def merge(self, other: 'CountMinSketch'):
        """
        Merge another CMS into this one (for distributed aggregation).
        Both sketches must have same dimensions.
        """
        if self.width != other.width or self.depth != other.depth:
            raise ValueError("Cannot merge sketches with different dimensions")
        
        for i in range(self.depth):
            for j in range(self.width):
                self.table[i][j] += other.table[i][j]
        self.total_count += other.total_count
    
    def get_memory_usage(self) -> int:
        """Return approximate memory usage in bytes."""
        # Each counter is a Python int (roughly 8 bytes for small values)
        return self.width * self.depth * 8
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary for JSON export."""
        return {
            'width': self.width,
            'depth': self.depth,
            'table': self.table,
            'total_count': self.total_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CountMinSketch':
        """Deserialize from dictionary."""
        cms = cls(width=data['width'], depth=data['depth'])
        cms.table = data['table']
        cms.total_count = data['total_count']
        return cms


class CMSAggregator:
    """
    Aggregates network flows using Count-Min Sketch.
    Tracks multiple metrics: bytes, packets, and flow counts.
    """
    
    def __init__(self, width: int = 2048, depth: int = 5):
        self.bytes_sketch = CountMinSketch(width, depth)
        self.packets_sketch = CountMinSketch(width, depth)
        self.flows_sketch = CountMinSketch(width, depth)
        
        # Keep track of actual flows we've seen (for heavy hitter detection)
        self.flow_keys = set()
    
    def add_flow(self, flow_record: Dict):
        """
        Add a flow record to the aggregator.
        
        Args:
            flow_record: Dictionary with keys:
                - src_ip, dst_ip, src_port, dst_port, protocol
                - packet_count, byte_count
        """
        # Create flow identifier
        flow_key = self._make_flow_key(flow_record)
        
        # Add to sketches
        self.bytes_sketch.add(flow_key, flow_record['byte_count'])
        self.packets_sketch.add(flow_key, flow_record['packet_count'])
        self.flows_sketch.add(flow_key, 1)
        
        # Track unique flows
        self.flow_keys.add(flow_key)
        
        # Also track per-IP statistics
        src_ip = flow_record['src_ip']
        dst_ip = flow_record['dst_ip']
        
        self.bytes_sketch.add(f"src:{src_ip}", flow_record['byte_count'])
        self.bytes_sketch.add(f"dst:{dst_ip}", flow_record['byte_count'])
    
    def _make_flow_key(self, flow_record: Dict) -> str:
        """Create unique flow identifier from 5-tuple."""
        return (f"{flow_record['src_ip']}:{flow_record['src_port']}->"
                f"{flow_record['dst_ip']}:{flow_record['dst_port']}"
                f"/{flow_record['protocol']}")
    
    def get_heavy_hitters(self, top_n: int = 10, metric: str = 'bytes') -> List[Tuple[str, int]]:
        """
        Get top N flows by specified metric.
        
        Args:
            top_n: Number of top flows to return
            metric: 'bytes', 'packets', or 'flows'
        
        Returns:
            List of (flow_key, estimated_count) tuples
        """
        sketch = {
            'bytes': self.bytes_sketch,
            'packets': self.packets_sketch,
            'flows': self.flows_sketch
        }[metric]
        
        # Estimate counts for all observed flows
        flow_estimates = []
        for flow_key in self.flow_keys:
            if not flow_key.startswith(('src:', 'dst:')):  # Skip IP-only keys
                estimate = sketch.estimate(flow_key)
                flow_estimates.append((flow_key, estimate))
        
        # Sort by estimate and return top N
        flow_estimates.sort(key=lambda x: x[1], reverse=True)
        return flow_estimates[:top_n]
    
    def get_ip_statistics(self, ip: str, direction: str = 'src') -> Dict[str, int]:
        """
        Get traffic statistics for a specific IP.
        
        Args:
            ip: IP address
            direction: 'src' or 'dst'
        
        Returns:
            Dictionary with bytes, packets estimates
        """
        key = f"{direction}:{ip}"
        return {
            'bytes': self.bytes_sketch.estimate(key),
            'packets': self.packets_sketch.estimate(key),
            'flows': self.flows_sketch.estimate(key)
        }
    
    def get_summary(self) -> Dict:
        """Generate summary statistics."""
        return {
            'type': 'count_min_sketch',
            'total_bytes': self.bytes_sketch.total_count,
            'total_packets': self.packets_sketch.total_count,
            'unique_flows': len(self.flow_keys),
            'memory_bytes': self.get_memory_usage(),
            'dimensions': {
                'width': self.bytes_sketch.width,
                'depth': self.bytes_sketch.depth
            }
        }
    
    def get_memory_usage(self) -> int:
        """Total memory usage of all sketches."""
        return (self.bytes_sketch.get_memory_usage() +
                self.packets_sketch.get_memory_usage() +
                self.flows_sketch.get_memory_usage())
    
    def merge(self, other: 'CMSAggregator'):
        """Merge another aggregator into this one."""
        self.bytes_sketch.merge(other.bytes_sketch)
        self.packets_sketch.merge(other.packets_sketch)
        self.flows_sketch.merge(other.flows_sketch)
        self.flow_keys.update(other.flow_keys)
    
    def export(self) -> Dict:
        """Export complete state for serialization."""
        return {
            'type': 'cms_aggregator',
            'bytes_sketch': self.bytes_sketch.to_dict(),
            'packets_sketch': self.packets_sketch.to_dict(),
            'flows_sketch': self.flows_sketch.to_dict(),
            'flow_keys': list(self.flow_keys),
            'summary': self.get_summary()
        }
    
    @classmethod
    def from_export(cls, data: Dict) -> 'CMSAggregator':
        """Reconstruct aggregator from exported data."""
        width = data['bytes_sketch']['width']
        depth = data['bytes_sketch']['depth']
        
        aggregator = cls(width, depth)
        aggregator.bytes_sketch = CountMinSketch.from_dict(data['bytes_sketch'])
        aggregator.packets_sketch = CountMinSketch.from_dict(data['packets_sketch'])
        aggregator.flows_sketch = CountMinSketch.from_dict(data['flows_sketch'])
        aggregator.flow_keys = set(data['flow_keys'])
        
        return aggregator


if __name__ == "__main__":
    # Example usage
    aggregator = CMSAggregator(width=2048, depth=5)
    
    # Simulate some flows
    test_flows = [
        {'src_ip': '192.168.1.10', 'dst_ip': '8.8.8.8', 'src_port': 54321, 
         'dst_port': 443, 'protocol': 'TCP', 'packet_count': 100, 'byte_count': 50000},
        {'src_ip': '192.168.1.10', 'dst_ip': '1.1.1.1', 'src_port': 54322,
         'dst_port': 443, 'protocol': 'TCP', 'packet_count': 50, 'byte_count': 25000},
        {'src_ip': '192.168.1.20', 'dst_ip': '8.8.8.8', 'src_port': 60000,
         'dst_port': 53, 'protocol': 'UDP', 'packet_count': 10, 'byte_count': 1000},
    ]
    
    for flow in test_flows:
        aggregator.add_flow(flow)
    
    # Get heavy hitters
    print("Top flows by bytes:")
    for flow, bytes_est in aggregator.get_heavy_hitters(top_n=3, metric='bytes'):
        print(f"  {flow}: {bytes_est} bytes")
    
    # Get IP stats
    print("\nStats for 192.168.1.10:")
    stats = aggregator.get_ip_statistics('192.168.1.10', 'src')
    print(f"  Bytes: {stats['bytes']}, Packets: {stats['packets']}, Flows: {stats['flows']}")
    
    # Summary
    print(f"\nSummary:")
    summary = aggregator.get_summary()
    print(json.dumps(summary, indent=2))