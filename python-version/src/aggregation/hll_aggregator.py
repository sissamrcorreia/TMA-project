"""
HyperLogLog Aggregator
Estimates cardinality (unique counts) with minimal memory.
Perfect for detecting port scans, unique connections, network diversity.
"""

import hashlib
import math
from typing import Dict, Set, List


class HyperLogLog:
    """
    HyperLogLog cardinality estimator.
    
    Memory: O(2^precision) = O(m) registers
    Error: ~1.04/sqrt(m)
    
    precision=14 -> 16KB memory, ~0.81% error
    precision=12 -> 4KB memory, ~1.625% error
    """
    
    def __init__(self, precision: int = 14):
        """
        Initialize HyperLogLog.
        
        Args:
            precision: Number of bits for register indexing (4-16 recommended)
                      Higher = more accurate but more memory
        
        precision=14: 16384 registers, ~16KB, standard error ~0.81%
        """
        if precision < 4 or precision > 16:
            raise ValueError("Precision must be between 4 and 16")
        
        self.precision = precision
        self.m = 1 << precision  # 2^precision registers
        self.registers = [0] * self.m
        self.alpha = self._get_alpha(self.m)
    
    def _get_alpha(self, m: int) -> float:
        """Get bias correction constant based on number of registers."""
        if m >= 128:
            return 0.7213 / (1 + 1.079 / m)
        elif m >= 64:
            return 0.709
        elif m >= 32:
            return 0.697
        elif m >= 16:
            return 0.673
        else:
            return 0.5
    
    def _hash(self, value: str) -> int:
        """Generate 64-bit hash of value."""
        return int(hashlib.sha256(value.encode('utf-8')).hexdigest()[:16], 16)
    
    def _rho(self, w: int, max_width: int = 64) -> int:
        """
        Count leading zeros + 1.
        Position of first 1-bit from the left.
        """
        if w == 0:
            return max_width + 1
        
        # Count leading zeros
        rho = 1
        while (w & (1 << (max_width - 1))) == 0 and rho <= max_width:
            w <<= 1
            rho += 1
        return rho
    
    def add(self, value: str):
        """
        Add an element to the HyperLogLog.
        
        Args:
            value: String representation of element (IP, port, etc.)
        """
        # Hash the value
        x = self._hash(value)
        
        # Use first 'precision' bits as register index
        j = x & ((1 << self.precision) - 1)
        
        # Use remaining bits to count leading zeros
        w = x >> self.precision
        self.registers[j] = max(self.registers[j], self._rho(w, 64 - self.precision))
    
    def count(self) -> int:
        """
        Estimate cardinality (number of unique elements).
        
        Returns:
            Estimated count of unique elements
        """
        # Calculate raw estimate
        raw_estimate = self.alpha * (self.m ** 2) / sum(2 ** (-x) for x in self.registers)
        
        # Apply bias correction for small/large cardinalities
        if raw_estimate <= 2.5 * self.m:
            # Small range correction
            zeros = self.registers.count(0)
            if zeros != 0:
                return int(self.m * math.log(self.m / zeros))
        
        if raw_estimate <= (1/30) * (1 << 32):
            # No correction
            return int(raw_estimate)
        else:
            # Large range correction
            return int(-1 * (1 << 32) * math.log(1 - raw_estimate / (1 << 32)))
    
    def merge(self, other: 'HyperLogLog'):
        """
        Merge another HyperLogLog into this one.
        Takes maximum value for each register (union operation).
        """
        if self.precision != other.precision:
            raise ValueError("Cannot merge HyperLogLogs with different precision")
        
        for i in range(self.m):
            self.registers[i] = max(self.registers[i], other.registers[i])
    
    def get_memory_usage(self) -> int:
        """Return approximate memory usage in bytes."""
        # Each register is roughly 1 byte (stores 0-64)
        return self.m
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary."""
        return {
            'precision': self.precision,
            'registers': self.registers
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'HyperLogLog':
        """Deserialize from dictionary."""
        hll = cls(precision=data['precision'])
        hll.registers = data['registers']
        return hll


class HLLAggregator:
    """
    Network flow aggregator using HyperLogLog.
    Tracks unique IPs, ports, and connections for anomaly detection.
    """
    
    def __init__(self, precision: int = 14):
        """
        Initialize HLL aggregator.
        
        Args:
            precision: HyperLogLog precision (14 recommended)
        """
        # Track different cardinalities
        self.unique_src_ips = HyperLogLog(precision)
        self.unique_dst_ips = HyperLogLog(precision)
        self.unique_src_ports = HyperLogLog(precision)
        self.unique_dst_ports = HyperLogLog(precision)
        self.unique_flows = HyperLogLog(precision)
        
        # Per-IP tracking for scan detection
        self.src_to_dst_ports = {}  # src_ip -> HLL of dst ports (scan detection)
        self.dst_to_src_ips = {}    # dst_port -> HLL of src IPs (service popularity)
        
        # Keep basic counters
        self.total_flows = 0
        self.total_bytes = 0
        self.total_packets = 0
    
    def add_flow(self, flow_record: Dict):
        """
        Add flow record to aggregator.
        
        Args:
            flow_record: Dictionary with flow information
        """
        src_ip = flow_record['src_ip']
        dst_ip = flow_record['dst_ip']
        src_port = str(flow_record['src_port'])
        dst_port = str(flow_record['dst_port'])
        protocol = flow_record['protocol']
        
        # Add to global HLLs
        self.unique_src_ips.add(src_ip)
        self.unique_dst_ips.add(dst_ip)
        self.unique_src_ports.add(src_port)
        self.unique_dst_ports.add(dst_port)
        
        # Track unique flows
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        self.unique_flows.add(flow_key)
        
        # Port scan detection: track unique dst ports per src IP
        if src_ip not in self.src_to_dst_ports:
            self.src_to_dst_ports[src_ip] = HyperLogLog(precision=12)  # Smaller precision
        self.src_to_dst_ports[src_ip].add(dst_port)
        
        # Service popularity: track unique src IPs per dst port
        if dst_port not in self.dst_to_src_ips:
            self.dst_to_src_ips[dst_port] = HyperLogLog(precision=12)
        self.dst_to_src_ips[dst_port].add(src_ip)
        
        # Update counters
        self.total_flows += 1
        self.total_bytes += flow_record['byte_count']
        self.total_packets += flow_record['packet_count']
    
    def get_cardinalities(self) -> Dict[str, int]:
        """Get estimated unique counts for all tracked metrics."""
        return {
            'unique_src_ips': self.unique_src_ips.count(),
            'unique_dst_ips': self.unique_dst_ips.count(),
            'unique_src_ports': self.unique_src_ports.count(),
            'unique_dst_ports': self.unique_dst_ports.count(),
            'unique_flows': self.unique_flows.count()
        }
    
    def detect_port_scanners(self, threshold: int = 50) -> List[tuple]:
        """
        Detect potential port scanners.
        
        Args:
            threshold: Minimum unique dst ports to flag as scanner
        
        Returns:
            List of (src_ip, unique_dst_ports_count) tuples
        """
        scanners = []
        for src_ip, hll in self.src_to_dst_ports.items():
            unique_ports = hll.count()
            if unique_ports >= threshold:
                scanners.append((src_ip, unique_ports))
        
        scanners.sort(key=lambda x: x[1], reverse=True)
        return scanners
    
    def get_popular_services(self, top_n: int = 10) -> List[tuple]:
        """
        Get most popular services by unique client count.
        
        Args:
            top_n: Number of top services to return
        
        Returns:
            List of (dst_port, unique_clients_count) tuples
        """
        services = []
        for dst_port, hll in self.dst_to_src_ips.items():
            unique_clients = hll.count()
            services.append((dst_port, unique_clients))
        
        services.sort(key=lambda x: x[1], reverse=True)
        return services[:top_n]
    
    def get_network_diversity_score(self) -> float:
        """
        Calculate network diversity score (0-1).
        Higher = more diverse communication patterns.
        
        Formula: (unique_src_ips + unique_dst_ips) / (2 * unique_flows)
        """
        cardinalities = self.get_cardinalities()
        if cardinalities['unique_flows'] == 0:
            return 0.0
        
        diversity = (cardinalities['unique_src_ips'] + 
                    cardinalities['unique_dst_ips']) / (2 * cardinalities['unique_flows'])
        return min(diversity, 1.0)
    
    def get_summary(self) -> Dict:
        """Generate summary statistics."""
        cardinalities = self.get_cardinalities()
        
        return {
            'type': 'hyperloglog',
            'cardinalities': cardinalities,
            'total_flows': self.total_flows,
            'total_bytes': self.total_bytes,
            'total_packets': self.total_packets,
            'diversity_score': self.get_network_diversity_score(),
            'memory_bytes': self.get_memory_usage(),
            'tracked_src_ips': len(self.src_to_dst_ports),
            'tracked_services': len(self.dst_to_src_ips)
        }
    
    def get_memory_usage(self) -> int:
        """Total memory usage of all HLLs."""
        base_memory = (self.unique_src_ips.get_memory_usage() +
                      self.unique_dst_ips.get_memory_usage() +
                      self.unique_src_ports.get_memory_usage() +
                      self.unique_dst_ports.get_memory_usage() +
                      self.unique_flows.get_memory_usage())
        
        # Add per-IP/port HLLs (precision 12 = 4KB each)
        per_ip_memory = len(self.src_to_dst_ports) * 4096
        per_port_memory = len(self.dst_to_src_ips) * 4096
        
        return base_memory + per_ip_memory + per_port_memory
    
    def merge(self, other: 'HLLAggregator'):
        """Merge another aggregator into this one."""
        self.unique_src_ips.merge(other.unique_src_ips)
        self.unique_dst_ips.merge(other.unique_dst_ips)
        self.unique_src_ports.merge(other.unique_src_ports)
        self.unique_dst_ports.merge(other.unique_dst_ports)
        self.unique_flows.merge(other.unique_flows)
        
        # Merge per-IP tracking
        for src_ip, hll in other.src_to_dst_ports.items():
            if src_ip in self.src_to_dst_ports:
                self.src_to_dst_ports[src_ip].merge(hll)
            else:
                self.src_to_dst_ports[src_ip] = hll
        
        for dst_port, hll in other.dst_to_src_ips.items():
            if dst_port in self.dst_to_src_ips:
                self.dst_to_src_ips[dst_port].merge(hll)
            else:
                self.dst_to_src_ips[dst_port] = hll
        
        self.total_flows += other.total_flows
        self.total_bytes += other.total_bytes
        self.total_packets += other.total_packets
    
    def export(self) -> Dict:
        """Export complete state for serialization."""
        # Export per-IP HLLs
        src_to_dst_ports_export = {
            ip: hll.to_dict() for ip, hll in self.src_to_dst_ports.items()
        }
        dst_to_src_ips_export = {
            port: hll.to_dict() for port, hll in self.dst_to_src_ips.items()
        }
        
        return {
            'type': 'hll_aggregator',
            'unique_src_ips': self.unique_src_ips.to_dict(),
            'unique_dst_ips': self.unique_dst_ips.to_dict(),
            'unique_src_ports': self.unique_src_ports.to_dict(),
            'unique_dst_ports': self.unique_dst_ports.to_dict(),
            'unique_flows': self.unique_flows.to_dict(),
            'src_to_dst_ports': src_to_dst_ports_export,
            'dst_to_src_ips': dst_to_src_ips_export,
            'total_flows': self.total_flows,
            'total_bytes': self.total_bytes,
            'total_packets': self.total_packets,
            'summary': self.get_summary()
        }
    
    @classmethod
    def from_export(cls, data: Dict) -> 'HLLAggregator':
        """Reconstruct aggregator from exported data."""
        precision = data['unique_src_ips']['precision']
        aggregator = cls(precision)
        
        aggregator.unique_src_ips = HyperLogLog.from_dict(data['unique_src_ips'])
        aggregator.unique_dst_ips = HyperLogLog.from_dict(data['unique_dst_ips'])
        aggregator.unique_src_ports = HyperLogLog.from_dict(data['unique_src_ports'])
        aggregator.unique_dst_ports = HyperLogLog.from_dict(data['unique_dst_ports'])
        aggregator.unique_flows = HyperLogLog.from_dict(data['unique_flows'])
        
        # Reconstruct per-IP tracking
        for ip, hll_data in data['src_to_dst_ports'].items():
            aggregator.src_to_dst_ports[ip] = HyperLogLog.from_dict(hll_data)
        
        for port, hll_data in data['dst_to_src_ips'].items():
            aggregator.dst_to_src_ips[port] = HyperLogLog.from_dict(hll_data)
        
        aggregator.total_flows = data['total_flows']
        aggregator.total_bytes = data['total_bytes']
        aggregator.total_packets = data['total_packets']
        
        return aggregator


if __name__ == "__main__":
    # Example usage
    import json
    
    aggregator = HLLAggregator(precision=14)
    
    # Simulate normal traffic
    for i in range(100):
        aggregator.add_flow({
            'src_ip': f'192.168.1.{10 + i % 20}',
            'dst_ip': f'8.8.8.{i % 10}',
            'src_port': 50000 + i,
            'dst_port': 443,
            'protocol': 'TCP',
            'packet_count': 50,
            'byte_count': 25000
        })
    
    # Simulate port scanner
    for port in range(1, 101):
        aggregator.add_flow({
            'src_ip': '10.0.0.66',
            'dst_ip': '192.168.1.100',
            'src_port': 60000,
            'dst_port': port,
            'protocol': 'TCP',
            'packet_count': 1,
            'byte_count': 64
        })
    
    # Get cardinalities
    print("Cardinality Estimates:")
    cardinalities = aggregator.get_cardinalities()
    print(json.dumps(cardinalities, indent=2))
    
    # Detect port scanners
    print("\nPotential Port Scanners:")
    scanners = aggregator.detect_port_scanners(threshold=20)
    for ip, ports in scanners:
        print(f"  {ip}: contacted {ports} unique ports")
    
    # Popular services
    print("\nPopular Services:")
    services = aggregator.get_popular_services(top_n=5)
    for port, clients in services:
        print(f"  Port {port}: {clients} unique clients")
    
    # Summary
    print(f"\nSummary:")
    summary = aggregator.get_summary()
    print(json.dumps(summary, indent=2))