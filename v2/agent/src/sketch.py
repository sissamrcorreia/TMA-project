"""
Probabilistic Data Structures
=============================

This module implements Probabilistic Data Structures (Sketches) for efficient
network traffic cardinality estimation and heavy hitter detection.

Classes:
    CountMinSketch: Estimates frequency of events (for Heavy Hitters).
    HyperLogLog: Estimates cardinality (unique elements) of a set.
"""

import hashlib
import math
import struct
import heapq

class CountMinSketch:
    """
    Count-Min Sketch implementation for frequency estimation.
    Used to track heavy hitters (top talkers) by bytes or packets with fixed memory usage.
    """
    def __init__(self, width=2048, depth=5):
        """
        Initializes the CMS.

        Args:
            width (int): Number of counters per row (affects error rate).
            depth (int): Number of hash functions (affects confidence).
        """
        self.width = width
        self.depth = depth
        self.table = [[0] * width for _ in range(depth)]
        self.total_count = 0
        self.total_bytes = 0
        self.seeds = [i * 101 for i in range(depth)] # Simple seeding

    def _hash(self, key, seed):
        # Using sha256 with seed for valid distribution
        # In production, mmh3 is preferred for speed
        if isinstance(key, str):
            key = key.encode()
        h = hashlib.md5(key + str(seed).encode()).digest()
        # Take first 4 bytes as int
        val = struct.unpack("I", h[:4])[0]
        return val % self.width

    def update(self, key, count=1):
        self.total_count += count # Packets or arbitrary count
        self.total_bytes += count # Assuming calling with bytes
        
        for i in range(self.depth):
            idx = self._hash(key, self.seeds[i])
            self.table[i][idx] += count
            
    def estimate(self, key):
        min_est = float('inf')
        for i in range(self.depth):
            idx = self._hash(key, self.seeds[i])
            min_est = min(min_est, self.table[i][idx])
        return min_est

    def get_heavy_hitters(self, candidates, top_k=20):
        """
        Identifies heavy hitters from a list of candidate keys.
        
        Since CMS is not reversible, it requires a stream of candidate keys 
        (sourced here from the exact BPF map deltas) to query the sketch.

        Args:
            candidates (dict): Dictionary of {flow_id: exact_data}.
            top_k (int): Number of top flows to return.

        Returns:
            list: Top k heavy hitters formatted as dictionaries.
        """
        # Since CMS is not reversible, we need a list of candidates to query.
        # In our case, the BPF map provides the exact list of candidates for this batch.
        heap = []
        for key, exact_val in candidates.items():
            # We can use the sketch estimate or the exact value from BPF. 
            # Using exact value from BPF is better for accuracy in this context,
            # but using Estimate validates the Sketch.
            # For the purpose of the output, let's return the exact BPF value
            # properly formatted, as that is the ground truth.
            
            # However, if the requirement is to use CMS estimate:
            est = self.estimate(key)
            heapq.heappush(heap, (est, key))
            if len(heap) > top_k:
                heapq.heappop(heap)
        
        # Sort desc
        result = sorted(heap, key=lambda x: x[0], reverse=True)
        return [{"flow": k, "bytes": v} for v, k in result]

class HyperLogLog:
    """
    HyperLogLog implementation for cardinality estimation.
    Used to count unique source IPs and flows with minimal memory.
    """
    def __init__(self, p=12):
        """
        Args:
            p (int): Precision parameter. Registers = 2^p.
        """
        self.p = p # Precision bits (registers = 2^p)
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.tracked_src_ips = set()
        self.tracked_services = set()
        self.unique_src_ports = set()
        self.unique_dst_ports = set()

    def _get_alpha(self):
        if self.p == 4: return 0.673
        if self.p == 5: return 0.697
        if self.p == 6: return 0.709
        return 0.7213 / (1 + 1.079 / self.m)

    def _hash(self, key):
        if isinstance(key, str):
            key = key.encode()
        h = hashlib.sha1(key).digest()
        # Return 64-bit int
        return struct.unpack("Q", h[:8])[0]

    def _rho(self, w):
        # find position of first 1
        # w is 64-bit int. mask p bits.
        # implementation simplified
        return (w & -w).bit_length() if w > 0 else 64

    def update(self, key):
        x = self._hash(key)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def count(self):
        E = self.alpha * (self.m ** 2) / sum(2.0 ** -reg for reg in self.registers)
        # Corrections
        if E <= 2.5 * self.m:
            V = self.registers.count(0)
            if V > 0:
                E = self.m * math.log(self.m / V)
        return int(E)
    
    # Helpers for the specific JSON output structure
    def track_metadata(self, src_ip, dst_ip, src_port, dst_port):
        self.tracked_src_ips.add(src_ip)
        self.tracked_services.add(f"{dst_port}")
        self.unique_src_ports.add(src_port)
        self.unique_dst_ports.add(dst_port)

    def get_cardinalities(self):
        return {
            "unique_src_ips": len(self.tracked_src_ips),
            "unique_src_ports": len(self.unique_src_ports),
            "unique_dst_ports": len(self.unique_dst_ports),
            "unique_flows": self.count()
        }
