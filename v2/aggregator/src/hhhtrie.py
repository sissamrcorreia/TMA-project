"""
Hierarchical Heavy Hitter (HHH) Trie
====================================

This module implements a binary Prefix Trie to efficiently aggregate and identify
heavy hitter subnets (CIDR prefixes) from IP traffic data. It supports hierarchical
queries to find significant traffic sources at various network levels (e.g., /8, /16, /24).
"""

import socket
import struct

class TrieNode:
    """
    Represents a single node in the binary Prefix Trie.
    """
    def __init__(self):
        self.children = {}  # Keys are '0' or '1'
        self.total_bytes = 0

class HHHTrie:
    """
    Hierarchical Heavy Hitter Trie.
    
    Stores IP traffic counts in a binary tree structure to allow efficient
    querying of traffic volumes at any subnet level (Prefix).
    """
    def __init__(self):
        self.root = TrieNode()

    def _ip_to_binary(self, ip):
        """
        Helper: Converts IPv4 string to 32-bit binary string.
        
        Args:
            ip (str): e.g., '10.0.0.5'
            
        Returns:
            str: e.g., '00001010000000000000000000000101'
        """
        try:
            packed = socket.inet_aton(ip)
            int_ip = struct.unpack("!I", packed)[0]
            return f"{int_ip:032b}"
        except OSError:
            return None

    def insert(self, ip, byte_count):
        """
        Updates the Trie with traffic volume for a specific IP.
        The byte count is propagated (summed) from the root down to the leaf.
        
        Args:
            ip (str): Destination IP.
            byte_count (int): Volume of bytes to add.
        """
        binary_ip = self._ip_to_binary(ip)
        if not binary_ip:
            print(f"TRIE ERROR: Could not convert IP {ip}")
            return

        node = self.root
        # 1. Update the Root (Global traffic)
        node.total_bytes += byte_count

        # 2. Traverse down, creating nodes if needed and updating counts
        for bit in binary_ip:
            if bit not in node.children:
                node.children[bit] = TrieNode()
            
            node = node.children[bit]
            node.total_bytes += byte_count

    def get_heavy_hitters(self, threshold):
        """
        Identifies all prefixes (nodes) that have exceeded the byte threshold.
        
        Args:
            threshold (int): The byte count threshold for a node to be considered a heavy hitter.
            
        Returns:
            list: A list of dictionaries containing {prefix, parent, bytes} for visualizations.
        """
        results = []
        print(f"TRIE DEBUG: Root Total Bytes: {self.root.total_bytes}. Threshold: {threshold}")
        
        # Start recursion. Root is always emitted (or implied).
        self._find_culprits(self.root, "", threshold, results, last_emitted_parent="")
        
        if len(results) == 0:
             print("TRIE DEBUG: No heavy hitters found.")
        else:
             print(f"TRIE DEBUG: Found {len(results)} heavy hitters.")
             
        return results

    def _find_culprits(self, node, current_prefix_bits, threshold, results, last_emitted_parent):
        """
        Recursive helper with Smart Pruning (Collapsing redundant layers).
        
        Args:
            node: Current TrieNode
            current_prefix_bits: Binary string path to this node
            threshold: Byte limit
            results: List to append to
            last_emitted_parent: The CIDR string of the nearest ancestor that was actually output. 
                                 This ensures children link back to a valid node, preventing orphans.
        """
        if node.total_bytes < threshold:
            return

        current_cidr = self._bits_to_ip_cidr(current_prefix_bits)
        mask_len = len(current_prefix_bits)

        # --- VISUALIZATION POLICY: STRICT MAJOR TIERS ---
        # To prevent "Too Many Prefixes" clutter (e.g., /19, /21 nodes from binary structure),
        # we ONY emission key network boundaries: /0, /8, /16, /24, /32.
        
        # Default: Treat node as "structural/hidden" (redundant)
        is_redundant = True

        # Rule 1: Always Show Major Tiers
        if (mask_len % 8 == 0) or (mask_len == 32):
            is_redundant = False

        # Rule 2: Exception for Root
        if mask_len == 0: 
            is_redundant = False
        
        # --- DECISION ---
        next_parent = last_emitted_parent
        
        if not is_redundant:
            # EMIT NODE
            results.append({
                "prefix": current_cidr,
                "parent": last_emitted_parent, # Link to nearest Major Tier ancestor
                "bytes": node.total_bytes
            })
            next_parent = current_cidr 
        else:
            # SKIP NODE (Prune)
            # We recurse, but pass 'last_emitted_parent' through.
            # This effectively "collapses" the intermediate binary layers.
            pass

        # 2. Recurse children
        for bit, child_node in node.children.items():
            self._find_culprits(child_node, current_prefix_bits + bit, threshold, results, next_parent)

    def _bits_to_ip_cidr(self, bits):
        """
        Helper: Converts binary path string back to 'IP/CIDR' format.
        
        Args:
            bits (str): e.g., '00001010'
            
        Returns:
            str: e.g., '10.0.0.0/8'
        """
        length = len(bits)
        # Pad with 0s to reach 32 bits for reconstruction
        padded_bits = bits + ('0' * (32 - length))
        
        ip_int = int(padded_bits, 2)
        ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
        
        return f"{ip_str}/{length}"