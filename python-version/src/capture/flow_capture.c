#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#define ETHERNET_HEADER_SIZE 14
#define SNAPLEN 74
#define FLOW_TABLE_SIZE 10000
#define EXPORT_INTERVAL 30  // Export flows every 60 seconds

/* Flow key structure (5-tuple) */
typedef struct {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_key_t;

/* Flow record with statistics */
typedef struct {
    flow_key_t key;
    uint64_t packet_count;
    uint64_t byte_count;
    time_t first_seen;
    time_t last_seen;
    int active;
} flow_record_t;

/* Global flow table */
flow_record_t flow_table[FLOW_TABLE_SIZE];
int flow_count = 0;
time_t last_export_time;
pcap_t *global_handle = NULL;

/* Function prototypes */
void export_flows();
void signal_handler(int signum);
int find_or_create_flow(flow_key_t *key);
void update_flow(int index, uint32_t packet_len, time_t timestamp);

/* Signal handler for graceful shutdown */
void signal_handler(int signum) {
    printf("\nCaught signal %d, exporting flows and exiting...\n", signum);
    export_flows();
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
    exit(0);
}

/* Find existing flow or create new one */
int find_or_create_flow(flow_key_t *key) {
    // Search for existing flow
    for (int i = 0; i < flow_count; i++) {
        if (flow_table[i].active &&
            strcmp(flow_table[i].key.src_ip, key->src_ip) == 0 &&
            strcmp(flow_table[i].key.dst_ip, key->dst_ip) == 0 &&
            flow_table[i].key.src_port == key->src_port &&
            flow_table[i].key.dst_port == key->dst_port &&
            flow_table[i].key.protocol == key->protocol) {
            return i;
        }
    }
    
    // Create new flow if space available
    if (flow_count < FLOW_TABLE_SIZE) {
        int index = flow_count++;
        memcpy(&flow_table[index].key, key, sizeof(flow_key_t));
        flow_table[index].packet_count = 0;
        flow_table[index].byte_count = 0;
        flow_table[index].active = 1;
        return index;
    }
    
    return -1; // Table full
}

/* Update flow statistics */
void update_flow(int index, uint32_t packet_len, time_t timestamp) {
    if (index >= 0 && index < flow_count) {
        flow_table[index].packet_count++;
        flow_table[index].byte_count += packet_len;
        
        if (flow_table[index].packet_count == 1) {
            flow_table[index].first_seen = timestamp;
        }
        flow_table[index].last_seen = timestamp;
    }
}

/* Export flows to stdout (later can be sent to aggregation layer) */
void export_flows() {
    printf("\n========== FLOW EXPORT ==========\n");
    printf("Timestamp: %ld\n", time(NULL));
    printf("Active Flows: %d\n", flow_count);
    printf("=================================\n");
    
    for (int i = 0; i < flow_count; i++) {
        if (flow_table[i].active && flow_table[i].packet_count > 0) {
            printf("Flow %d:\n", i);
            printf("  %s:%u -> %s:%u\n",
                   flow_table[i].key.src_ip,
                   flow_table[i].key.src_port,
                   flow_table[i].key.dst_ip,
                   flow_table[i].key.dst_port);
            printf("  Protocol: %s\n", 
                   flow_table[i].key.protocol == IPPROTO_TCP ? "TCP" : "UDP");
            printf("  Packets: %lu, Bytes: %lu\n",
                   flow_table[i].packet_count,
                   flow_table[i].byte_count);
            printf("  Duration: %ld seconds\n",
                   flow_table[i].last_seen - flow_table[i].first_seen);
            printf("  First seen: %ld, Last seen: %ld\n",
                   flow_table[i].first_seen,
                   flow_table[i].last_seen);
            printf("---\n");
        }
    }
    printf("=================================\n\n");
    
    // Reset flow table after export
    memset(flow_table, 0, sizeof(flow_table));
    flow_count = 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct ip6_hdr *ip6_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    flow_key_t flow_key;
    int ip_header_len = 0;
    int is_ipv6 = 0;
    uint8_t protocol;
    
    // Check if it's time to export flows
    time_t current_time = header->ts.tv_sec;
    if (current_time - last_export_time >= EXPORT_INTERVAL) {
        export_flows();
        last_export_time = current_time;
    }
    
    // Extract Ethernet header
    eth_header = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth_header->ether_type);
    
    // Parse IP header (IPv4 or IPv6)
    if (ether_type == ETHERTYPE_IP) {
        // IPv4 packet
        is_ipv6 = 0;
        ip_header = (struct ip*)(packet + ETHERNET_HEADER_SIZE);
        protocol = ip_header->ip_p;
        
        // Only process TCP and UDP
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return;
        }
        
        ip_header_len = ip_header->ip_hl * 4;
        
        // Extract IP addresses
        inet_ntop(AF_INET, &(ip_header->ip_src), flow_key.src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), flow_key.dst_ip, INET6_ADDRSTRLEN);
        
    } else if (ether_type == ETHERTYPE_IPV6) {
        // IPv6 packet
        is_ipv6 = 1;
        ip6_header = (struct ip6_hdr*)(packet + ETHERNET_HEADER_SIZE);
        protocol = ip6_header->ip6_nxt;
        
        // Only process TCP and UDP
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return;
        }
        
        ip_header_len = 40;
        
        // Extract IP addresses
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), flow_key.src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), flow_key.dst_ip, INET6_ADDRSTRLEN);
        
    } else {
        return;
    }
    
    flow_key.protocol = protocol;
    
    // Extract port information based on protocol
    if (protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
        flow_key.src_port = ntohs(tcp_header->th_sport);
        flow_key.dst_port = ntohs(tcp_header->th_dport);
    } else if (protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
        flow_key.src_port = ntohs(udp_header->uh_sport);
        flow_key.dst_port = ntohs(udp_header->uh_dport);
    }
    
    // Find or create flow and update statistics
    int flow_index = find_or_create_flow(&flow_key);
    if (flow_index >= 0) {
        update_flow(flow_index, header->len, current_time);
    } else {
        fprintf(stderr, "Warning: Flow table full, dropping flow\n");
    }
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 net;
    bpf_u_int32 mask;
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize flow table
    memset(flow_table, 0, sizeof(flow_table));
    last_export_time = time(NULL);
    
    // Find capture device
    if (argc >= 2) {
        device = argv[1];
    } else {
        if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", error_buffer);
            return 2;
        }
        
        for (d = alldevs; d != NULL; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK)
                continue;
            device = d->name;
            break;
        }
        
        if (device == NULL) {
            if (alldevs != NULL) {
                device = alldevs->name;
            } else {
                fprintf(stderr, "No devices found\n");
                return 2;
            }
        }
        
        device = strdup(device);
        pcap_freealldevs(alldevs);
    }
    
    printf("Decentralized Flow Monitoring Agent\n");
    printf("====================================\n");
    printf("Capturing on device: %s\n", device);
    printf("Filter: %s\n", filter_exp);
    printf("Flow export interval: %d seconds\n", EXPORT_INTERVAL);
    printf("Supports: IPv4 and IPv6, TCP and UDP\n");
    printf("====================================\n\n");
    
    // Get network info
    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
        fprintf(stderr, "Warning: Couldn't get netmask for device %s: %s\n", device, error_buffer);
        net = 0;
        mask = 0;
    }
    
    // Open capture session
    global_handle = pcap_open_live(device, SNAPLEN, 1, 1000, error_buffer);
    if (global_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
        if (argc < 2) free(device);
        return 2;
    }
    
    // Compile and apply filter
    if (pcap_compile(global_handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(global_handle));
        if (argc < 2) free(device);
        return 2;
    }
    
    if (pcap_setfilter(global_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(global_handle));
        if (argc < 2) free(device);
        return 2;
    }
    
    // Start capturing packets
    pcap_loop(global_handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_freecode(&fp);
    pcap_close(global_handle);
    if (argc < 2) free(device);
    
    return 0;
}