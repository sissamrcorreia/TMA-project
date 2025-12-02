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
#include <sys/stat.h>

#define ETHERNET_HEADER_SIZE 14
#define SNAPLEN 74
#define FLOW_TABLE_SIZE 10000
#define EXPORT_INTERVAL 30  // Export flows every 30 seconds
#define OUTPUT_DIR "output/flows"
#define OUTPUT_FILE "output/flows/current_flows.json"

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
int warned_table_full = 0; // Flag to prevent console spam
time_t last_export_time;
pcap_t *global_handle = NULL;

/* Function prototypes */
void export_flows_json();
void signal_handler(int signum);
int find_or_create_flow(flow_key_t *key);
void update_flow(int index, uint32_t packet_len, time_t timestamp);
void create_output_directory();

/* Create output directory if it doesn't exist */
void create_output_directory() {
    struct stat st = {0};
    if (stat(OUTPUT_DIR, &st) == -1) {
        mkdir(OUTPUT_DIR, 0755);
    }
}

/* Signal handler for graceful shutdown */
void signal_handler(int signum) {
    printf("\nCaught signal %d, exporting flows and exiting...\n", signum);
    export_flows_json();
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
    exit(0);
}

/* Find existing flow or create new one */
int find_or_create_flow(flow_key_t *key) {
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
    
    if (flow_count < FLOW_TABLE_SIZE) {
        int index = flow_count++;
        memcpy(&flow_table[index].key, key, sizeof(flow_key_t));
        flow_table[index].packet_count = 0;
        flow_table[index].byte_count = 0;
        flow_table[index].active = 1;
        return index;
    } else {
        // Warn only once per interval if table is full
        if (!warned_table_full) {
            fprintf(stderr, "\n[WARNING] Flow table full (%d flows)! Dropping new flows.\n", FLOW_TABLE_SIZE);
            warned_table_full = 1;
        }
    }
    
    return -1;
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

/* Export flows to JSON file */
void export_flows_json() {
    FILE *fp;
    char temp_file[256];
    time_t current_time = time(NULL);
    
    // Write to temporary file first (atomic operation)
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", OUTPUT_FILE);
    
    fp = fopen(temp_file, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error: Cannot open output file %s\n", temp_file);
        return;
    }
    
    // Write JSON header
    fprintf(fp, "{\n");
    fprintf(fp, "  \"timestamp\": %ld,\n", current_time);
    fprintf(fp, "  \"flow_count\": %d,\n", flow_count);
    fprintf(fp, "  \"flows\": [\n");
    
    // Write flows
    int first = 1;
    for (int i = 0; i < flow_count; i++) {
        if (flow_table[i].active && flow_table[i].packet_count > 0) {
            if (!first) {
                fprintf(fp, ",\n");
            }
            first = 0;
            
            fprintf(fp, "    {\n");
            fprintf(fp, "      \"src_ip\": \"%s\",\n", flow_table[i].key.src_ip);
            fprintf(fp, "      \"dst_ip\": \"%s\",\n", flow_table[i].key.dst_ip);
            fprintf(fp, "      \"src_port\": %u,\n", flow_table[i].key.src_port);
            fprintf(fp, "      \"dst_port\": %u,\n", flow_table[i].key.dst_port);
            fprintf(fp, "      \"protocol\": \"%s\",\n", 
                    flow_table[i].key.protocol == IPPROTO_TCP ? "TCP" : "UDP");
            fprintf(fp, "      \"packet_count\": %lu,\n", flow_table[i].packet_count);
            fprintf(fp, "      \"byte_count\": %lu,\n", flow_table[i].byte_count);
            fprintf(fp, "      \"first_seen\": %ld,\n", flow_table[i].first_seen);
            fprintf(fp, "      \"last_seen\": %ld\n", flow_table[i].last_seen);
            fprintf(fp, "    }");
        }
    }
    
    // Write JSON footer
    fprintf(fp, "\n  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    
    // Atomic rename (prevents reading partial files)
    rename(temp_file, OUTPUT_FILE);
    
    printf("[%ld] Exported %d flows to %s\n", current_time, flow_count, OUTPUT_FILE);
    
    // Reset flow table and warning flag after export
    memset(flow_table, 0, sizeof(flow_table));
    flow_count = 0;
    warned_table_full = 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct ip6_hdr *ip6_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    flow_key_t flow_key;
    int ip_header_len = 0;
    uint8_t protocol;
    
    time_t current_time = header->ts.tv_sec;
    if (current_time - last_export_time >= EXPORT_INTERVAL) {
        export_flows_json();
        last_export_time = current_time;
    }
    
    eth_header = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth_header->ether_type);
    
    if (ether_type == ETHERTYPE_IP) {
        ip_header = (struct ip*)(packet + ETHERNET_HEADER_SIZE);
        protocol = ip_header->ip_p;
        
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return;
        }
        
        ip_header_len = ip_header->ip_hl * 4;
        inet_ntop(AF_INET, &(ip_header->ip_src), flow_key.src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), flow_key.dst_ip, INET6_ADDRSTRLEN);
        
    } else if (ether_type == ETHERTYPE_IPV6) {
        ip6_header = (struct ip6_hdr*)(packet + ETHERNET_HEADER_SIZE);
        protocol = ip6_header->ip6_nxt;
        
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return;
        }
        
        ip_header_len = 40;
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), flow_key.src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), flow_key.dst_ip, INET6_ADDRSTRLEN);
        
    } else {
        return;
    }
    
    flow_key.protocol = protocol;
    
    if (protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
        flow_key.src_port = ntohs(tcp_header->th_sport);
        flow_key.dst_port = ntohs(tcp_header->th_dport);
    } else if (protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
        flow_key.src_port = ntohs(udp_header->uh_sport);
        flow_key.dst_port = ntohs(udp_header->uh_dport);
    }
    
    int flow_index = find_or_create_flow(&flow_key);
    if (flow_index >= 0) {
        update_flow(flow_index, header->len, current_time);
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
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    create_output_directory();
    memset(flow_table, 0, sizeof(flow_table));
    last_export_time = time(NULL);
    
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
    
    printf("Decentralized Flow Monitoring Agent (JSON Mode)\n");
    printf("================================================\n");
    printf("Capturing on device: %s\n", device);
    printf("Flow export interval: %d seconds\n", EXPORT_INTERVAL);
    printf("Output file: %s\n", OUTPUT_FILE);
    printf("================================================\n\n");
    
    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
        net = 0;
        mask = 0;
    }
    
    global_handle = pcap_open_live(device, SNAPLEN, 1, 1000, error_buffer);
    if (global_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
        if (argc < 2) free(device);
        return 2;
    }
    
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
    
    pcap_loop(global_handle, 0, packet_handler, NULL);
    
    pcap_freecode(&fp);
    pcap_close(global_handle);
    if (argc < 2) free(device);
    
    return 0;
}