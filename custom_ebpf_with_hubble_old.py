#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct
import socket
import struct
import time
import argparse
import signal
import sys
import os
import psutil
from datetime import datetime
from collections import defaultdict
import hashlib
import pandas as pd
import numpy as np
import threading
import json
import subprocess

# Feature aggregation window (seconds)
AGGREGATION_WINDOW = 5.0

# Check if Hubble libraries are available
HUBBLE_AVAILABLE = True
try:
    import grpc
    from google.protobuf import json_format
except ImportError:
    HUBBLE_AVAILABLE = False

# Network telemetry event structure
class NetworkTelemetry(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("ifindex", ct.c_uint32),
        ("src_mac", ct.c_uint8 * 6),
        ("dst_mac", ct.c_uint8 * 6),
        ("vlan_id", ct.c_uint16),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("ip_ttl", ct.c_uint8),
        ("ip_tos", ct.c_uint8),
        ("ip_flags", ct.c_uint16),
        ("ip_frag_offset", ct.c_uint16),
        ("ip_total_len", ct.c_uint16),
        ("ip_id", ct.c_uint16),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("protocol", ct.c_uint8),
        ("tcp_flags", ct.c_uint8),
        ("tcp_seq", ct.c_uint32),
        ("tcp_ack", ct.c_uint32),
        ("tcp_window", ct.c_uint16),
        ("conn_state", ct.c_uint8),
        ("retransmission", ct.c_uint8),
        ("payload_size", ct.c_uint32),
        ("packet_size", ct.c_uint32),
        ("error_flags", ct.c_uint32),
        ("l7_protocol", ct.c_uint8),
        ("l7_payload", ct.c_uint8 * 64),
        ("icmp_type", ct.c_uint8),
        ("icmp_code", ct.c_uint8),
        ("dns_query_type", ct.c_uint16),
        ("dns_flags", ct.c_uint16),
        ("arp_op", ct.c_uint16),
    ]

# System health event structure (reduced - only eBPF-friendly metrics)
class SystemHealthEvent(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("event_type", ct.c_uint8),  # 2=Memory, 3=IO, 4=Process
        ("pid", ct.c_uint32),
        ("memory_alloc_bytes", ct.c_uint64),
        ("memory_free_bytes", ct.c_uint64),
        ("io_read_bytes", ct.c_uint64),
        ("io_write_bytes", ct.c_uint64),
        ("io_latency_us", ct.c_uint64),
        ("oom_score", ct.c_uint32),
        ("process_state", ct.c_uint8),  # 0=running, 1=zombie, 2=dead
        ("comm", ct.c_char * 16),
    ]

# Full eBPF program with network + system tracing
bpf_text = """
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
// Minimal includes to avoid kernel header conflicts
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/pkt_cls.h>

// Define structures we need without including problematic headers
struct tcphdr_min {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 flags;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct udphdr_min {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

struct icmphdr_min {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
    } un;
} __attribute__((packed));

#define ETH_P_ARP 0x0806
#define ETH_P_IP  0x0800
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

#define L7_UNKNOWN 0
#define L7_HTTP 1
#define L7_HTTPS 2
#define L7_DNS 3

#define CONN_NEW 1
#define CONN_ESTABLISHED 2
#define CONN_CLOSING 3

#define ERR_TTL_EXPIRED (1 << 1)
#define ERR_FRAGMENTED (1 << 2)
#define ERR_OUT_OF_ORDER (1 << 3)
#define ERR_RETRANSMISSION (1 << 4)
#define ERR_ZERO_WINDOW (1 << 5)
#define ERR_RST_RECEIVED (1 << 6)

#define DNS_PORT 53
#define HTTP_PORT 80
#define HTTPS_PORT 443

// Event types for system health (eBPF only tracks these)
#define EVENT_MEMORY 2
#define EVENT_IO 3
#define EVENT_PROCESS 4

struct network_telemetry {
    __u64 timestamp;
    __u32 ifindex;
    __u8 src_mac[6];
    __u8 dst_mac[6];
    __u16 vlan_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u8 ip_ttl;
    __u8 ip_tos;
    __u16 ip_flags;
    __u16 ip_frag_offset;
    __u16 ip_total_len;
    __u16 ip_id;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u16 tcp_window;
    __u8 conn_state;
    __u8 retransmission;
    __u32 payload_size;
    __u32 packet_size;
    __u32 error_flags;
    __u8 l7_protocol;
    __u8 l7_payload[64];
    __u8 icmp_type;
    __u8 icmp_code;
    __u16 dns_query_type;
    __u16 dns_flags;
    __u16 arp_op;
} __attribute__((packed));

struct system_health_event {
    __u64 timestamp;
    __u8 event_type;
    __u32 pid;
    __u64 memory_alloc_bytes;
    __u64 memory_free_bytes;
    __u64 io_read_bytes;
    __u64 io_write_bytes;
    __u64 io_latency_us;
    __u32 oom_score;
    __u8 process_state;
    char comm[16];
} __attribute__((packed));

BPF_PERF_OUTPUT(telemetry_events);
BPF_PERF_OUTPUT(system_events);

// IP blocklist for flood protection
// Source IPs exceeding rate threshold are added here and their packets are dropped
BPF_HASH(ip_blocklist, __u32, __u8, 1000);  // src_ip -> 1 (blocked)
BPF_HASH(ip_packet_count, __u32, __u64, 10000);  // src_ip -> packet count for flood detection

#define IP_RATE_WINDOW_NS 1000000000ULL  // 1 second
#define IP_FLOOD_THRESHOLD 500  // Threshold for blocking high-rate sources (packets per second)

struct ip_rate_tracker {
    __u64 last_reset;
    __u64 packet_count;
} __attribute__((packed));

BPF_HASH(ip_rate_map, __u32, struct ip_rate_tracker, 10000);

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct conn_state {
    __u32 last_seq;
    __u64 last_seen;
    __u8 state;
} __attribute__((packed));

BPF_HASH(connections, struct conn_key, struct conn_state, 50000);  // Increased for high-rate traffic

// Per-flow rate limiting to detect and drop flooding flows
struct flow_rate {
    __u64 last_reset_time;
    __u32 packet_count;
    __u8 is_flooding;  // 1 if flow is flooding, 0 otherwise
} __attribute__((packed));

BPF_HASH(flow_rate_limiter, struct conn_key, struct flow_rate, 50000);

#define RATE_LIMIT_WINDOW_NS 1000000000ULL  // 1 second window
#define RATE_LIMIT_THRESHOLD 500  // Max 500 packets/sec per flow before dropping

// SYN flood detection - per-source IP tracking
BPF_HASH(syn_flood_tracker, __u32, __u64, 10000);  // src_ip -> SYN count
BPF_HASH(dropped_flows, struct conn_key, __u64, 10000);  // Track dropped flooding flows

// Block I/O tracking (eBPF)
struct io_key {
    __u32 pid;
    __u64 sector;
} __attribute__((packed));

struct io_start {
    __u64 start_time;
    __u64 bytes;
} __attribute__((packed));

BPF_HASH(io_starts, struct io_key, struct io_start, 1024);

// ========== NETWORK TELEMETRY (same as before) ==========

static __always_inline __u8 detect_l7_protocol(__u16 src_port, __u16 dst_port, __u8 *payload, void *data_end, __u8 protocol)
{
    if ((src_port == DNS_PORT || dst_port == DNS_PORT) && protocol == PROTO_UDP) {
        return L7_DNS;
    }
    
    if (protocol != PROTO_TCP) {
        return L7_UNKNOWN;
    }
    
    if ((void *)(payload + 5) > data_end) {
        return L7_UNKNOWN;
    }
    
    if (dst_port == HTTP_PORT || src_port == HTTP_PORT) {
        if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') ||
            (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
            (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')) {
            return L7_HTTP;
        }
    }
    
    if (dst_port == HTTPS_PORT || src_port == HTTPS_PORT) {
        if ((void *)(payload + 6) > data_end) {
            return L7_HTTPS;
        }
        if (payload[0] == 0x16 && payload[1] == 0x03) {
            return L7_HTTPS;
        }
        return L7_HTTPS;
    }
    
    return L7_UNKNOWN;
}

static __always_inline int handle_tcp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct tcphdr_min *tcph = (void *)iph + (iph->ihl * 4);
    
    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // Extract TCP flags for SYN flood check
    __u16 tcp_flags_raw_check = tcph->flags;
    __u8 tcp_flags_check = (tcp_flags_raw_check >> 8) & 0xFF;
    __u8 syn_check = (tcp_flags_check & 0x02) ? 1 : 0;
    __u8 ack_check = (tcp_flags_check & 0x10) ? 1 : 0;
    
    // SYN flood tracking: Count SYNs separately
    if (syn_check && !ack_check) {
        __u32 src_ip = iph->saddr;
        __u64 *syn_count = syn_flood_tracker.lookup(&src_ip);
        
        if (syn_count) {
            __sync_fetch_and_add(syn_count, 1);
        } else {
            __u64 one = 1;
            syn_flood_tracker.update(&src_ip, &one);
        }
    }
    
    // Send full telemetry for all non-blocked packets
    struct network_telemetry t = {};
    t.timestamp = bpf_ktime_get_ns();
    t.ifindex = skb->ifindex;
    t.protocol = PROTO_TCP;
    
    __builtin_memcpy(t.src_mac, eth->h_source, 6);
    __builtin_memcpy(t.dst_mac, eth->h_dest, 6);
    
    t.src_ip = iph->saddr;
    t.dst_ip = iph->daddr;
    t.ip_ttl = iph->ttl;
    t.ip_tos = iph->tos;
    t.ip_total_len = bpf_ntohs(iph->tot_len);
    t.ip_id = bpf_ntohs(iph->id);
    
    t.src_port = bpf_ntohs(tcph->source);
    t.dst_port = bpf_ntohs(tcph->dest);
    
    // Extract TCP flags from the combined flags field
    __u16 tcp_flags_raw = tcph->flags;
    __u8 tcp_flags_byte = (tcp_flags_raw >> 8) & 0xFF;
    __u8 tcp_flags = 0;
    if (tcp_flags_byte & 0x02) tcp_flags |= 0x02;  // SYN
    if (tcp_flags_byte & 0x10) tcp_flags |= 0x10;  // ACK
    if (tcp_flags_byte & 0x01) tcp_flags |= 0x01;  // FIN
    if (tcp_flags_byte & 0x04) tcp_flags |= 0x04;  // RST
    if (tcp_flags_byte & 0x08) tcp_flags |= 0x08;  // PSH
    if (tcp_flags_byte & 0x20) tcp_flags |= 0x20;  // URG
    t.tcp_flags = tcp_flags;
    
    __u8 syn_flag = tcp_flags_byte & 0x02;
    __u8 ack_flag = tcp_flags_byte & 0x10;
    __u8 fin_flag = tcp_flags_byte & 0x01;
    __u8 rst_flag = tcp_flags_byte & 0x04;
    
    t.tcp_seq = bpf_ntohl(tcph->seq);
    t.tcp_ack = bpf_ntohl(tcph->ack_seq);
    t.tcp_window = bpf_ntohs(tcph->window);
    
    __u32 tcp_hdr_len = ((tcp_flags_raw >> 12) & 0x0F) * 4;  // Data offset is in lower nibble of flags
    __u32 ip_hdr_len = iph->ihl * 4;
    t.packet_size = t.ip_total_len;
    t.payload_size = t.ip_total_len - ip_hdr_len - tcp_hdr_len;
    
    t.error_flags = 0;
    
    if (t.ip_ttl < 5) {
        t.error_flags |= ERR_TTL_EXPIRED;
    }
    
    if (rst_flag) {
        t.error_flags |= ERR_RST_RECEIVED;
    }
    
    if (t.tcp_window == 0 && ack_flag) {
        t.error_flags |= ERR_ZERO_WINDOW;
    }
    
    struct conn_key key = {};
    key.src_ip = t.src_ip;
    key.dst_ip = t.dst_ip;
    key.src_port = t.src_port;
    key.dst_port = t.dst_port;
    key.protocol = PROTO_TCP;
    
    struct conn_state *state = connections.lookup(&key);
    struct conn_state new_state = {};
    
    if (state) {
        if (t.tcp_seq < state->last_seq && !syn_flag) {
            t.retransmission = 1;
            t.error_flags |= ERR_RETRANSMISSION;
        } else if (t.tcp_seq > state->last_seq + 1500) {
            t.error_flags |= ERR_OUT_OF_ORDER;
        }
        
        new_state.last_seq = t.tcp_seq;
        new_state.last_seen = t.timestamp;
        
        if (syn_flag && !ack_flag) {
            new_state.state = CONN_NEW;
        } else if (syn_flag && ack_flag) {
            new_state.state = CONN_NEW;
        } else if (fin_flag || rst_flag) {
            new_state.state = CONN_CLOSING;
        } else if (ack_flag) {
            new_state.state = CONN_ESTABLISHED;
        }
        
        t.conn_state = new_state.state;
    } else {
        new_state.last_seq = t.tcp_seq;
        new_state.last_seen = t.timestamp;
        new_state.state = syn_flag ? CONN_NEW : CONN_ESTABLISHED;
        t.conn_state = new_state.state;
    }
    
    connections.update(&key, &new_state);
    
    __u8 *payload = (__u8 *)tcph + tcp_hdr_len;
    
    if ((void *)payload < data_end && t.payload_size > 0) {
        __u8 l7_proto = detect_l7_protocol(t.src_port, t.dst_port, payload, data_end, PROTO_TCP);
        if (l7_proto <= L7_HTTPS) {
            t.l7_protocol = l7_proto;
        }
    }
    
    telemetry_events.perf_submit(skb, &t, sizeof(t));
    return TC_ACT_OK;
}

static __always_inline int handle_udp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct udphdr_min *udph = (void *)iph + (iph->ihl * 4);
    
    if ((void *)(udph + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    struct network_telemetry t = {};
    t.timestamp = bpf_ktime_get_ns();
    t.ifindex = skb->ifindex;
    t.protocol = PROTO_UDP;
    
    __builtin_memcpy(t.src_mac, eth->h_source, 6);
    __builtin_memcpy(t.dst_mac, eth->h_dest, 6);
    
    t.src_ip = iph->saddr;
    t.dst_ip = iph->daddr;
    t.ip_ttl = iph->ttl;
    t.ip_tos = iph->tos;
    t.ip_total_len = bpf_ntohs(iph->tot_len);
    t.ip_id = bpf_ntohs(iph->id);
    
    t.src_port = bpf_ntohs(udph->source);
    t.dst_port = bpf_ntohs(udph->dest);
    t.packet_size = t.ip_total_len;
    t.payload_size = bpf_ntohs(udph->len) - 8;
    
    t.error_flags = 0;
    
    if (t.ip_ttl < 5) {
        t.error_flags |= ERR_TTL_EXPIRED;
    }
    
    __u8 *payload = (__u8 *)(udph + 1);
    
    if ((void *)payload < data_end && t.payload_size > 0) {
        __u8 l7_proto = detect_l7_protocol(t.src_port, t.dst_port, payload, data_end, PROTO_UDP);
        if (l7_proto <= L7_HTTPS) {
            t.l7_protocol = l7_proto;
        }
        
        if (t.l7_protocol == L7_DNS && (void *)(payload + 12) <= data_end) {
            t.dns_flags = (payload[2] << 8) | payload[3];
        }
    }
    
    telemetry_events.perf_submit(skb, &t, sizeof(t));
    return TC_ACT_OK;
}

static __always_inline int handle_icmp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct icmphdr_min *icmph = (void *)iph + (iph->ihl * 4);
    
    if ((void *)(icmph + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // ICMP typically low volume, no rate limiting needed
    
    struct network_telemetry t = {};
    t.timestamp = bpf_ktime_get_ns();
    t.ifindex = skb->ifindex;
    t.protocol = PROTO_ICMP;
    
    __builtin_memcpy(t.src_mac, eth->h_source, 6);
    __builtin_memcpy(t.dst_mac, eth->h_dest, 6);
    
    t.src_ip = iph->saddr;
    t.dst_ip = iph->daddr;
    t.ip_ttl = iph->ttl;
    t.ip_total_len = bpf_ntohs(iph->tot_len);
    t.packet_size = t.ip_total_len;
    
    t.icmp_type = icmph->type;
    t.icmp_code = icmph->code;
    
    t.error_flags = 0;
    
    if (t.ip_ttl < 5) {
        t.error_flags |= ERR_TTL_EXPIRED;
    }
    
    telemetry_events.perf_submit(skb, &t, sizeof(t));
    return TC_ACT_OK;
}

int tc_telemetry(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    __u16 proto = bpf_ntohs(eth->h_proto);
    
    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_OK;
        }
        
        __u32 src_ip = iph->saddr;
        __u64 now = bpf_ktime_get_ns();
        
        // Check if source IP is blocklisted
        __u8 *blocked = ip_blocklist.lookup(&src_ip);
        if (blocked && *blocked == 1) {
            return TC_ACT_SHOT;  // Drop packet without further processing
        }
        
        // Track packet rate per source IP for flood detection
        struct ip_rate_tracker *tracker = ip_rate_map.lookup(&src_ip);
        struct ip_rate_tracker new_tracker = {};
        
        if (tracker) {
            __u64 time_delta = now - tracker->last_reset;
            
            if (time_delta > IP_RATE_WINDOW_NS) {
                // Reset window
                new_tracker.last_reset = now;
                new_tracker.packet_count = 1;
                ip_rate_map.update(&src_ip, &new_tracker);
            } else {
                // Increment counter
                new_tracker.last_reset = tracker->last_reset;
                new_tracker.packet_count = tracker->packet_count + 1;
                
                // Check if this IP is flooding
                if (new_tracker.packet_count > IP_FLOOD_THRESHOLD) {
                    // Add IP to blocklist
                    __u8 one = 1;
                    ip_blocklist.update(&src_ip, &one);
                    
                    // Drop this packet and all future packets from this IP
                    return TC_ACT_SHOT;
                }
                
                ip_rate_map.update(&src_ip, &new_tracker);
            }
        } else {
            // First packet from this IP
            new_tracker.last_reset = now;
            new_tracker.packet_count = 1;
            ip_rate_map.update(&src_ip, &new_tracker);
        }
        
        // IP is not flooding - proceed with protocol handling
        
        if (iph->protocol == PROTO_TCP) {
            return handle_tcp(skb, eth, iph);
        }
        if (iph->protocol == PROTO_UDP) {
            return handle_udp(skb, eth, iph);
        }
        if (iph->protocol == PROTO_ICMP) {
            return handle_icmp(skb, eth, iph);
        }
    }
    
    return TC_ACT_OK;
}

// System health tracing - OOM event monitoring

// Trace OOM killer events for memory pressure detection
TRACEPOINT_PROBE(oom, mark_victim)
{
    __u32 pid = args->pid;
    __u64 now = bpf_ktime_get_ns();
    
    struct system_health_event event = {};
    event.timestamp = now;
    event.event_type = EVENT_MEMORY;
    event.pid = pid;
    event.oom_score = 1;
    
    system_events.perf_submit(args, &event, sizeof(event));
    
    return 0;
}

// Block I/O and process exit tracepoints disabled to reduce overhead
// Disk I/O and process metrics collected via psutil instead
"""

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))

CONN_STATES = {1: "NEW", 2: "ESTABLISHED", 3: "CLOSING", 4: "CLOSED"}


# ========== Hubble L7 Data Structure ==========

class HubbleL7Data:
    """Container for Hubble L7 observability data"""
    def __init__(self):
        # HTTP
        self.http_status_code = 0
        self.http_method = ""
        self.http_url = ""
        self.http_latency_ms = 0
        
        # gRPC
        self.grpc_status_code = 0
        self.grpc_method = ""
        
        # DNS
        self.dns_response_code = 0
        self.dns_query_name = ""
        self.dns_num_answers = 0
        
        # Kafka
        self.kafka_api_key = 0
        self.kafka_error_code = 0
        
        # Service mesh metadata
        self.namespace = ""
        self.pod_name = ""
        self.service_name = ""
        self.l7_protocol_detected = ""
        
        # Cilium verdict and drop reason
        self.verdict = ""
        self.drop_reason = ""


# ========== Hubble Client ==========

class HubbleClient:
    """Client to fetch L7 metrics from Hubble"""
    
    def __init__(self, hubble_relay="127.0.0.1:4245", enabled=True):
        self.hubble_relay = hubble_relay
        self.enabled = enabled and HUBBLE_AVAILABLE
        self.l7_data_cache = {}  # Cache L7 data by flow key
        self.xlated_ip_cache = {}  # Track xlated IPs per connection: (src_ip, src_port, dst_ip, dst_port, proto) -> (xlat_src, xlat_dst)
        self.lock = threading.Lock()
        self.running = False
        self.thread = None
        
        if self.enabled:
            print(f"[INFO] Hubble client initialized (relay: {hubble_relay})")
        else:
            print("[INFO] Hubble client disabled (missing libraries or disabled)")
    
    def start(self):
        """Start Hubble flow collection in background thread"""
        if not self.enabled:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._collect_flows, daemon=True)
        self.thread.start()
        print("[OK] Hubble flow collector started")
    
    def stop(self):
        """Stop Hubble flow collection"""
        if not self.enabled or not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        print("[INFO] Hubble flow collector stopped")
    
    def _collect_flows(self):
        """Background thread to collect Hubble flows via CLI"""
        # Use Unix socket to connect directly to Cilium agent's Hubble
        cmd = ["hubble", "observe", "-o", "json", "--follow", 
               "--server", "unix:///var/run/cilium/hubble.sock"]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            print("[OK] Hubble CLI stream connected")
            
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                
                try:
                    data = json.loads(line.strip())
                    # Hubble wraps the flow in a "flow" key
                    flow = data.get("flow", data)
                    self._process_hubble_flow(flow)
                except json.JSONDecodeError:
                    continue
                except Exception:
                    pass
            
            process.terminate()
            process.wait(timeout=2.0)
            
        except FileNotFoundError:
            print("[ERROR] 'hubble' CLI not found. Install with:")
            print("        HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)")
            print("        curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz")
            print("        tar xzvf hubble-linux-amd64.tar.gz && sudo mv hubble /usr/local/bin/")
            self.enabled = False
        except Exception as e:
            print(f"[ERROR] Hubble flow collection failed: {e}")
            self.enabled = False
    
    def _process_hubble_flow(self, flow):
        """Process a Hubble flow and extract L7 data"""
        try:
            ip = flow.get("IP", {})
            l4 = flow.get("l4", {})
            l7 = flow.get("l7", {})
            
            src_ip = ip.get("source", "")
            dst_ip = ip.get("destination", "")
            
            # Also get translated IPs (for service/NAT flows)
            src_ip_xlated = ip.get("source_xlated", "")
            dst_ip_xlated = ip.get("destination_xlated", "")
            
            src_port = 0
            dst_port = 0
            protocol = 0
            
            if "TCP" in l4:
                src_port = l4["TCP"].get("source_port", 0)
                dst_port = l4["TCP"].get("destination_port", 0)
                protocol = 6
            elif "UDP" in l4:
                src_port = l4["UDP"].get("source_port", 0)
                dst_port = l4["UDP"].get("destination_port", 0)
                protocol = 17
            else:
                return
            
            # Convert IPs to host byte order (same as eBPF uses)
            try:
                src_ip_int = struct.unpack("I", socket.inet_aton(src_ip))[0]  # Host byte order
                dst_ip_int = struct.unpack("I", socket.inet_aton(dst_ip))[0]  # Host byte order
            except:
                return
            
            flow_key = (src_ip_int, src_port, dst_ip_int, dst_port, protocol)
            
            # Track xlated IPs for this connection (store for later use)
            if src_ip_xlated or dst_ip_xlated:
                with self.lock:
                    if flow_key not in self.xlated_ip_cache:
                        self.xlated_ip_cache[flow_key] = {}
                    if src_ip_xlated:
                        self.xlated_ip_cache[flow_key]["src"] = src_ip_xlated
                    if dst_ip_xlated:
                        self.xlated_ip_cache[flow_key]["dst"] = dst_ip_xlated
            
            # Look up previously seen xlated IPs for this connection (check both directions)
            cached_xlated = None
            reverse_flow_key = (dst_ip_int, dst_port, src_ip_int, src_port, protocol)
            
            with self.lock:
                # Check forward direction
                if flow_key in self.xlated_ip_cache:
                    cached_xlated = self.xlated_ip_cache[flow_key].copy()
                    print(f"[XLAT-CACHE] Found cached xlated IPs (forward) for {src_ip}:{src_port}->{dst_ip}:{dst_port}: {cached_xlated}")
                # Check reverse direction
                elif reverse_flow_key in self.xlated_ip_cache:
                    cached_xlated = self.xlated_ip_cache[reverse_flow_key].copy()
                    print(f"[XLAT-CACHE] Found cached xlated IPs (reverse) for {src_ip}:{src_port}->{dst_ip}:{dst_port}: {cached_xlated}")
                    # Swap src/dst since we got it from reverse direction
                    if "src" in cached_xlated and "dst" not in cached_xlated:
                        # Reverse flow's src is our dst
                        cached_xlated = {"dst": cached_xlated["src"]}
                    elif "dst" in cached_xlated and "src" not in cached_xlated:
                        # Reverse flow's dst is our src
                        cached_xlated = {"src": cached_xlated["dst"]}
                    elif "src" in cached_xlated and "dst" in cached_xlated:
                        # Swap both
                        cached_xlated = {"src": cached_xlated["dst"], "dst": cached_xlated["src"]}
            
            # Merge current xlated IPs with cached ones
            if cached_xlated:
                if not src_ip_xlated and "src" in cached_xlated:
                    src_ip_xlated = cached_xlated["src"]
                    print(f"[XLAT-MERGE] Using cached src_xlated: {src_ip_xlated}")
                if not dst_ip_xlated and "dst" in cached_xlated:
                    dst_ip_xlated = cached_xlated["dst"]
                    print(f"[XLAT-MERGE] Using cached dst_xlated: {dst_ip_xlated}")
            
            # Create keys for translated IPs (NAT/service IPs)
            flow_keys = [flow_key]
            if src_ip_xlated:
                try:
                    src_xlat_int = struct.unpack("I", socket.inet_aton(src_ip_xlated))[0]
                    flow_keys.append((src_xlat_int, src_port, dst_ip_int, dst_port, protocol))
                except:
                    pass
            if dst_ip_xlated:
                try:
                    dst_xlat_int = struct.unpack("I", socket.inet_aton(dst_ip_xlated))[0]
                    flow_keys.append((src_ip_int, src_port, dst_xlat_int, dst_port, protocol))
                except:
                    pass
            if src_ip_xlated and dst_ip_xlated:
                try:
                    src_xlat_int = struct.unpack("I", socket.inet_aton(src_ip_xlated))[0]
                    dst_xlat_int = struct.unpack("I", socket.inet_aton(dst_ip_xlated))[0]
                    flow_keys.append((src_xlat_int, src_port, dst_xlat_int, dst_port, protocol))
                except:
                    pass
            
            l7_data = HubbleL7Data()
            
            # Only process if there's actual L7 data OR important metadata
            has_l7_data = False
            
            # HTTP
            if "http" in l7:
                http = l7["http"]
                l7_data.l7_protocol_detected = "http"
                l7_data.http_status_code = http.get("code", 0)
                l7_data.http_method = http.get("method", "")
                l7_data.http_url = http.get("url", "")
                has_l7_data = True
                if "Summary" in flow:
                    try:
                        l7_data.http_latency_ms = int(flow.get("Summary", "").split("ms")[0].split()[-1] or 0)
                    except:
                        pass
            
            # gRPC
            elif "grpc" in l7:
                grpc_data = l7["grpc"]
                l7_data.l7_protocol_detected = "grpc"
                l7_data.grpc_status_code = grpc_data.get("status_code", 0)
                l7_data.grpc_method = grpc_data.get("method", "")
                has_l7_data = True
            
            # DNS
            elif "dns" in l7:
                dns = l7["dns"]
                l7_data.l7_protocol_detected = "dns"
                l7_data.dns_response_code = dns.get("rcode", 0)
                l7_data.dns_query_name = dns.get("query", "")
                l7_data.dns_num_answers = len(dns.get("rrs", []))
                has_l7_data = True
            
            # Kafka
            elif "kafka" in l7:
                kafka = l7["kafka"]
                l7_data.l7_protocol_detected = "kafka"
                l7_data.kafka_api_key = kafka.get("api_key", 0)
                l7_data.kafka_error_code = kafka.get("error_code", 0)
                has_l7_data = True
            
            source = flow.get("source", {})
            destination = flow.get("destination", {})
            
            l7_data.namespace = source.get("namespace", "")
            l7_data.pod_name = source.get("pod_name", "")
            l7_data.service_name = destination.get("service_name", "")
            
            l7_data.verdict = flow.get("verdict", "UNKNOWN")
            if flow.get("drop_reason_desc"):
                l7_data.drop_reason = flow["drop_reason_desc"]
            
            with self.lock:
                # Cache L7 data for all possible flow key combinations
                for fk in flow_keys:
                    if fk in self.l7_data_cache and not has_l7_data:
                        # Update metadata only, keep existing L7 fields
                        existing = self.l7_data_cache[fk]["data"]
                        existing.namespace = l7_data.namespace
                        existing.pod_name = l7_data.pod_name
                        existing.service_name = l7_data.service_name
                        existing.verdict = l7_data.verdict
                        existing.drop_reason = l7_data.drop_reason
                        self.l7_data_cache[fk]["timestamp"] = time.time()
                    else:
                        # Cache everything (new entry or has L7 data)
                        self.l7_data_cache[fk] = {
                            "data": l7_data,
                            "timestamp": time.time()
                        }
                
                # Debug: show what we're caching when we have HTTP
                if has_l7_data and l7_data.http_status_code > 0:
                    src_str = socket.inet_ntoa(struct.pack('I', src_ip_int))
                    dst_str = socket.inet_ntoa(struct.pack('I', dst_ip_int))
                    print(f"[CACHE] HTTP {l7_data.http_status_code} for {src_str}:{src_port}->{dst_str}:{dst_port} under {len(flow_keys)} keys")
                
                now = time.time()
                to_delete = [k for k, v in self.l7_data_cache.items() 
                            if now - v["timestamp"] > 30.0]
                for k in to_delete:
                    del self.l7_data_cache[k]
                
                # Clean up xlated IP cache entries for deleted flows
                xlated_to_delete = [k for k in self.xlated_ip_cache.keys() if k not in self.l7_data_cache]
                for k in xlated_to_delete:
                    del self.xlated_ip_cache[k]
        
        except Exception:
            pass
    
    def get_l7_data(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """Retrieve L7 data for a flow (if available)"""
        if not self.enabled:
            return None
        
        flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        
        with self.lock:
            # Debug: show cache size
            if len(self.l7_data_cache) > 0 and len(self.l7_data_cache) % 50 == 0:
                print(f"[DEBUG] L7 cache has {len(self.l7_data_cache)} entries")
            
            entry = self.l7_data_cache.get(flow_key)
            if entry:
                if time.time() - entry["timestamp"] < 30.0:  # Increased from 10s to 30s TTL
                    data = entry["data"]
                    # Return data if we have HTTP status code
                    if data.http_status_code > 0:
                        print(f"[HIT] HTTP {data.http_status_code} {data.http_method} found for {socket.inet_ntoa(struct.pack('I', src_ip))}:{src_port}")
                    return data
        
        return None


class SystemHealthAggregator:
    """Aggregates system health metrics using psutil and eBPF OOM tracking"""
    
    def __init__(self):
        # eBPF-tracked metrics for OOM detection
        self.oom_kills = 0
        self.window_start = time.time()
        
    def process_system_event(self, event):
        """Process system health event from eBPF (OOM only)"""
        if event.event_type == 2:  # Memory (OOM only)
            if event.oom_score > 0:
                self.oom_kills += 1
    
    def get_aggregated_metrics(self, window_duration):
        """Get aggregated system metrics for the window"""
        metrics = {}
        
        # CPU metrics via psutil (accurate and simple)
        try:
            cpu_percent = psutil.cpu_percent(interval=0)  # Non-blocking!
            metrics['cpu_usage_percent'] = cpu_percent
            
            # Get top 3 CPU processes
            procs = []
            for proc in psutil.process_iter(['name', 'cpu_percent']):
                try:
                    procs.append((proc.info['name'], proc.info['cpu_percent'] or 0))
                except:
                    continue
            
            procs.sort(key=lambda x: x[1], reverse=True)
            top3 = procs[:3]
            metrics['process_cpu_top3'] = ','.join([f"{n}({c:.1f}%)" for n, c in top3 if c > 0])
            if not metrics['process_cpu_top3']:
                metrics['process_cpu_top3'] = "idle"
        except:
            metrics['cpu_usage_percent'] = 0.0
            metrics['process_cpu_top3'] = "unknown"
        
        # Memory metrics via psutil (current state - more reliable than page faults)
        try:
            mem = psutil.virtual_memory()
            metrics['memory_usage_percent'] = mem.percent
            metrics['memory_available_mb'] = mem.available / (1024 * 1024)
            
            # Swap usage as memory pressure indicator
            swap = psutil.swap_memory()
            metrics['swap_usage_percent'] = swap.percent
        except:
            metrics['memory_usage_percent'] = 0.0
            metrics['memory_available_mb'] = 0.0
            metrics['swap_usage_percent'] = 0.0
        
        metrics['oom_kill_count'] = self.oom_kills
        
        # I/O metrics via psutil (more reliable than eBPF block tracepoints)
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics['disk_read_mb'] = disk_io.read_bytes / (1024 * 1024)
                metrics['disk_write_mb'] = disk_io.write_bytes / (1024 * 1024)
                
                # Calculate average latency from cumulative read/write times
                read_time_ms = disk_io.read_time
                write_time_ms = disk_io.write_time
                total_ops = disk_io.read_count + disk_io.write_count
                
                if total_ops > 0:
                    metrics['disk_avg_latency_us'] = ((read_time_ms + write_time_ms) * 1000) / total_ops
                else:
                    metrics['disk_avg_latency_us'] = 0.0
            else:
                metrics['disk_read_mb'] = 0.0
                metrics['disk_write_mb'] = 0.0
                metrics['disk_avg_latency_us'] = 0.0
        except:
            metrics['disk_read_mb'] = 0.0
            metrics['disk_write_mb'] = 0.0
            metrics['disk_avg_latency_us'] = 0.0
        
        # Process monitoring via psutil (count zombies, etc.)
        try:
            zombie_count = 0
            for proc in psutil.process_iter(['status']):
                try:
                    if proc.info['status'] == psutil.STATUS_ZOMBIE:
                        zombie_count += 1
                except:
                    continue
            metrics['process_exits'] = zombie_count
        except:
            metrics['process_exits'] = 0
        
        # Binary flags for ML
        metrics['high_io_latency'] = 1 if metrics['disk_avg_latency_us'] > 10000 else 0  # >10ms
        metrics['cpu_contention'] = 1 if metrics['cpu_usage_percent'] > 80 else 0  # >80%
        metrics['memory_critical'] = 1 if metrics['memory_usage_percent'] > 90 else 0  # >90%
        metrics['swap_active'] = 1 if metrics['swap_usage_percent'] > 10 else 0  # >10% swap
        
        return metrics
    
    def reset(self):
        """Reset for next window"""
        self.oom_kills = 0
        self.window_start = time.time()


class MLFeatureAggregator:
    """Aggregates network + system metrics into ML features"""
    
    def __init__(self, window_size=5.0, anomaly_label=0, hubble_client=None):
        self.window_size = window_size
        self.anomaly_label = anomaly_label
        self.hubble_client = hubble_client
        self.flow_windows = defaultdict(lambda: defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'end_time': None,
            'l7_data': None,  # Hubble L7 data
        }))
        self.completed_features = []
        self.system_aggregator = SystemHealthAggregator()
        self.bpf_program = None  # Will be set to access BPF maps
        self.last_syn_read = time.time()
        
    def generate_flow_id(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """Generate flow ID hash"""
        flow_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
        return hashlib.md5(flow_str.encode()).hexdigest()[:8]
    
    def get_syn_flood_stats(self):
        """Read SYN flood statistics from BPF map"""
        if not self.bpf_program:
            return {}
        
        syn_stats = {}
        try:
            syn_map = self.bpf_program["syn_flood_tracker"]
            for k, v in syn_map.items():
                src_ip = socket.inet_ntoa(struct.pack("I", k.value))
                syn_count = v.value
                syn_stats[src_ip] = syn_count
        except:
            pass
        
        return syn_stats
    
    def generate_blocked_flow_features(self):
        """Generate feature rows for blocked IPs to capture flood characteristics"""
        if not self.bpf_program:
            return
        
        try:
            blocked_map = self.bpf_program["ip_blocklist"]
            ip_rate_map = self.bpf_program["ip_rate_map"]
            syn_stats = self.get_syn_flood_stats()
            
            for k, v in blocked_map.items():
                if v.value != 1:
                    continue
                    
                src_ip = socket.inet_ntoa(struct.pack("I", k.value))
                
                # Get packet rate that caused blocking
                packet_count = 5000  # Default threshold
                try:
                    rate_tracker = ip_rate_map[k]
                    packet_count = rate_tracker.packet_count
                except:
                    pass
                
                # Create synthetic feature row for blocked flow
                # Destination IP unavailable due to early blocking
                features = {
                    'timestamp': int(time.time()),
                    'flow_id': hashlib.md5(f"BLOCKED_{src_ip}".encode()).hexdigest()[:8],
                    'src_ip': src_ip,
                    'dst_ip': '0.0.0.0',  # Unavailable at blocking point
                    'src_port': 0,  # Unknown (aggregated)
                    'dst_port': 0,
                    'protocol': 6,  # Assume TCP
                    'l7_protocol': 0,
                    'packet_count': packet_count,
                    'byte_count': packet_count * 60,  # Estimate
                    'packets_per_second': packet_count,  # Over 1 sec window
                    'bytes_per_second': packet_count * 60,
                    'avg_packet_size': 60,
                    'is_blocked_flow': 1,  # Indicates blocked flood traffic
                    'syn_count': syn_stats.get(src_ip, packet_count),  # High SYN count
                    'syn_ack_count': 0,  # No responses (flood)
                    'syn_to_synack_ratio': 9999,  # Extremely high (flood indicator)
                    'half_open_connections': packet_count,
                    'connection_state': 'NEW',
                    'error_rate': 0.0,
                }
                
                # Fill in other required fields with defaults
                for key in ['retransmission_count', 'retransmission_rate', 'consecutive_retrans',
                           'out_of_order_count', 'tcp_resets', 'zero_window_count', 'zero_window_duration',
                           'fin_count', 'rst_count', 'psh_count', 'duplicate_acks',
                           'ttl_min', 'ttl_avg', 'ttl_stddev', 'payload_entropy', 'dns_failures',
                           'connection_duration', 'handshake_latency']:
                    features[key] = 0 if 'count' in key or 'duration' in key else 0.0
                
                # Add system metrics
                system_metrics = self.system_aggregator.get_aggregated_metrics(1.0)
                features.update(system_metrics)
                
                # Labels
                features['anomaly_label'] = 2  # SYN_FLOOD or FLOOD type
                features['anomaly_severity'] = 3  # High severity
                features['remediation_action'] = 1  # Block IP
                
                self.completed_features.append(features)
        except Exception as e:
            print(f"Throwing an error: {e}")
            pass  # Silent fail
    
    def process_network_event(self, event):
        """Process incoming packet event"""
        timestamp_sec = event.timestamp / 1e9
        
        # Use integer IPs for flow key to match Hubble cache keys
        flow_key = (event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol)
        
        window_id = int(timestamp_sec / self.window_size)
        
        flow_window = self.flow_windows[flow_key][window_id]
        
        if flow_window['start_time'] is None:
            flow_window['start_time'] = timestamp_sec
            flow_window['end_time'] = timestamp_sec
        else:
            # Track min/max to handle out-of-order packets from multiple interfaces
            flow_window['start_time'] = min(flow_window['start_time'], timestamp_sec)
            flow_window['end_time'] = max(flow_window['end_time'], timestamp_sec)
        
        flow_window['packets'].append(event)
        
        # Fetch Hubble L7 data if available (use integer IPs)
        if self.hubble_client and flow_window['l7_data'] is None:
            # Try forward direction
            l7_data = self.hubble_client.get_l7_data(
                event.src_ip, event.src_port,
                event.dst_ip, event.dst_port,
                event.protocol
            )
            # If not found, try reverse direction (for response packets)
            if not l7_data:
                l7_data = self.hubble_client.get_l7_data(
                    event.dst_ip, event.dst_port,
                    event.src_ip, event.src_port,
                    event.protocol
                )
            
            if l7_data:
                flow_window['l7_data'] = l7_data
                print(f"[HIT] Found L7 data: {l7_data.l7_protocol_detected} for {ip_to_str(event.src_ip)}:{event.src_port}")
        
        self._finalize_old_windows(timestamp_sec)
    
    def process_system_event(self, event):
        """Process system health event"""
        self.system_aggregator.process_system_event(event)
    
    def _finalize_old_windows(self, current_time):
        """Finalize windows that are complete"""
        current_window = int(current_time / self.window_size)
        flows_to_remove = []
        
        for flow_key in list(self.flow_windows.keys()):
            windows_to_remove = []
            
            for window_id in list(self.flow_windows[flow_key].keys()):
                if window_id < current_window - 1:
                    features = self._extract_features(flow_key, window_id)
                    if features:
                        self.completed_features.append(features)
                    windows_to_remove.append(window_id)
            
            for wid in windows_to_remove:
                del self.flow_windows[flow_key][wid]
            
            if not self.flow_windows[flow_key]:
                flows_to_remove.append(flow_key)
        
        for fk in flows_to_remove:
            del self.flow_windows[fk]
    
    def _extract_features(self, flow_key, window_id):
        """Extract 72 ML features (38 network + 15 L7 + 12 system + 7 metadata) from flow window"""
        src_ip_int, src_port, dst_ip_int, dst_port, protocol = flow_key
        flow_window = self.flow_windows[flow_key][window_id]
        packets = flow_window['packets']
        l7_data = flow_window.get('l7_data')
        
        if not packets:
            return None
        
        # RETRY: Try one more time to fetch L7 data before finalizing (in case Hubble was delayed)
        if self.hubble_client and not l7_data:
            l7_data = self.hubble_client.get_l7_data(
                src_ip_int, src_port, dst_ip_int, dst_port, protocol
            )
            if not l7_data:
                # Try reverse direction
                l7_data = self.hubble_client.get_l7_data(
                    dst_ip_int, dst_port, src_ip_int, src_port, protocol
                )
            if l7_data:
                flow_window['l7_data'] = l7_data  # Cache for potential future use
        
        # Convert integer IPs to strings for CSV output
        src_ip = ip_to_str(src_ip_int)
        dst_ip = ip_to_str(dst_ip_int)
        
        flow_id = self.generate_flow_id(src_ip, src_port, dst_ip, dst_port, protocol)
        
        l7_protocols = [p.l7_protocol for p in packets if p.l7_protocol > 0]
        l7_protocol_type = max(set(l7_protocols), key=l7_protocols.count) if l7_protocols else 0
        
        features = {
            'timestamp': int(time.time()),  # Unix epoch seconds (not eBPF boot time)
            'flow_id': flow_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'l7_protocol': l7_protocol_type,
        }
        
        # Use the configured window size for rate calculations (NOT actual packet duration)
        # This gives consistent, comparable rates across all flows
        window_duration = self.window_size  # e.g., 5.0 seconds
        
        # ========== NETWORK FEATURES (38) [attached at TC ingress & egress]==========
        
        # Validate and sanitize packet data
        valid_packets = [p for p in packets if 0 < p.packet_size < 65536]  # Valid packet size range
        if not valid_packets:
            return None  # Skip corrupted data
        
        features['packet_count'] = len(valid_packets)
        features['byte_count'] = sum(p.packet_size for p in valid_packets)
        
        # Calculate rates with bounds checking
        pps = features['packet_count'] / window_duration
        bps = features['byte_count'] / window_duration
        
        # Sanity checks: cap at physically possible maximums
        features['packets_per_second'] = min(max(0, pps), 10000000)  # Cap at 10M pps
        features['bytes_per_second'] = min(max(0, bps), 100000000000)  # Cap at 100 Gbps
        features['avg_packet_size'] = features['byte_count'] / features['packet_count'] if features['packet_count'] > 0 else 0
        
        # Ensure avg_packet_size is reasonable (40 bytes min for TCP/IP, 9000 max for jumbo frames)
        if features['avg_packet_size'] > 0:
            features['avg_packet_size'] = min(max(40, features['avg_packet_size']), 9000)
        
        tcp_packets = [p for p in valid_packets if p.protocol == 6]
        
        if tcp_packets:
            features['retransmission_count'] = sum(1 for p in tcp_packets if p.retransmission)
            features['retransmission_rate'] = features['retransmission_count'] / len(tcp_packets)
            
            max_consecutive = 0
            current_consecutive = 0
            last_retrans_time = 0
            for p in tcp_packets:
                if p.retransmission:
                    current_time = p.timestamp / 1e9
                    if last_retrans_time > 0 and (current_time - last_retrans_time) < 1.0:
                        current_consecutive += 1
                    else:
                        current_consecutive = 1
                    max_consecutive = max(max_consecutive, current_consecutive)
                    last_retrans_time = current_time
            features['consecutive_retrans'] = max_consecutive
            
            features['out_of_order_count'] = sum(1 for p in tcp_packets if p.error_flags & 0x08)
            features['tcp_resets'] = sum(1 for p in tcp_packets if p.tcp_flags & 0x04)
            features['zero_window_count'] = sum(1 for p in tcp_packets if p.tcp_window == 0)
            
            zero_window_duration = 0.0
            in_zero_window = False
            zero_window_start = 0
            for p in tcp_packets:
                if p.tcp_window == 0 and not in_zero_window:
                    in_zero_window = True
                    zero_window_start = p.timestamp / 1e9
                elif p.tcp_window > 0 and in_zero_window:
                    zero_window_duration += (p.timestamp / 1e9) - zero_window_start
                    in_zero_window = False
            features['zero_window_duration'] = zero_window_duration
            
            # Get actual SYN count from BPF map (includes all SYNs, not just sampled)
            syn_stats = self.get_syn_flood_stats()
            if src_ip in syn_stats:
                features['syn_count'] = syn_stats[src_ip]
            else:
                features['syn_count'] = 0
            
            features['syn_ack_count'] = sum(1 for p in tcp_packets if (p.tcp_flags & 0x02) and (p.tcp_flags & 0x10))
            features['syn_to_synack_ratio'] = features['syn_count'] / features['syn_ack_count'] if features['syn_ack_count'] > 0 else (features['syn_count'] if features['syn_count'] > 0 else 0)
            features['fin_count'] = sum(1 for p in tcp_packets if p.tcp_flags & 0x01)
            features['rst_count'] = sum(1 for p in tcp_packets if p.tcp_flags & 0x04)
            features['psh_count'] = sum(1 for p in tcp_packets if p.tcp_flags & 0x08)
            features['duplicate_acks'] = 0
            
        else:
            for key in ['retransmission_count', 'retransmission_rate', 'consecutive_retrans',
                       'out_of_order_count', 'tcp_resets', 'zero_window_count', 'zero_window_duration',
                       'syn_count', 'syn_ack_count', 'syn_to_synack_ratio',
                       'fin_count', 'rst_count', 'psh_count', 'duplicate_acks']:
                features[key] = 0 if 'count' in key or 'duration' in key or 'consecutive' in key else 0.0
        
        ttl_values = [p.ip_ttl for p in packets if p.ip_ttl > 0]
        if ttl_values:
            features['ttl_min'] = min(ttl_values)
            features['ttl_avg'] = sum(ttl_values) / len(ttl_values)
            features['ttl_stddev'] = np.std(ttl_values) if len(ttl_values) > 1 else 0.0
        else:
            features['ttl_min'] = 0
            features['ttl_avg'] = 0.0
            features['ttl_stddev'] = 0.0
        
        payload_sizes = [p.payload_size for p in packets]
        if payload_sizes and max(payload_sizes) > 0:
            unique_sizes = len(set(payload_sizes))
            features['payload_entropy'] = min(1.0, unique_sizes / len(payload_sizes))
        else:
            features['payload_entropy'] = 0.0
        
        dns_queries = [p for p in packets if p.dst_port == 53 and p.protocol == 17]
        dns_responses = [p for p in packets if p.src_port == 53 and p.protocol == 17]
        dns_packets = [p for p in packets if p.l7_protocol == 3]
        
        error_responses = sum(1 for p in dns_packets if p.dns_flags & 0x0003)
        unanswered_queries = max(0, len(dns_queries) - len(dns_responses))
        features['dns_failures'] = error_responses + unanswered_queries
        
        if tcp_packets:
            last_packet = tcp_packets[-1]
            features['connection_state'] = CONN_STATES.get(last_packet.conn_state, "UNKNOWN")
        else:
            features['connection_state'] = "ESTABLISHED"
        
        features['connection_duration'] = window_duration
        
        features['handshake_latency'] = 0.0
        if tcp_packets and features['syn_count'] > 0:
            if len(tcp_packets) >= 2:
                features['handshake_latency'] = (tcp_packets[1].timestamp - tcp_packets[0].timestamp) / 1e9
        
        error_packets = sum(1 for p in packets if p.error_flags != 0)
        features['error_rate'] = error_packets / features['packet_count'] if features['packet_count'] > 0 else 0.0
        
        features['half_open_connections'] = 0
        if tcp_packets:
            syn_only = sum(1 for p in tcp_packets if (p.tcp_flags & 0x02) and not (p.tcp_flags & 0x10))
            features['half_open_connections'] = syn_only
        
        # Check if this flow's source IP is blocked (flood detected)
        features['is_blocked_flow'] = 0
        if self.bpf_program:
            try:
                blocked_map = self.bpf_program["ip_blocklist"]
                src_ip_int = struct.unpack("I", socket.inet_aton(src_ip))[0]
                if blocked_map.get(ct.c_uint32(src_ip_int)):
                    features['is_blocked_flow'] = 1
            except:
                pass
        
        # ========== SYSTEM HEALTH FEATURES ==========
        
        system_metrics = self.system_aggregator.get_aggregated_metrics(window_duration)
        features.update(system_metrics)
        
        # ========== HUBBLE L7 FEATURES (15) ==========
        
        if l7_data:
            # HTTP
            features['http_status_code'] = l7_data.http_status_code
            features['http_method'] = l7_data.http_method
            features['http_latency_ms'] = l7_data.http_latency_ms
            
            # gRPC
            features['grpc_status_code'] = l7_data.grpc_status_code
            features['grpc_method'] = l7_data.grpc_method
            
            # DNS
            features['dns_response_code'] = l7_data.dns_response_code
            features['dns_num_answers'] = l7_data.dns_num_answers
            
            # Kafka
            features['kafka_api_key'] = l7_data.kafka_api_key
            features['kafka_error_code'] = l7_data.kafka_error_code
            
            # Metadata
            features['l7_protocol_detected'] = l7_data.l7_protocol_detected
            features['namespace'] = l7_data.namespace
            features['pod_name'] = l7_data.pod_name
            features['service_name'] = l7_data.service_name
            features['verdict'] = l7_data.verdict
            features['drop_reason'] = l7_data.drop_reason if l7_data.drop_reason else ""
        else:
            # Default values when no L7 data
            features['http_status_code'] = 0
            features['http_method'] = ""
            features['http_latency_ms'] = 0
            features['grpc_status_code'] = 0
            features['grpc_method'] = ""
            features['dns_response_code'] = 0
            features['dns_num_answers'] = 0
            features['kafka_api_key'] = 0
            features['kafka_error_code'] = 0
            features['l7_protocol_detected'] = ""
            features['namespace'] = ""
            features['pod_name'] = ""
            features['service_name'] = ""
            features['verdict'] = ""
            features['drop_reason'] = ""
        
        # Labels
        features['anomaly_label'] = self.anomaly_label
        features['anomaly_severity'] = 0
        features['remediation_action'] = 0
        
        return features
    
    def finalize_all(self):
        """Finalize all remaining windows"""
        # Generate features for blocked IPs (floods that were dropped)
        self.generate_blocked_flow_features()
        
        for flow_key in list(self.flow_windows.keys()):
            for window_id in list(self.flow_windows[flow_key].keys()):
                features = self._extract_features(flow_key, window_id)
                if features:
                    self.completed_features.append(features)
        
        self.flow_windows.clear()
    
    def get_features_df(self):
        """Return features as pandas DataFrame"""
        if not self.completed_features:
            return pd.DataFrame()
        
        df = pd.DataFrame(self.completed_features)
        
        # Column order: 38 network + 15 L7 + 12 system + 7 metadata = 72 features + 3 labels = 75 columns
        column_order = [
            # Metadata (7)
            'timestamp', 'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'l7_protocol',
            # Network features (38)
            'packet_count', 'byte_count', 'packets_per_second', 'bytes_per_second', 'avg_packet_size',
            'retransmission_count', 'retransmission_rate', 'consecutive_retrans',
            'out_of_order_count', 'tcp_resets', 'zero_window_count', 'zero_window_duration',
            'syn_count', 'syn_ack_count', 'syn_to_synack_ratio',
            'fin_count', 'rst_count', 'psh_count', 'duplicate_acks',
            'ttl_min', 'ttl_avg', 'ttl_stddev',
            'payload_entropy', 'dns_failures',
            'connection_state', 'connection_duration', 'handshake_latency',
            'error_rate', 'half_open_connections', 'is_blocked_flow',
            # System metrics (12)
            'cpu_usage_percent', 'process_cpu_top3', 
            'memory_usage_percent', 'memory_available_mb', 'swap_usage_percent', 'oom_kill_count',
            'disk_read_mb', 'disk_write_mb', 'disk_avg_latency_us',
            'process_exits', 'high_io_latency', 'cpu_contention', 'memory_critical', 'swap_active',
            # Hubble L7 features (15)
            'http_status_code', 'http_method', 'http_latency_ms',
            'grpc_status_code', 'grpc_method',
            'dns_response_code', 'dns_num_answers',
            'kafka_api_key', 'kafka_error_code',
            'l7_protocol_detected', 'namespace', 'pod_name', 'service_name', 'verdict', 'drop_reason',
            # Labels (3)
            'anomaly_label', 'anomaly_severity', 'remediation_action'
        ]
        
        for col in column_order:
            if col not in df.columns:
                if col in ['connection_state', 'process_cpu_top3', 'http_method', 'grpc_method', 
                          'l7_protocol_detected', 'namespace', 'pod_name', 'service_name', 'verdict', 'drop_reason']:
                    df[col] = ""
                else:
                    df[col] = 0
        
        return df[column_order]


# Global state
aggregator = None
b = None
ip_route = None
interface_index = None
filter_ip = None

def cleanup(signum=None, frame=None):
    """Cleanup on exit"""
    global b, ip_route, interface_indices, aggregator, hubble_client
    
    print("\n\nShutting down...")
    
    # Stop Hubble client first
    if hubble_client:
        hubble_client.stop()
    
    if aggregator:
        print("Finalizing remaining windows...")
        aggregator.finalize_all()
        
        df = aggregator.get_features_df()
        if not df.empty:
            print(f"\nTotal features extracted: {len(df)} rows x {len(df.columns)} columns")
            print(f"  → 38 network + 15 L7 (Hubble) + 12 system = 72 features (with 7 metadata columns)")
            
            output_file = f"ml_features_hybrid_{int(time.time())}.csv"
            df.to_csv(output_file, index=False)
            print(f"[OK] Saved to {output_file}")
            
            try:
                parquet_file = f"ml_features_hybrid_{int(time.time())}.parquet"
                df.to_parquet(parquet_file, index=False, compression='snappy')
                print(f"[OK] Saved to {parquet_file}")
            except ImportError:
                print(f"[WARNING] Parquet export skipped (install: pip install pyarrow)")
            
            print("\nSample features (first 2 rows, key metrics):")
            sample_cols = ['timestamp', 'flow_id', 'retransmission_rate', 'http_status_code',
                          'cpu_usage_percent', 'memory_usage_percent', 'disk_avg_latency_us', 'anomaly_label']
            if all(col in df.columns for col in sample_cols):
                print(df[sample_cols].head(2).to_string())
    
    if ip_route and interface_indices:
        for idx in interface_indices:
            try:
                ip_route.tc("del", "clsact", idx)
            except Exception as e:
                pass
        print("[OK] TC filters removed from all interfaces")
    
    print("Detached!")
    sys.exit(0)

def print_network_event(cpu, data, size):
    """Callback for network perf buffer events"""
    global aggregator, filter_ip
    
    event = ct.cast(data, ct.POINTER(NetworkTelemetry)).contents
    
    if filter_ip:
        src_ip = socket.inet_ntoa(struct.pack("I", event.src_ip))
        dst_ip = socket.inet_ntoa(struct.pack("I", event.dst_ip))
        if src_ip != filter_ip and dst_ip != filter_ip:
            return
    
    aggregator.process_network_event(event)

def print_system_event(cpu, data, size):
    """Callback for system health perf buffer events"""
    global aggregator
    
    event = ct.cast(data, ct.POINTER(SystemHealthEvent)).contents
    aggregator.process_system_event(event)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='ML Feature Exporter - Hybrid eBPF + Hubble',
        epilog='Exports 72 features (38 network + 15 L7 + 12 system + 7 metadata)'
    )
    parser.add_argument('interface', nargs='?', default='all', help='Network interface to monitor (or "all" for all lxc interfaces)')
    parser.add_argument('--window', '-w', type=float, default=5.0,
                       help='Aggregation window (seconds, default: 5.0)')
    parser.add_argument('--duration', '-d', type=int, default=60,
                       help='Collection duration (seconds, 0=infinite)')
    parser.add_argument('--label', '-l', type=int, default=0,
                       help='Anomaly label (0=NORMAL, 1-11=anomaly types)')
    parser.add_argument('--output-interval', '-i', type=int, default=30,
                       help='Print stats every N seconds (0=only at end)')
    parser.add_argument('--filter-ip', '-f', type=str, default=None,
                       help='Filter traffic by IP (source or destination)')
    parser.add_argument('--no-hubble', action='store_true',
                       help='Disable Hubble L7 data collection')
    
    args = parser.parse_args()
    
    device = args.interface
    filter_ip = args.filter_ip
    
    # Get list of interfaces to monitor
    if device == 'all':
        from pyroute2 import IPRoute
        ip_route = IPRoute()
        interfaces = []
        for link in ip_route.get_links():
            name = link.get_attr('IFLA_IFNAME')
            if name and name.startswith('lxc') and name != 'lxc_health':
                interfaces.append(name)
        ip_route.close()
        
        if not interfaces:
            print("[ERROR] No lxc interfaces found")
            sys.exit(1)
        
        print(f"[INFO] Found {len(interfaces)} lxc interfaces: {', '.join(interfaces[:5])}...")
        device_list = interfaces
    else:
        device_list = [device]
    
    # Initialize Hubble client
    hubble_client = None
    if not args.no_hubble and HUBBLE_AVAILABLE:
        hubble_client = HubbleClient(enabled=True)
        hubble_client.start()
    
    aggregator = MLFeatureAggregator(
        window_size=args.window, 
        anomaly_label=args.label,
        hubble_client=hubble_client
    )
    
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    print("="*70)
    print("ML Feature Exporter - Hybrid eBPF + Hubble")
    print("="*70)
    print(f"   Interfaces: {len(device_list)} ({', '.join(device_list[:3])}{'...' if len(device_list) > 3 else ''})")
    print(f"   Window: {args.window}s")
    print(f"   Duration: {args.duration}s ({'infinite' if args.duration == 0 else 'finite'})")
    print(f"   Anomaly Label: {args.label}")
    if filter_ip:
        print(f"   IP Filter: {filter_ip}")
    print(f"\n   Features: 38 network + 15 L7 + 12 system + 7 metadata = 72 total")
    print(f"   Hubble: {'Enabled' if hubble_client else 'Disabled'}")
    print(f"   Network: eBPF (TC classifier + IP-level flood blocking)")
    print(f"   System: psutil (all metrics) + eBPF OOM tracking")
    print(f"   Protection: Block IPs >500pkt/s (no sampling)")
    print("="*70)
    
    print("Loading eBPF programs (network + system tracing)...")
    cflags = [
        "-w", 
        "-D__BPF_TRACING__", 
        "-DCONFIG_NET_CLS_ACT=y",
        "-DBPF_LOAD_ACQ=0xe1",
        "-DBPF_STORE_REL=0xf1",
        "-Wno-macro-redefined",
        "-Wno-deprecated-declarations",
        "-fno-stack-protector",
        "-D__KERNEL__",
        "-D__ASM_SYSREG_H",
        "-Wno-address-of-packed-member",
        "-Wno-compare-distinct-pointer-types",
        "-Wno-gnu-variable-sized-type-not-at-end",
        "-Wno-tautological-compare",
        "-O2"
    ]
    b = BPF(text=bpf_text, cflags=cflags, debug=0)
    
    # Load network TC filter
    fn = b.load_func("tc_telemetry", BPF.SCHED_CLS)
    
    # Attach to TC on all interfaces
    from pyroute2 import IPRoute
    ip_route = IPRoute()
    
    attached_interfaces = []
    interface_indices = []
    
    for device in device_list:
        idx_list = ip_route.link_lookup(ifname=device)
        if not idx_list:
            print(f"[WARNING] Interface {device} not found, skipping")
            continue
        
        interface_index = idx_list[0]
        
        try:
            ip_route.tc("add", "clsact", interface_index)
        except Exception as e:
            pass  # clsact may already exist
        
        try:
            ip_route.tc("add-filter", "bpf", interface_index, ":1", fd=fn.fd, name=fn.name,
                        parent="ffff:fff2", classid=1, direct_action=True)
            
            ip_route.tc("add-filter", "bpf", interface_index, ":2", fd=fn.fd, name=fn.name,
                        parent="ffff:fff3", classid=1, direct_action=True)
            
            attached_interfaces.append(device)
            interface_indices.append(interface_index)
        except Exception as e:
            print(f"[WARNING] Failed to attach to {device}: {e}")
    
    if not attached_interfaces:
        print("[ERROR] Failed to attach to any interface")
        sys.exit(1)
    
    print(f"[OK] Network telemetry attached to {len(attached_interfaces)} interfaces")
    print(f"     Monitoring: {', '.join(attached_interfaces[:5])}{'...' if len(attached_interfaces) > 5 else ''}")
    print(f"[OK] System metrics: psutil (CPU, Memory, Disk I/O) + eBPF OOM only")
    print("Collecting data...\n")
    
    # Link BPF program to aggregator for SYN flood map access
    aggregator.bpf_program = b
    
    # Open perf buffer for network events only (512 pages = 2MB buffer for flood protection)
    b["telemetry_events"].open_perf_buffer(print_network_event, page_cnt=512)
    # Note: system_events buffer removed - OOM events too rare to poll for
    
    start_time = time.time()
    last_status = time.time()
    
    try:
        while True:
            b.perf_buffer_poll(timeout=10)  # Poll every 10ms (was 100ms) - drain buffer faster
            
            current_time = time.time()
            elapsed = current_time - start_time
            
            if args.output_interval > 0 and (current_time - last_status) >= args.output_interval:
                # Generate features for currently blocked IPs
                aggregator.generate_blocked_flow_features()
                
                features_count = len(aggregator.completed_features)
                sys_metrics = aggregator.system_aggregator.get_aggregated_metrics(elapsed)
                
                # Check for SYN flood activity
                syn_stats = aggregator.get_syn_flood_stats()
                total_syns = sum(syn_stats.values()) if syn_stats else 0
                
                # Check for blocked IPs
                blocked_count = 0
                try:
                    blocked_map = b["ip_blocklist"]
                    blocked_ips = [socket.inet_ntoa(struct.pack("I", k.value)) for k, v in blocked_map.items()]
                    blocked_count = len(blocked_ips)
                except:
                    pass
                
                print(f"[{elapsed:.1f}s] Features: {features_count} | "
                      f"CPU: {sys_metrics['cpu_usage_percent']:.1f}% | "
                      f"MEM: {sys_metrics['memory_usage_percent']:.1f}% | "
                      f"Blocked IPs: {blocked_count}")
                
                if blocked_count > 0 and blocked_ips:
                    print(f"   [BLOCKED] {', '.join(blocked_ips[:5])}")
                
                last_status = current_time
            
            if args.duration > 0 and elapsed >= args.duration:
                break
    
    except KeyboardInterrupt:
        pass
    
    cleanup()
