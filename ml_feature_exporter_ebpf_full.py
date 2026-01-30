#!/usr/bin/env python3
"""
ML Feature Exporter - Full eBPF Implementation
Network + System metrics using pure eBPF for self-healing edge systems

Features: 38 network + 12 system (eBPF-based) = 50 features
Optimized for low-overhead production edge deployment
"""

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

# Feature aggregation window (seconds)
AGGREGATION_WINDOW = 5.0

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
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/sched.h>
#include <linux/mm.h>

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
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    
    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // SYN flood tracking: Count SYNs separately
    if (tcph->syn && !tcph->ack) {
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
    
    __u8 tcp_flags = 0;
    if (tcph->syn) tcp_flags |= 0x02;
    if (tcph->ack) tcp_flags |= 0x10;
    if (tcph->fin) tcp_flags |= 0x01;
    if (tcph->rst) tcp_flags |= 0x04;
    if (tcph->psh) tcp_flags |= 0x08;
    if (tcph->urg) tcp_flags |= 0x20;
    t.tcp_flags = tcp_flags;
    
    t.tcp_seq = bpf_ntohl(tcph->seq);
    t.tcp_ack = bpf_ntohl(tcph->ack_seq);
    t.tcp_window = bpf_ntohs(tcph->window);
    
    __u32 tcp_hdr_len = tcph->doff * 4;
    __u32 ip_hdr_len = iph->ihl * 4;
    t.packet_size = t.ip_total_len;
    t.payload_size = t.ip_total_len - ip_hdr_len - tcp_hdr_len;
    
    t.error_flags = 0;
    
    if (t.ip_ttl < 5) {
        t.error_flags |= ERR_TTL_EXPIRED;
    }
    
    if (tcph->rst) {
        t.error_flags |= ERR_RST_RECEIVED;
    }
    
    if (t.tcp_window == 0 && tcph->ack) {
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
        if (t.tcp_seq < state->last_seq && !tcph->syn) {
            t.retransmission = 1;
            t.error_flags |= ERR_RETRANSMISSION;
        } else if (t.tcp_seq > state->last_seq + 1500) {
            t.error_flags |= ERR_OUT_OF_ORDER;
        }
        
        new_state.last_seq = t.tcp_seq;
        new_state.last_seen = t.timestamp;
        
        if (tcph->syn && !tcph->ack) {
            new_state.state = CONN_NEW;
        } else if (tcph->syn && tcph->ack) {
            new_state.state = CONN_NEW;
        } else if (tcph->fin || tcph->rst) {
            new_state.state = CONN_CLOSING;
        } else if (tcph->ack) {
            new_state.state = CONN_ESTABLISHED;
        }
        
        t.conn_state = new_state.state;
    } else {
        new_state.last_seq = t.tcp_seq;
        new_state.last_seen = t.timestamp;
        new_state.state = tcph->syn ? CONN_NEW : CONN_ESTABLISHED;
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
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    
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
    struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
    
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
    
    def __init__(self, window_size=5.0, anomaly_label=0):
        self.window_size = window_size
        self.anomaly_label = anomaly_label
        self.flow_windows = defaultdict(lambda: defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'end_time': None,
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
            pass  # Silent fail
    
    def process_network_event(self, event):
        """Process incoming packet event"""
        timestamp_sec = event.timestamp / 1e9
        
        src_ip = ip_to_str(event.src_ip)
        dst_ip = ip_to_str(event.dst_ip)
        
        flow_key = (src_ip, event.src_port, dst_ip, event.dst_port, event.protocol)
        
        window_id = int(timestamp_sec / self.window_size)
        
        flow_window = self.flow_windows[flow_key][window_id]
        
        if flow_window['start_time'] is None:
            flow_window['start_time'] = timestamp_sec
        
        flow_window['end_time'] = timestamp_sec
        flow_window['packets'].append(event)
        
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
        """Extract 50 ML features (38 network + 12 system) from flow window"""
        src_ip, src_port, dst_ip, dst_port, protocol = flow_key
        flow_window = self.flow_windows[flow_key][window_id]
        packets = flow_window['packets']
        
        if not packets:
            return None
        
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
        
        window_duration = flow_window['end_time'] - flow_window['start_time']
        if window_duration == 0:
            window_duration = 0.001
        
        # ========== NETWORK FEATURES (38) ==========
        
        features['packet_count'] = len(packets)
        features['byte_count'] = sum(p.packet_size for p in packets)
        features['packets_per_second'] = features['packet_count'] / window_duration
        features['bytes_per_second'] = features['byte_count'] / window_duration
        features['avg_packet_size'] = features['byte_count'] / features['packet_count'] if features['packet_count'] > 0 else 0
        
        tcp_packets = [p for p in packets if p.protocol == 6]
        
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
        
        # ========== SYSTEM HEALTH FEATURES (12 from eBPF) ==========
        
        system_metrics = self.system_aggregator.get_aggregated_metrics(window_duration)
        features.update(system_metrics)
        
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
        
        # Column order: 39 network + 12 system = 51 features + 3 labels = 54 columns
        column_order = [
            'timestamp', 'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'l7_protocol',
            'packet_count', 'byte_count', 'packets_per_second', 'bytes_per_second', 'avg_packet_size',
            'retransmission_count', 'retransmission_rate', 'consecutive_retrans',
            'out_of_order_count', 'tcp_resets', 'zero_window_count', 'zero_window_duration',
            'syn_count', 'syn_ack_count', 'syn_to_synack_ratio',
            'fin_count', 'rst_count', 'psh_count', 'duplicate_acks',
            'ttl_min', 'ttl_avg', 'ttl_stddev',
            'payload_entropy', 'dns_failures',
            'connection_state', 'connection_duration', 'handshake_latency',
            'error_rate', 'half_open_connections', 'is_blocked_flow',
            # System metrics (psutil + eBPF I/O + OOM)
            'cpu_usage_percent', 'process_cpu_top3', 
            'memory_usage_percent', 'memory_available_mb', 'swap_usage_percent', 'oom_kill_count',
            'disk_read_mb', 'disk_write_mb', 'disk_avg_latency_us',
            'process_exits', 'high_io_latency', 'cpu_contention', 'memory_critical', 'swap_active',
            'anomaly_label', 'anomaly_severity', 'remediation_action'
        ]
        
        for col in column_order:
            if col not in df.columns:
                df[col] = 0 if col not in ['connection_state', 'process_cpu_top3'] else ""
        
        return df[column_order]


# Global state
aggregator = None
b = None
ip_route = None
interface_index = None
filter_ip = None

def cleanup(signum=None, frame=None):
    """Cleanup on exit"""
    global b, ip_route, interface_index, aggregator
    
    print("\n\nShutting down...")
    
    if aggregator:
        print("Finalizing remaining windows...")
        aggregator.finalize_all()
        
        df = aggregator.get_features_df()
        if not df.empty:
            print(f"\nTotal features extracted: {len(df)} rows x {len(df.columns)} columns")
            print(f"  → 38 network + 12 system (psutil + eBPF I/O) = 50 features")
            
            output_file = f"ml_features_ebpf_{int(time.time())}.csv"
            df.to_csv(output_file, index=False)
            print(f"[OK] Saved to {output_file}")
            
            try:
                parquet_file = f"ml_features_ebpf_{int(time.time())}.parquet"
                df.to_parquet(parquet_file, index=False, compression='snappy')
                print(f"[OK] Saved to {parquet_file}")
            except ImportError:
                print(f"[WARNING] Parquet export skipped (install: pip install pyarrow)")
            
            print("\nSample features (first 2 rows, key metrics):")
            sample_cols = ['timestamp', 'flow_id', 'retransmission_rate', 'cpu_usage_percent', 
                          'memory_pressure_mb', 'disk_avg_latency_us', 'anomaly_label']
            if all(col in df.columns for col in sample_cols):
                print(df[sample_cols].head(2).to_string())
    
    if ip_route and interface_index:
        try:
            ip_route.tc("del", "clsact", interface_index)
            print("[OK] TC filter removed")
        except Exception as e:
            print(f"[WARNING] TC cleanup warning: {e}")
    
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
        description='ML Feature Exporter - Full eBPF (Network + System)',
        epilog='Exports 50 features using pure eBPF (38 network + 12 system)'
    )
    parser.add_argument('interface', help='Network interface to monitor')
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
    
    args = parser.parse_args()
    
    device = args.interface
    filter_ip = args.filter_ip
    
    aggregator = MLFeatureAggregator(window_size=args.window, anomaly_label=args.label)
    
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    print("="*70)
    print("ML Feature Exporter - Hybrid eBPF + psutil")
    print("="*70)
    print(f"   Interface: {device}")
    print(f"   Window: {args.window}s")
    print(f"   Duration: {args.duration}s ({'infinite' if args.duration == 0 else 'finite'})")
    print(f"   Anomaly Label: {args.label}")
    if filter_ip:
        print(f"   IP Filter: {filter_ip}")
    print(f"\n   Features: 39 network + 12 system = 51 total")
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
        "-DBPF_STORE_REL=0xf1"
    ]
    b = BPF(text=bpf_text, cflags=cflags)
    
    # Load network TC filter
    fn = b.load_func("tc_telemetry", BPF.SCHED_CLS)
    
    # Attach to TC
    from pyroute2 import IPRoute
    ip_route = IPRoute()
    
    idx_list = ip_route.link_lookup(ifname=device)
    if not idx_list:
        print(f"[ERROR] Interface {device} not found")
        sys.exit(1)
    
    interface_index = idx_list[0]
    
    try:
        ip_route.tc("add", "clsact", interface_index)
    except Exception as e:
        pass
    
    ip_route.tc("add-filter", "bpf", interface_index, ":1", fd=fn.fd, name=fn.name,
                parent="ffff:fff2", classid=1, direct_action=True)
    
    ip_route.tc("add-filter", "bpf", interface_index, ":2", fd=fn.fd, name=fn.name,
                parent="ffff:fff3", classid=1, direct_action=True)
    
    print(f"[OK] Network telemetry attached to {device}")
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
