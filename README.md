# eBPF + Hubble Network Telemetry Exporter

## Overview

This tool provides comprehensive network, application, and system telemetry collection for Kubernetes environments using a hybrid approach combining **eBPF (Extended Berkeley Packet Filter)** for low-level packet capture and **Cilium Hubble** for Layer 7 application visibility. It exports machine learning-ready features in CSV format for building self-healing edge computing systems and network security applications.

### What This Tool Does

- **Captures network packets** at the kernel level using eBPF TC (Traffic Control) hooks
- **Extracts Layer 7 application data** (HTTP, gRPC, DNS, Kafka) via Hubble integration
- **Monitors system health** (CPU, memory, disk I/O) using psutil
- **Aggregates 72 ML features** per flow into time-windowed CSV files
- **Tracks TCP performance** (retransmissions, out-of-order packets, zero windows)
- **Detects anomalies** with configurable labeling for supervised learning

### Use Cases

- **Anomaly Detection**: Train ML models to detect DDoS attacks, port scans, and unusual traffic patterns
- **Self-Healing Systems**: Automatically identify and respond to network degradation
- **Performance Monitoring**: Track application-level metrics alongside network behavior
- **Security Research**: Collect labeled datasets for network intrusion detection systems
- **Capacity Planning**: Analyze traffic patterns and resource utilization over time

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Kubernetes Pod                          │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │ Application  │◄────────┤ lxc interface│                  │
│  │  Container   │         │  (veth pair) │                  │
│  └──────────────┘         └───────┬──────┘                  │
└─────────────────────────────────────┼───────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │  eBPF TC Hook   │                 │
                    │  (Kernel Space) │                 │
                    │  ┌──────────────▼──────────────┐  │
                    │  │ Packet Capture & Analysis   │  │
                    │  │  - TCP/IP headers           │  │
                    │  │  - Retransmissions          │  │
                    │  │  - Packet timing            │  │
                    │  │  - Flow aggregation         │  │
                    │  └────────────┬────────────────┘  │
                    └───────────────┼───────────────────┘
                                    │
        ┌───────────────────────────┴────────────────────────┐
        │                                                    │
        ▼                                                    ▼
┌───────────────────┐                         ┌──────────────────────┐
│  Hubble Observer  │                         │  System Monitoring   │
│  (User Space)     │                         │  (psutil)            │
│  ┌─────────────┐  │                         │  ┌────────────────┐  │
│  │ HTTP Parser │  │                         │  │ CPU Usage      │  │
│  │ gRPC Parser │  │                         │  │ Memory Usage   │  │
│  │ DNS Parser  │  │                         │  │ Disk I/O       │  │
│  │ Kafka Parser│  │                         │  │ OOM Events     │  │
│  └─────────────┘  │                         │  └────────────────┘  │
└─────────┬─────────┘                         └──────────┬───────────┘
          │                                              │
          └──────────────────┬───────────────────────────┘
                             │
                             ▼
                ┌────────────────────────────┐
                │  Feature Aggregator        │
                │  - Time-windowed grouping  │
                │  - 72 ML features          │
                │  - Flow correlation        │
                └────────────┬───────────────┘
                             │
                             ▼
                ┌─────────────────────────────┐
                │  CSV Output                 │
                │  ml_features_<timestamp>.csv│
                └─────────────────────────────┘
```

---

## Features Collected (72 Total)

### Network Features (38)
Captured via eBPF TC hooks on network interfaces:

| Feature | Description | Range |
|---------|-------------|-------|
| `packet_count` | Total packets in flow window | 0 - ∞ |
| `byte_count` | Total bytes transmitted | 0 - ∞ |
| `packets_per_second` | Packet rate | 0 - 10M |
| `bytes_per_second` | Throughput (bps) | 0 - 100Gbps |
| `avg_packet_size` | Average packet size | 40 - 9000 bytes |
| `retransmission_count` | TCP retransmitted packets | 0 - ∞ |
| `retransmission_rate` | Retrans / total packets | 0.0 - 1.0 |
| `consecutive_retrans` | Max consecutive retransmissions | 0 - ∞ |
| `out_of_order_count` | Out-of-order TCP packets | 0 - ∞ |
| `tcp_resets` | TCP RST flags | 0 - ∞ |
| `zero_window_count` | TCP zero window events | 0 - ∞ |
| `zero_window_duration` | Total time in zero window (sec) | 0 - ∞ |
| `syn_count` | TCP SYN packets | 0 - ∞ |
| `syn_ack_count` | TCP SYN-ACK packets | 0 - ∞ |
| `fin_count` | TCP FIN packets | 0 - ∞ |
| `rst_count` | TCP RST packets | 0 - ∞ |
| `psh_count` | TCP PSH packets | 0 - ∞ |
| `ack_count` | TCP ACK packets | 0 - ∞ |
| `urg_count` | TCP URG packets | 0 - ∞ |
| `ece_count` | TCP ECE flags | 0 - ∞ |
| `cwr_count` | TCP CWR flags | 0 - ∞ |
| `syn_to_synack_ratio` | SYN / SYN-ACK ratio | 0 - ∞ |
| `half_open_connections` | SYN without SYN-ACK | 0 - ∞ |
| `connection_state` | Flow state (NEW/ESTABLISHED/CLOSING) | categorical |
| `min_packet_size` | Smallest packet in flow | 40 - 9000 |
| `max_packet_size` | Largest packet in flow | 40 - 9000 |
| `packet_size_variance` | Packet size variance | 0 - ∞ |
| `inter_arrival_time_mean` | Avg time between packets (ms) | 0 - ∞ |
| `inter_arrival_time_std` | Std dev of arrival times | 0 - ∞ |
| `flow_duration` | Total flow duration (sec) | 0 - ∞ |
| `bidirectional_packets` | Total packets both directions | 0 - ∞ |
| `bidirectional_bytes` | Total bytes both directions | 0 - ∞ |
| `forward_packets` | Packets src→dst | 0 - ∞ |
| `backward_packets` | Packets dst→src | 0 - ∞ |
| `forward_bytes` | Bytes src→dst | 0 - ∞ |
| `backward_bytes` | Bytes dst→src | 0 - ∞ |
| `is_blocked_flow` | Flow blocked by rate limiting | 0 or 1 |
| `error_rate` | Packet error rate | 0.0 - 1.0 |

### Layer 7 Features (15)
Captured via Hubble flow observation:

| Feature | Description | Example |
|---------|-------------|---------|
| `http_status_code` | HTTP response code | 200, 404, 500 |
| `http_method` | HTTP method | GET, POST, PUT |
| `http_url` | HTTP request path | /api/users |
| `http_latency_ms` | HTTP response time | 0 - ∞ |
| `grpc_status_code` | gRPC status | 0, 14, 16 |
| `grpc_method` | gRPC method name | /service.Method |
| `dns_response_code` | DNS response code | 0 (NOERROR), 3 (NXDOMAIN) |
| `dns_query_name` | DNS query domain | example.com |
| `dns_num_answers` | DNS answer count | 0 - ∞ |
| `kafka_api_key` | Kafka API key | 0 - 18 |
| `kafka_error_code` | Kafka error code | 0 - 87 |
| `namespace` | Kubernetes namespace | default, kube-system |
| `pod_name` | Pod name | app-123-xyz |
| `service_name` | Service name | my-service |
| `l7_protocol_detected` | Protocol name | http, grpc, dns |

### System Metrics (12)
Captured via psutil and eBPF OOM tracking:

| Feature | Description | Range |
|---------|-------------|-------|
| `cpu_usage_percent` | CPU utilization | 0.0 - 100.0 |
| `memory_usage_percent` | Memory utilization | 0.0 - 100.0 |
| `memory_available_mb` | Available memory (MB) | 0 - ∞ |
| `disk_read_bytes` | Disk bytes read | 0 - ∞ |
| `disk_write_bytes` | Disk bytes written | 0 - ∞ |
| `disk_read_count` | Disk read operations | 0 - ∞ |
| `disk_write_count` | Disk write operations | 0 - ∞ |
| `disk_read_time_ms` | Disk read latency | 0 - ∞ |
| `disk_write_time_ms` | Disk write latency | 0 - ∞ |
| `disk_avg_latency_us` | Average disk latency (μs) | 0 - ∞ |
| `oom_kills` | Out-of-memory kills | 0 - ∞ |
| `process_cpu_top3` | Top 3 CPU processes | string |

### Metadata (7)

| Feature | Description |
|---------|-------------|
| `timestamp` | Unix epoch seconds |
| `flow_id` | MD5 hash of 5-tuple |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `protocol` | IP protocol (6=TCP, 17=UDP) |
| `l7_protocol` | L7 protocol ID |
| `anomaly_label` | Label for supervised learning |

---

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Kernel**: 4.19+ with BPF support
- **CPU**: 2+ cores
- **RAM**: 4GB minimum
- **Disk**: 10GB free space

### Software Dependencies
- Docker
- kubectl
- minikube (or any Kubernetes cluster)
- Python 3.8+
- Cilium CNI with Hubble enabled

---

## Installation Guide

### Step 1: Install Docker

```bash
# Update package index
sudo apt-get update

# Install dependencies
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Add your user to docker group (logout/login required)
sudo usermod -aG docker $USER

# Verify installation
docker --version
```

### Step 2: Install kubectl

```bash
# Download latest kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# Make it executable
chmod +x kubectl

# Move to system path
sudo mv kubectl /usr/local/bin/

# Verify installation
kubectl version --client
```

### Step 3: Install minikube

```bash
# Download minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64

# Install minikube
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Verify installation
minikube version
```

### Step 4: Start minikube with Cilium

```bash
# Start minikube with CNI disabled (we'll use Cilium)
minikube start --network-plugin=cni --cni=false --memory=4096 --cpus=2

# Verify minikube is running
minikube status
```

### Step 5: Install Cilium CNI

```bash
# Install Cilium CLI
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}

# Install Cilium into the cluster
cilium install

# Wait for Cilium to be ready (may take 2-3 minutes)
cilium status --wait

# Verify installation
kubectl get pods -n kube-system | grep cilium
```

### Step 6: Enable Hubble

```bash
# Enable Hubble relay and UI
cilium hubble enable --ui

# Wait for Hubble to be ready
kubectl wait --for=condition=ready pod -l k8s-app=hubble-relay -n kube-system --timeout=120s

# Verify Hubble is running
kubectl get pods -n kube-system | grep hubble

# Test Hubble CLI access
kubectl exec -n kube-system ds/cilium -- hubble observe --last 5
```

### Step 7: Install Python Dependencies

```bash
# Install pip if not already installed
sudo apt-get install -y python3-pip

# Install required Python packages
pip3 install bcc psutil pandas
```

### Step 8: Deploy Test Applications

```bash
# Create test namespace
kubectl create namespace cilium-test-1

# Deploy echo server
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-server
  namespace: cilium-test-1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - name: echo
        image: ealen/echo-server:latest
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: cilium-test-1
spec:
  selector:
    app: echo
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
EOF

# Deploy client pod
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
  namespace: cilium-test-1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: client
  template:
    metadata:
      labels:
        app: client
    spec:
      containers:
      - name: client
        image: curlimages/curl:latest
        command: ["sleep", "infinity"]
EOF

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=echo -n cilium-test-1 --timeout=60s
kubectl wait --for=condition=ready pod -l app=client -n cilium-test-1 --timeout=60s

# Verify deployment
kubectl get pods -n cilium-test-1
```

---

## Usage

### Basic Usage

#### Step 1: Find the Network Interface

Find the lxc interface for the pod you want to monitor:

```bash
# Get pod IP
kubectl get pods -n cilium-test-1 -o wide

# Find the Cilium endpoint
kubectl exec -n kube-system ds/cilium -- cilium endpoint list

# SSH into minikube and find the interface
minikube ssh
sudo ip link | grep lxc
exit
```

Example: If your pod has IP `10.0.0.67`, you might find interface `lxc8e3f4a9b2c1d`.

#### Step 2: Copy Script to minikube

```bash
# Copy the Python script to minikube
minikube cp ml_feature_exporter_minikube.py minikube:/tmp/ml_feature_exporter_minikube.py
```

#### Step 3: Run the Collector

**Monitor a specific interface:**
```bash
minikube ssh -- "sudo python3 /tmp/ml_feature_exporter_minikube.py lxc8e3f4a9b2c1d --duration 60 --label 0"
```

**Monitor all lxc interfaces:**
```bash
minikube ssh -- "sudo python3 /tmp/ml_feature_exporter_minikube.py all --duration 60 --label 0"
```

**Parameters:**
- `interface`: Network interface name or `all` for all lxc interfaces
- `--duration`: Collection duration in seconds (default: 60)
- `--window`: Aggregation window size in seconds (default: 5)
- `--output-interval`: CSV write interval in seconds (default: 10)
- `--label`: Anomaly label for supervised learning (0=normal, 1=anomaly)

#### Step 4: Generate Traffic

In another terminal, generate HTTP traffic:

```bash
# Simple test traffic
kubectl exec -n cilium-test-1 deployment/client -- sh -c '
for i in $(seq 1 100); do 
    curl -s http://echo/ > /dev/null && echo "Request $i"
    sleep 0.3
done
'
```

#### Step 5: Retrieve Results

```bash
# Copy CSV file from minikube to local machine
minikube ssh -- "ls -lh ml_features_*.csv"
minikube cp minikube:/home/docker/ml_features_hybrid_<timestamp>.csv ./
```

### Advanced Usage Examples

#### Example 1: Detect DDoS Attack

```bash
# Terminal 1: Start collector with normal traffic label
minikube ssh -- "sudo python3 /tmp/ml_feature_exporter_minikube.py all --duration 120 --label 0"

# Terminal 2: Generate normal traffic for 60 seconds
kubectl exec -n cilium-test-1 deployment/client -- sh -c '
for i in $(seq 1 200); do 
    curl -s http://echo/ > /dev/null
    sleep 0.3
done
'

# Terminal 3: After 60 seconds, simulate SYN flood (change label to 1)
# Stop the collector and restart with label 1
minikube ssh -- "sudo python3 /tmp/ml_feature_exporter_minikube.py all --duration 60 --label 1"

# Generate flood traffic
kubectl exec -n cilium-test-1 deployment/client -- sh -c '
for i in $(seq 1 10000); do 
    timeout 0.1 curl -s http://echo/ > /dev/null 2>&1 &
done
wait
'
```

#### Example 2: Monitor Network Degradation

Use the provided heavy traffic generator script:

```bash
# Make the script executable
chmod +x test_heavy_traffic.sh

# Run the test (generates high-volume traffic with packet loss)
./test_heavy_traffic.sh
```

This script:
1. Finds the client pod's interface
2. Configures 25% packet loss using `tc netem`
3. Starts the eBPF collector
4. Generates continuous large file downloads
5. Captures TCP retransmissions and performance degradation
6. Removes packet loss after test

---

## Heavy Traffic Generator Script

The `test_heavy_traffic.sh` script simulates realistic network conditions with packet loss to test retransmission detection and performance monitoring.


### What It Does

1. **Identifies Target Pod**: Finds the client pod and its network interface
2. **Simulates Packet Loss**: Uses Linux `tc` (traffic control) to drop packets
3. **Generates Heavy Traffic**: Downloads large files repeatedly to create sustained traffic
4. **Monitors TCP Behavior**: Captures retransmissions, timeouts, and degradation
5. **Cleans Up**: Removes packet loss configuration after test

### How to Use

#### Basic Usage
```bash
# Run with default settings (25% packet loss, 30 seconds)
./test_heavy_traffic.sh
```

#### Modify Test Parameters

Edit the script to change:

```bash
# At the top of test_heavy_traffic.sh
PACKET_LOSS="25%"      # Change to 10%, 50%, etc.
TEST_DURATION="30"     # Change duration in seconds
FILE_SIZE="10M"        # Change download size (1M, 50M, 100M)
```

#### Expected Output

```
==============================================
High-Volume Traffic Test with Retransmissions
==============================================

Client pod: client-5b9b5866cb-pvsm6
Client interface: lxc8e3f4a9b2c1d
Test duration: 30s

[1/4] Configuring 25% packet loss on lxc8e3f4a9b2c1d...
✓ Packet loss configured

[2/4] Copying eBPF tracer to minikube...
✓ Script copied

[3/4] Starting eBPF tracer on lxc8e3f4a9b2c1d...
    This will collect TCP retransmission data...

[4/4] Generating heavy HTTP traffic (10MB downloads)...
    This will cause many TCP retransmissions...

Download 1: 100% [========================================]
Download 2: 100% [========================================]
...

[OK] Saved to ml_features_hybrid_1769505828.csv
    148 rows collected, 100 flows with retransmissions

[CLEANUP] Removing packet loss...
✓ Packet loss removed
```

### Analyzing Results

After the test completes:

```bash
# Find the generated CSV
ls -lht ml_features_*.csv | head -1

# Check retransmission statistics
# Columns to examine:
# - retransmission_count (should be > 0)
# - retransmission_rate (0.2-0.4 for 25% loss)
# - consecutive_retrans
# - tcp_resets
# - zero_window_count

# Example: Extract retransmission data
cut -d',' -f1,19,20,21 ml_features_hybrid_<timestamp>.csv | head -20
```

### Customization Examples

#### Test with Higher Packet Loss (50%)
```bash
# Edit the script
sed -i 's/PACKET_LOSS="25%"/PACKET_LOSS="50%"/' test_heavy_traffic.sh

# Run the test
./test_heavy_traffic.sh
```

#### Test with Larger Files (100MB)
```bash
# Edit the file size
sed -i 's/FILE_SIZE="10M"/FILE_SIZE="100M"/' test_heavy_traffic.sh

# Run the test
./test_heavy_traffic.sh
```

#### Test with Latency Instead of Packet Loss
```bash
# Edit the tc command in the script
# Change this line:
# minikube ssh -- "sudo tc qdisc add dev $CLIENT_INTERFACE root netem loss $PACKET_LOSS"

# To add 200ms latency:
# minikube ssh -- "sudo tc qdisc add dev $CLIENT_INTERFACE root netem delay 200ms"
```

---

## Understanding the Output

### CSV File Format

The output file `ml_features_hybrid_<timestamp>.csv` contains:
- **Header row**: Column names for all 72 features
- **Data rows**: One row per flow window (default: 5-second windows)
- **Format**: Standard CSV with comma separators

### Sample Output

```csv
timestamp,flow_id,src_ip,dst_ip,src_port,dst_port,protocol,l7_protocol,packet_count,byte_count,packets_per_second,bytes_per_second,avg_packet_size,retransmission_count,retransmission_rate,...
1769505828,a1b2c3d4,10.0.0.67,10.0.0.95,45678,80,6,1,150,75000,30.0,15000.0,500.0,5,0.033,...
1769505833,e5f6g7h8,10.0.0.67,10.96.0.10,54321,53,17,3,2,164,0.4,32.8,82.0,0,0.0,...
```

### Key Metrics to Monitor

**Normal Traffic Patterns:**
- `retransmission_rate`: < 0.01 (1%)
- `syn_to_synack_ratio`: ~1.0
- `packets_per_second`: Consistent
- `http_status_code`: Mostly 200

**Attack/Anomaly Indicators:**
- High `retransmission_rate` (> 0.1)
- High `syn_to_synack_ratio` (> 10) → SYN flood
- Unusual `packets_per_second` spikes
- Many `tcp_resets`
- High `half_open_connections`
- HTTP errors (4xx, 5xx codes)

---

## Troubleshooting

### Issue: "Command not found: hubble"
**Solution:**
```bash
# Verify Hubble is installed
kubectl get pods -n kube-system | grep hubble

# If not installed, enable Hubble
cilium hubble enable
```

### Issue: "No such file or directory: libcc.so"
**Solution:**
```bash
# Install BCC tools
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)

# Install Python BCC library
pip3 install bcc
```

### Issue: "Permission denied" when running script
**Solution:**
```bash
# The script requires root privileges for eBPF
# Run with sudo inside minikube:
minikube ssh -- "sudo python3 /tmp/ml_feature_exporter_minikube.py all --duration 60"
```

### Issue: "No HTTP data collected"
**Possible causes:**
1. **Hubble not observing flows**: Check `kubectl exec -n kube-system ds/cilium -- hubble observe --last 10`
2. **Timing mismatch**: HTTP data arrives after flow window closes (expected ~5-10% coverage)
3. **Wrong interface**: Ensure you're monitoring the correct lxc interface

**Solution for better L7 coverage:**
- Increase window size: `--window 30`
- Generate slower traffic with longer connections
- Use persistent connections (HTTP keep-alive)

### Issue: "Negative or extreme rate values"
**Fixed in latest version**. If you see this:
- Update to the latest script version
- Ensure `window_size` is configured correctly
- Check that eBPF timestamps are being handled properly

### Issue: "Interface not found"
**Solution:**
```bash
# Re-identify the pod's interface
kubectl get pods -n cilium-test-1 -o wide

# Find the interface in minikube
minikube ssh -- "sudo ip link | grep lxc"

# Use the correct interface name or 'all'
```

---

## Best Practices

### Data Collection
1. **Start with normal traffic**: Collect baseline data with `--label 0`
2. **Label your data**: Use different labels for different scenarios
3. **Consistent windows**: Keep `--window` size consistent for training data
4. **Multiple interfaces**: Use `all` for comprehensive cluster monitoring

### Performance Optimization
1. **Increase output interval**: Use `--output-interval 30` for less frequent writes
2. **Filter interfaces**: Monitor specific interfaces instead of `all` when possible
3. **Limit duration**: Don't run indefinitely; collect in batches

### ML Model Training
1. **Balanced dataset**: Collect equal amounts of normal (0) and anomaly (1) data
2. **Feature selection**: Not all 72 features may be relevant; analyze correlation
3. **Normalization**: Normalize rates and counts before training
4. **Time series**: Consider temporal patterns in sequential windows

---

## File Structure

```
ebpf/
├── ml_feature_exporter_minikube.py    # Main eBPF + Hubble collector
├── test_heavy_traffic.sh              # Traffic generator with packet loss
├── README.md                          # This documentation
└── ml_features_hybrid_<timestamp>.csv # Output CSV files
```

---

## References

- **eBPF**: https://ebpf.io/
- **BCC Tools**: https://github.com/iovisor/bcc
- **Cilium**: https://cilium.io/
- **Hubble**: https://github.com/cilium/hubble
- **Kubernetes**: https://kubernetes.io/

---
