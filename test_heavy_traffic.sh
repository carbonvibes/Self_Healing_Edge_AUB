#!/bin/bash
# Aggressive traffic test with packet loss to trigger many retransmissions

set -e

CLIENT_INTERFACE="lxc564692f1eecf"
CLIENT_POD="client-5b9b5866cb-pvsm6"
CLIENT_NAMESPACE="cilium-test-1"
TEST_DURATION=30

echo "=============================================="
echo "High-Volume Traffic Test with Retransmissions"
echo "=============================================="
echo ""
echo "Client pod: $CLIENT_POD"
echo "Client interface: $CLIENT_INTERFACE"
echo "Test duration: ${TEST_DURATION}s"
echo ""

# Step 1: Add 25% packet loss (enough to cause retransmissions, not too much to break connections)
echo "[1/4] Configuring 25% packet loss on $CLIENT_INTERFACE..."
minikube ssh -- "sudo tc qdisc del dev $CLIENT_INTERFACE root 2>/dev/null || true"
minikube ssh -- "sudo tc qdisc add dev $CLIENT_INTERFACE root netem loss 25% delay 20ms"
echo "✓ Packet loss + latency configured"
echo ""

# Step 2: Copy script
echo "[2/4] Copying eBPF tracer..."
minikube cp /home/arjun/Documents/ebpf/ml_feature_exporter_minikube.py minikube:/tmp/ml_feature_exporter_minikube.py
echo "✓ Script ready"
echo ""

# Step 3: Start tracer
echo "[3/4] Starting eBPF tracer..."
minikube ssh -- "sudo python3 /tmp/ml_feature_exporter_minikube.py all --duration $TEST_DURATION --label 0 --output-interval 10" &
TRACER_PID=$!

sleep 3

# Step 4: Generate CONTINUOUS high-volume traffic
echo "[4/4] Generating continuous heavy traffic..."
echo "    - Downloading 5MB files repeatedly"
echo "    - Running 5 parallel connections"
echo "    - With 25% packet loss, expect MANY retransmissions!"
echo ""

# Run 5 parallel download loops
for i in {1..5}; do
  kubectl exec -n $CLIENT_NAMESPACE $CLIENT_POD -- sh -c "
    for j in \$(seq 1 100); do 
      curl -s --max-time 10 http://nginx-server/large.bin -o /dev/null || true
      sleep 0.1
    done
  " &
done

echo "Traffic generation started (5 parallel streams)..."
echo ""

# Wait for tracer to complete
wait $TRACER_PID 2>/dev/null || true

# Kill any remaining curl processes
pkill -f "kubectl exec.*client.*curl" 2>/dev/null || true

echo ""
echo "[CLEANUP] Removing packet loss..."
minikube ssh -- "sudo tc qdisc del dev $CLIENT_INTERFACE root 2>/dev/null || true"
echo "✓ Network restored"
echo ""

echo "=============================================="
echo "Test Complete!"
echo "=============================================="
echo ""
echo "Latest CSV file:"
ls -lht /home/arjun/Documents/ml_features_*.csv | head -1
echo ""
echo "Quick stats:"
CSV_FILE=$(ls -t /home/arjun/Documents/ml_features_*.csv 2>/dev/null | head -1)
if [ -f "$CSV_FILE" ]; then
  echo "  Total rows: $(wc -l < "$CSV_FILE")"
  echo "  Flows with retransmissions: $(awk -F',' 'NR>1 && $19>0 {count++} END {print count+0}' "$CSV_FILE")"
  echo "  Max retransmission rate: $(awk -F',' 'NR>1 {if($20>max) max=$20} END {print max+0}' "$CSV_FILE")"
  echo ""
  echo "View retransmission data:"
  echo "  awk -F',' 'NR==1 || \$19>0' \"$CSV_FILE\" | cut -d',' -f1,19,20,21,58,59 | head -20"
fi
echo ""
