#!bin/sh

cd vnetUtils/helper

# Setup relay and receiver
echo "[test-relay] Setting up relays..."
sudo ./execNS ns2 ../../target/debug/relay 1 veth2-1 veth2-3 &
sudo ./execNS ns3 ../../target/debug/relay 1 veth3-2 veth3-4 veth3-0 &
sudo ./execNS ns4 ../../target/debug/receiver veth4-3 &

sleep 3
# Send the packet and watch
echo "[test-relay] Packet sent..."
sudo ./execNS ns1 ../../target/debug/sender 11:22:33:44:55:66 veth1-2 hello-world &
sleep 3

echo "[test-relay] Done"