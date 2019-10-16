# roneo
NetFlow Duplicator: ingest NetFlow from multiple and send it out to multiple collectors.

## Why
After using [Samplicator](https://github.com/sleinen/samplicator) for a long time, it no longer sufficed for environments where a large number of flows were generated and devices are present that do not use the default NetFlow templates.

Roneo is a stripped down Python service, with only the necessary functions to forward NetFlow traffic. Any UDP traffic really, but it's designed for NetFlow.

## NetFlow (or sFlow, IPFIX)
Roneo has been tested with NetFlow version v5, v7, v9, and v10 (also known as IPFIX) and sFlow. 

Scale wise, it has been tested on a VM with 2 vCPUs and 4GB of memory. It took in 611Mbit p/s of NetFlow, resending it out to 4 target collectors. This is around 300Gbit p/s of real network traffic (average enterprise traffic). 

# Scapy
The Python module called Scapy is used to be able to spoof the NetFlow source IP. This way, the collectors seem to get the traffic directly from the source devices. Roneo was created to support vRealize Network Insight, which does some correlation with the NetFlow source IP. For the spoofing to work, it's important to place Roneo in the same IP subnet as the collectors.

# Installation

```
mkdir /opt && cd /opt
git clone https://github.com/smitmartijn/roneo-netflow-duplicator.git
cd roneo-netflow-duplicator
pip install -r requirements.txt
cp roneo-config-example.yaml /etc/roneo-config.yaml
# Edit config
(vi|nano|vim|pico|editorofyourchoice) /etc/roneo-config.yaml
python3 main.py --configfile roneo-config.yaml
```

# Starting on system boot

For CentOS 7 / SystemD systems:

```
cp /opt/roneo-netflow-duplicator/roneo.service /etc/systemd/system/roneo.service
systemctl daemon-reload
systemctl enable roneo
systemctl start roneo
```
