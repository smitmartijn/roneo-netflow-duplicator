# roneo
NetFlow Duplicator: ingest NetFlow from multiple and send it out to multiple collectors.

## Why
After using [Samplicator](https://github.com/sleinen/samplicator) for a long time, it no longer sufficed for environments where a large number of flows were generated and devices are present that do not use the default NetFlow templates.

Roneo is a stripped down Python service, with only the necessary functions to forward NetFlow traffic. Any UDP traffic really, but it's designed for NetFlow.

# Scapy
The Python module called Scapy is used to be able to spoof the NetFlow source IP. This way, the collectors seem to get the traffic directly from the source devices. Roneo was created to support vRealize Network Insight, which does some correlation with the NetFlow source IP.

# Installation

```
git clone https://github.com/smitmartijn/roneo-netflow-duplicator.git
cd roneo-netflow-duplicator
pip install -r requirements.txt
python3 main.py --collector_ips 10.0.0.10 --bind_ip 10.0.0.9 --collector_port 2055 --bind_port 2055
```
