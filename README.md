# Firewall and Intrusion Detection System using P4

## Firewall
- Implemented a simple one-way firewall function in the L2 switch s1.
- The switch drops all traffic from host h1 going to other host but still forward traffic from all other host to h1.

![Alt text](https://raw.githubusercontent.com/hoangnguyen2809/Firewall-IDS/master/diagram/one-way-firewall.png)

### Build
- start the network `sudo python network.py`
- start the controller `sudo python controller.py`
- use mininet cli to experiment with the network traffic

## Simple Intrusive Detection System

- Implemented a layer 4 signature-based IDS, the signature is located in the first few bytes of the TCP payload in the packet.
- Stateless IDS detects intrusions based on the payload of a single TCP packet.
- Stateful IDS detects intrusions based on the payloads of multiple packets on the same flow.


![Alt text](https://raw.githubusercontent.com/hoangnguyen2809/Firewall-IDS/master/diagram/ids.png)


### Build
- start the network `sudo python network.py`
- start the controller `sudo python controller.py`
- use mininet cli to experiment with the network traffic

