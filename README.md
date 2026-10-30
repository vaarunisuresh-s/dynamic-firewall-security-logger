# SDN Dynamic Firewall with Security Event Logger
Mininet + OS-Ken (OpenFlow 1.3) + TCP sockets. Group 1, Problem 1.

## Architecture
```
 h1,h2,h3 (TCP clients) ---\
                            s1 (Open vSwitch) --- h4 (TCP servers: 80, 8080, 23, 4444)
                             |  OpenFlow 1.3 (127.0.0.1:6653)
                       OS-Ken controller  --TCP (9999)-->  log_server.py (central security-event log)
```
- **tcp_server.py / tcp_client.py** - low-level multi-client TCP app (MSG / BULK / QUIT protocol, error handling).
- **controller.py** - learning switch + dynamic firewall. Policy in **firewall_rules.py** (source / destination / protocol / port -> allow / deny / block).
  Repeated denies (3 in 30 s) -> auto-block flow (priority 20, 30 s hard timeout) -> FlowRemoved -> RECOVERY.
- **log_server.py** - centralized socket logging server; **security_logger.py** sends events to it (local file fallback).
- **baseline_controller.py** - static learning switch with no firewall (comparison baseline).
- **topology.py** - Mininet topology. **experiment.py** - automated latency / throughput / block / recovery / robustness tests.

## Setup (Ubuntu VM)
```bash
cd ~/dynamic_firewall
source osken311/bin/activate          # OS-Ken venv
python3 -c "import mininet" && echo mininet ok
```

## Run the demo (3 terminals)
```bash
# T1  central log server
cd ~/dynamic_firewall && python3 log_server.py
# T2  controller (venv)
cd ~/dynamic_firewall && source osken311/bin/activate && osken-manager controller.py
# T3  topology
cd ~/dynamic_firewall && sudo mn -c && sudo python3 topology.py
```
In the Mininet CLI:
```
pingall
h1 python3 tcp_client.py 10.0.0.4 80            # allowed
h1 python3 tcp_client.py 10.0.0.4 23 --timeout 1  # denied (repeat 3x -> AUTO-BLOCK)
h1 python3 tcp_client.py 10.0.0.4 80            # now blocked
h2 python3 tcp_client.py 10.0.0.4 80            # other client unaffected
sh ovs-ofctl -O OpenFlow13 dump-flows s1
# wait 30 s -> RECOVERY appears in T1/T2, h1 works again
```

## Experiments (baseline vs dynamic)
```bash
# controller.py running in T2 (and log_server in T1):
sudo mn -c && sudo python3 experiment.py --label dynamic
# stop T2 (Ctrl+C), start the baseline controller instead:
osken-manager baseline_controller.py
sudo mn -c && sudo python3 experiment.py --label baseline
cat results/results.csv
```
Logs: `logs/security_events.log` (controller, local) and `logs/central_security_events.log` (log server).
