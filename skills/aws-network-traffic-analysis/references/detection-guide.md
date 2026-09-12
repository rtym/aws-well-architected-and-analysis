# What each query is looking for, and GuardDuty's network finding types

## The canned Flow Log Insights queries (`network_traffic.QUERIES`)

| Query | What it surfaces | How to read it |
|---|---|---|
| `top_talkers_by_bytes` | Highest-volume src/dst pairs | Establishes a traffic baseline; a pair far above the rest is worth naming even if not malicious |
| `rejected_traffic` | Highest-count REJECT actions by src/dst/port | Repeated rejects from one source at one port is the flow-log signature of scanning or a misconfigured client -- distinguish the two by whether the source is internal (misconfig) or external (scan) |
| `distinct_dst_ports_per_src` | Sources contacting an unusually wide port range | Feeds the port-scan heuristic (`PORT_SCAN_DISTINCT_PORT_THRESHOLD = 15` distinct ports) |
| `top_external_egress` | Highest-volume flows to non-RFC1918 destinations | Candidate exfiltration path -- also frequently legitimate (backups, CDN, SaaS integration); always ask before asserting exfiltration |
| `traffic_by_protocol` | Byte/flow totals by IP protocol number | A baseline sanity check -- protocol `6` is TCP, `17` is UDP, `1` is ICMP; a spike in an unexpected protocol (e.g. heavy ICMP) is itself a signal |

The port-scan heuristic is intentionally simple (a distinct-destination-port
count) -- it is a lead to investigate, not a confirmed detection. Corroborate
with GuardDuty before escalating.

## GuardDuty network-related finding types

Source: AWS docs, `guardduty/latest/ug/guardduty_finding-types.html`. This
skill's `network_findings()` collector filters to these prefixes:
`Recon:`, `UnauthorizedAccess:`, `Trojan:`, `Backdoor:`, `CryptoCurrency:`,
`Impact:`, `Behavior:`.

| Finding type (examples) | What it means |
|---|---|
| `Recon:EC2/Portscan`, `Recon:EC2/PortProbeUnprotectedPort` | Port scanning/probing detected against an EC2 resource, sourced from VPC Flow Logs |
| `UnauthorizedAccess:EC2/SSHBruteForce`, `.../RDPBruteForce` | Brute-force attempts against SSH/RDP |
| `UnauthorizedAccess:EC2/TorClient`, `.../TorRelay` | Traffic to/from the Tor anonymizing network |
| `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom` | Traffic involving an IP on a custom threat list you've configured |
| `Backdoor:EC2/C&CActivity.B[!DNS]` | Communication with a known command-and-control server |
| `Backdoor:EC2/DenialOfService.{Dns,Tcp,Udp,UdpOnTcpPorts,UnusualProtocol}` | The instance itself appears to be participating in a DoS attack (i.e., likely compromised and being used as an attack source) |
| `Trojan:EC2/DNSDataExfiltration` | DNS query patterns consistent with data exfiltration over DNS |
| `Trojan:EC2/DGADomainRequest.*` | Requests to domains matching a Domain Generation Algorithm pattern (malware C2 rendezvous) |
| `Trojan:EC2/BlackholeTraffic[!DNS]`, `.../DropPoint[!DNS]` | Traffic to a known malware drop point/blackhole |
| `CryptoCurrency:EC2/BitcoinTool.B[!DNS]` | Crypto-mining traffic pattern |
| `Behavior:EC2/{NetworkPortUnusual,TrafficVolumeUnusual}` | GuardDuty's own ML baseline flagging traffic that deviates from the resource's learned normal pattern -- the closest native equivalent to this skill's own heuristics, and a good corroboration signal |
| `Impact:EC2/{PortSweep,WinRMBruteForce,MaliciousDomainRequest.*}` | DNS-reputation and sweep-based impact findings |

Note: GuardDuty's finding-type catalogue is reorganized periodically --
re-check the finding-types doc above if a finding type appears in your
account that isn't in this table; don't assume it's out of scope just
because it's unlisted here.

## Escalation guidance (general practice, verify against your org's IR plan)

For any confirmed `Trojan:`/`Backdoor:`/`CryptoCurrency:` finding
corroborated by flow-log evidence:

1. Isolate the resource (move to a quarantine security group with no
   egress, or stop it if isolation via network controls isn't fast enough)
   rather than terminating it immediately -- you may need it for forensics.
2. Rotate/revoke any IAM credentials the resource had access to.
3. Check CloudTrail for follow-on API activity from those credentials.
4. This is general incident-response practice, not a specific AWS
   documentation citation -- confirm against your organization's actual
   incident response runbook before acting, and treat this skill's report
   as an input to that process, not a replacement for it.
