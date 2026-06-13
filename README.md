🌌 NexusBulker Studio: Geo-Analytics Edition

NexusBulker Studio (Geo-IP & Analytics Edition) is an elegant, production-grade cross-platform PySide6 desktop suite designed to inspect, parse, validate, filter, override, and bulk-rename proxy configuration profiles. It features deep geo-location profiling, live TCP latency checking, and advanced proxy chaining engines.

Whether you are managing tens of custom proxy endpoints or restructuring thousands of bulk-harvested subscription lines (Clash YAML / V2Ray URIs), NexusBulker provides high-performance asynchronous execution, custom telemetry visualizations, and absolute control over node data structure.

✨ Features Highlight

Multi-Protocol Compatibility: Full validation, parsing, and modification capabilities for VMess, VLESS, Trojan, Shadowsocks (SS), SSR, Hysteria, and Hysteria 2 (Hy2) protocols. Supports native proxy URIs and complex multi-node Clash YAML environments.

Dynamic Tag Renamer: Real-time evaluation of naming schemas using a high-fidelity template engine featuring country flags, cities, ASNs, speeds, sequential numbering padding, and randomized structural aesthetics.

High-Concurrency Engine: Asynchronous geo-lookup and live latency scanning managed via an integrated thread-pool architecture operating with adjustable socket-level isolation.

Sub-Routing & Proxy Bypass Integration: Avoid rate-limiting by routing Geo-IP lookups directly through one of your valid parsed proxy nodes. Integrates seamlessly with an external sing-box process acting as a localized SOCKS5 gateway.

Dual-Tier Geolocation Resolution: Custom priority selection across 7 public APIs, featuring sequential fallback algorithms or strict majority-vote Consensus mode.

Multi-Dimensional Matrix Overrides: Effortlessly assign custom load-balancer IPs or duplicate host profiles over hundreds of proxies in a multi-variable combination setup.

Sub-Folder Sort & File Splitting: Auto-categorize configurations based on geographical countries and chunk out split configurations in target sizes.

🛠️ Deep Dive: Mathematical Matrix & Consensus Engines

1. Cartesian Matrix Override Model

When performing infrastructure migrations or bulk SNI updates, you can provide a pool of Hosts $H = \{h_1, h_2, \dots, h_m\}$ and Ports $P = \{p_1, p_2, \dots, p_n\}$. For every configuration node $C_k$ in your collection, NexusBulker Studio builds a Cartesian variant space $V(C_k)$ defined as:

$$V(C_k) = \left\{ \operatorname{Variant}(C_k, h, p) \mid h \in H, p \in P \right\}$$

This automatically scales your infrastructure space, projecting precisely $|V(C_k)| = |H| \times |P|$ dynamic combinations per input item.

2. Multi-API Consensus Geo-Engine

To eliminate lookup errors and geographical data deviations across different public providers, NexusBulker includes a strict Consensus Mode. Under this mode, the program queries a subset of $M$ active Geo-IP backends. For a given IP address, let the output country returned by provider $i$ be $C_i$. The final resolved geo-property $C_{\text{final}}$ is determined as the mode of the dataset:

$$C_{\text{final}} = \underset{c}{\operatorname{arg\,max}} \sum_{i=1}^{M} \delta(C_i, c)$$

Where $\delta(x, y)$ is the Kronecker delta function:

$$\delta(x, y) = \begin{cases} 
1 & \text{if } x = y \\
0 & \text{if } x \neq y 
\end{cases}$$

If no single majority is reached, the engine automatically triggers sequential fallback mechanisms based on priority rankings.

📋 Dynamic Renaming Tag Directory

Tailor node descriptions in real-time by combining native metadata, geo-metrics, and layout formats. Use these templates directly inside the styling field:

Tag

Rendered Element

Practical Output Example

<protocol>

Up-cased protocol signature

VMESS, VLESS, HYSTERIA2

<country>

Geo-API Resolved Country Name

United States, Singapore, Japan

<city>

Geo-API Resolved City Name

New York, Changi, Tokyo

<flag>

High-resolution Unicode flag

🇺🇸, 🇸🇬, 🇯🇵

<asn>

Autonomous System Number & ISP name

AS16509 Amazon.com

<ping>

Active TCP Handshake Latency

45 (ms) or Timeout

<num>

Serial incrementing counter

1, 2, 3...

<num:padding>

Serial counter with custom zero-padding

<num:3> $\rightarrow$ 001, 002...

<emoji>

High-performance random network emojis

⚡

<heart>

Randomized aesthetic layout hearts

🧡, 💙, 💜

🚀 Getting Started

Prerequisites

Python 3.9, 3.10, or 3.11

Pip (Python Package Installer)

(Optional) A working sing-box executable in your environment if you intend to enable SOCKS5 API tunnel shielding.

Installation

Clone the project to your local workstation:

git clone https://github.com/yourusername/NexusBulker-Studio.git
cd NexusBulker-Studio


Install runtime and library dependencies:

pip install -r requirements.txt


Note: If a requirements.txt is not provided, manual installation is simple:

pip install PySide6 PyYAML


Launch the graphical studio:

python main.py


💻 Interface Layout & Architecture

The application is built on a custom high-performance split layout context:

┌─────────────────────────────────────────┬─────────────────────────────────────────┐
│              INPUT CONTROLS             │            WORKSPACE PREVIEW            │
│ ┌─────────────────────────────────────┐ │ ┌─────────────────────────────────────┐ │
│ │  Paste Links, Subscriptions, URIs   │ │ │  Live Interactive Preview Table     │ │
│ │  or Clash YAML configurations       │ │ │  (Columns: Proto, Name, Preview)   │ │
│ └─────────────────────────────────────┘ │ └─────────────────────────────────────┘ │
│ ┌─────────────────────────────────────┐ │ ┌─────────────────────────────────────┐ │
│ │  Bulk DNS/Port Custom Matrix Tools  │ │ │  Live Telemetry Panel               │ │
│ └─────────────────────────────────────┘ │ │  (Speed, Latency Ratio, API stats)  │ │
│ ┌─────────────────────────────────────┐ │ └─────────────────────────────────────┘ │
│ │  Geo-IP Provider Fallback Settings  │ │ ┌─────────────────────────────────────┐ │
│ └─────────────────────────────────────┘ │ │  Split, Sorting, & Concurrency bars │ │
│ ┌─────────────────────────────────────┐ │ └─────────────────────────────────────┘ │
│ │  Real-time System Logging Console   │ │ │  [🛑 STOP]             [🚀 PROCESS]  │ │
│ └─────────────────────────────────────┘ │ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┴─────────────────────────────────────────┘


Advanced Routing Configuration

To utilize a proxy node as a secure gate for your API geo-lookups:

Check "Connect through configs" inside the Geo API box.

Provide the local file path to your sing-box binary.

Define the targeting proxy indexing parameter (e.g. 1 for the first listed proxy) and input a vacant SOCKS5 port (e.g. 2080).

NexusBulker will run a lightweight, automated background configuration, dynamically route your lookup traffic safely, and secure your public IP from regional rate limits.

📄 License & Terms

NexusBulker Studio is distributed under the MIT License. Check out LICENSE for details.

Disclaimer: This system is built strictly for personal diagnostics, configuration management, and subscription tuning. Users assume full legal responsibility for configurations processed and compliance with local network regulations."# NexusBulker" 
