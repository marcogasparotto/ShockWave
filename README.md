# ⚡ SHOCKWAVE ⚡

<p align="center">
    <img src="assets/shockwave.png" width="700">
</p>

<p align="center">
<b>Advanced Network Reconnaissance & Analysis Toolkit</b><br>
<i>Decepticon Intelligence Unit</i><br><br>

"Logic. Superiority. Objective: Control."
</p>

---

# 📖 Sobre

**SHOCKWAVE** é uma ferramenta de reconhecimento e análise de redes desenvolvida em Python, projetada para fornecer uma suíte completa de coleta de informações, enumeração, diagnóstico e identificação de serviços.

O projeto busca reunir, em uma única interface de terminal, as funcionalidades mais utilizadas durante as fases de **Network Reconnaissance**, permitindo analisar hosts, serviços, infraestrutura e protocolos de forma rápida e organizada.

Seu foco é oferecer uma experiência moderna para administradores de redes, estudantes e profissionais de segurança que realizam avaliações em ambientes autorizados.

---

# ✨ Funcionalidades

## 🌍 Descoberta de Rede

- Host Resolver
- Reverse DNS
- Ping
- Ping Sweep
- ARP Scan
- TCP Host Discovery
- UDP Host Discovery
- CIDR Scanner
- Gateway Detection
- Network Interface Discovery
- MAC Address Discovery
- Vendor Identification (OUI)

---

## 🔍 Enumeração

- DNS Lookup
- WHOIS Lookup
- ASN Lookup
- GeoIP Lookup
- Subdomain Enumeration
- DNSSEC Detection
- Zone Transfer Check
- CDN Detection

---

## 🚪 Port Scanning

- Common Port Scan
- Full Port Scan
- Custom Port Scan
- TCP Scan
- UDP Scan
- SYN Scan
- ACK Scan
- FIN Scan
- NULL Scan
- XMAS Scan
- Window Scan
- Idle Scan
- Fragment Scan
- Adaptive Timing

---

## 🖥️ Identificação de Serviços

- Banner Grabbing
- Service Detection
- Version Detection
- HTTP Detection
- SSH Detection
- FTP Detection
- SMTP Detection
- SMB Detection
- SNMP Detection
- Database Detection
- MQTT Detection
- Redis Detection

---

## 🧠 Fingerprinting

- Operating System Detection
- Device Type Detection
- TCP/IP Stack Analysis
- TTL Analysis
- MSS Analysis
- Window Size Analysis

---

## 🔐 SSL / TLS

- Certificate Viewer
- Certificate Validation
- Cipher Enumeration
- TLS Version Detection
- HSTS Detection
- ALPN Detection
- Weak Cipher Detection
- Expiration Checker

---

## 🌐 HTTP Analysis

- HTTP Headers
- Security Headers
- Cookie Analysis
- Redirect Detection
- Compression Detection
- HTTP Methods
- HTTP/2 Detection
- HTTP/3 Detection
- robots.txt
- sitemap.xml
- Web Technology Detection

---

## 📡 Packet Analysis

- Live Packet Capture
- PCAP Reader
- Protocol Statistics
- TCP Stream Analysis
- DNS Analysis
- HTTP Analysis
- TLS Handshake Analysis
- ICMP Analysis
- Bandwidth Statistics

---

## 📊 Performance

- Latency
- Packet Loss
- Jitter
- MTU Discovery
- Path MTU
- Throughput Estimation

---

## 📄 Relatórios

- JSON Export
- HTML Report
- CSV Export
- XML Export
- PDF Report
- Scan Comparison

---

# 🚀 Instalação

```bash
git clone https://github.com/marcogasparotto/shockwave.git

cd shockwave

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

---

# ▶️ Executando

```bash
python -m shockwave <host>
```

ou

```bash
pip install -e .

shockwave <host>
```

---

# 💻 Comandos

| Categoria | Comandos |
|------------|----------|
| Reconhecimento | resolve, dns, whois, geo, asn |
| Descoberta | ping, sweep, arp, discover |
| Escaneamento | scan, cscan, syn, udp |
| Serviços | banner, detect, version |
| HTTP | headers, cookies, methods |
| SSL | ssl, tls |
| Sistema | netinfo |
| Utilidades | clear, help, target, banner, exit |

---

# 🗺️ Roadmap

## Core

- [x] Host Resolver
- [x] DNS Lookup
- [x] Ping
- [x] Ping Sweep
- [x] Port Scanner
- [x] HTTP Headers
- [x] WHOIS
- [x] GeoIP
- [x] Traceroute

---

## Network Discovery

- [ ] ARP Scanner
- [ ] CIDR Scanner
- [ ] Reverse DNS
- [ ] Gateway Discovery
- [ ] MAC Discovery
- [ ] Vendor Lookup
- [ ] Interface Enumeration

---

## Port Scanner

- [ ] Full TCP Scan
- [ ] UDP Scan
- [ ] SYN Scan
- [ ] ACK Scan
- [ ] FIN Scan
- [ ] NULL Scan
- [ ] XMAS Scan
- [ ] Idle Scan
- [ ] Fragment Scan
- [ ] Timing Profiles

---

## Enumeration

- [ ] Banner Grabbing
- [ ] Service Detection
- [ ] Version Detection
- [ ] ASN Lookup
- [ ] DNSSEC
- [ ] Zone Transfer
- [ ] CDN Detection
- [ ] Subdomain Enumeration

---

## Fingerprinting

- [ ] OS Detection
- [ ] Device Identification
- [ ] TCP/IP Stack Analysis
- [ ] TTL Analysis

---

## SSL / TLS

- [ ] Certificate Viewer
- [ ] TLS Detection
- [ ] Cipher Enumeration
- [ ] Weak Cipher Detection
- [ ] Expiration Alerts

---

## HTTP

- [ ] HTTP Methods
- [ ] Cookie Analysis
- [ ] CSP Detection
- [ ] Redirect Analysis
- [ ] robots.txt
- [ ] sitemap.xml
- [ ] Web Technology Detection

---

## Packet Analysis

- [ ] Live Capture
- [ ] PCAP Reader
- [ ] TCP Streams
- [ ] Protocol Statistics

---

## Reporting

- [ ] HTML Report
- [ ] JSON Export
- [ ] CSV Export
- [ ] XML Export
- [ ] PDF Report

---

## Interface

- [ ] Plugin System
- [ ] Configuration Profiles
- [ ] Session Save
- [ ] Autocomplete
- [ ] Command History
- [ ] Themes

---

# 📦 Dependências

- Python 3.8+
- Rich
- Requests
- dnspython

Ferramentas do sistema:

- ping
- traceroute
- dig

---

# ⚠️ Aviso

O SHOCKWAVE foi desenvolvido para fins de estudo, administração e reconhecimento de redes.

Utilize a ferramenta apenas em sistemas e redes para os quais você possua autorização.

---

# 🚧 Estado do Projeto

**Versão atual:** `v0.0.1`

O SHOCKWAVE está em desenvolvimento contínuo e tem como objetivo se tornar uma suíte completa de reconhecimento e análise de redes para ambientes autorizados.
