<p align="center">
  <img src="assets/shockwave.png" width="700">
</p>

<h1 align="center">⚡ SHOCKWAVE ⚡</h1>

<p align="center">
  <b>Suite completa de reconhecimento e diagnóstico de redes</b><br>
  <i>Todas as ferramentas que você precisa em uma única interface de terminal</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-purple?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/versão-2.0.0-blueviolet?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/módulos-90+-darkviolet?style=for-the-badge" alt="Modules">
  <img src="https://img.shields.io/badge/tema-roxo%20%26%20preto-8b00ff?style=for-the-badge" alt="Theme">
  <img src="https://img.shields.io/badge/licença-MIT-mediumpurple?style=for-the-badge" alt="License">
</p>

---

## 📖 Sobre

**SHOCKWAVE** é uma ferramenta de reconhecimento e análise de redes desenvolvida em Python, projetada para profissionais de segurança, administradores de redes e estudantes. Ela reúne **mais de 90 funcionalidades** em uma interface de terminal moderna com tema **roxo e preto**.

O projeto organiza as ferramentas em **10 categorias** que cobrem todo o ciclo de reconhecimento de rede — desde a descoberta de hosts até a geração de relatórios em múltiplos formatos.

---

## 🚀 Instalação

```bash
# Clone o repositório
git clone https://github.com/marcogasparotto/shockwave-complete.git
cd shockwave-complete

# Instale as dependências
pip install -r requirements.txt

# Execute
python -m shockwave <alvo>
```

**Exemplo:**
```bash
python -m shockwave google.com
python -m shockwave 192.168.1.1
python -m shockwave example.org
```

### Dependências opcionais

| Ferramenta | Para que serve | Instalação |
|------------|---------------|------------|
| `nmap` | Scans avançados (SYN, ACK, FIN, XMAS, etc.) | `sudo apt install nmap` |
| `tcpdump` | Captura e análise de pacotes | `sudo apt install tcpdump` |
| `traceroute` | Rastreamento de rota | `sudo apt install traceroute` |
| `dig` | Consultas DNS avançadas | `sudo apt install dnsutils` |
| `wkhtmltopdf` | Exportação para PDF | `sudo apt install wkhtmltopdf` |

---

## 🎨 Tema Visual

O Shockwave utiliza uma paleta de cores em **roxo e preto** com gradientes e tons intermediários, proporcionando uma experiência visual moderna e imersiva no terminal. A interface é construída com a biblioteca [Rich](https://github.com/Textualize/rich).

---

## ✨ Funcionalidades

### 🌍 Descoberta de Rede

Ferramentas para encontrar e identificar dispositivos na rede.

| Comando | Função | Uso |
|---------|--------|-----|
| `resolve` | Resolve um hostname para IPv4 usando DNS | `resolve [alvo]` |
| `rdns` | Faz o caminho inverso: dado um IP, descobre o hostname associado | `rdns [ip]` |
| `ping` | Envia pacotes ICMP para testar se o alvo está acessível e medir latência | `ping [quantidade]` |
| `sweep` | Varre uma faixa de IPs com ping para descobrir quais hosts estão ativos | `sweep [base] [inicio-fim]` |
| `arp` | Escaneia a rede local usando o protocolo ARP para listar dispositivos conectados | `arp [interface]` |
| `tcpdiscovery` | Descobre hosts ativos tentando conexões TCP em portas comuns (80, 443, 22...) | `tcpdiscovery [ip]` |
| `udpdiscovery` | Descobre hosts usando sondas UDP em portas como DNS (53), NTP (123), SNMP (161) | `udpdiscovery [ip]` |
| `cidr` | Escaneia uma rede inteira em notação CIDR (ex: 192.168.1.0/24) | `cidr [rede/prefixo]` |
| `gateway` | Detecta automaticamente o gateway padrão da rede | `gateway` |
| `interfaces` | Lista todas as interfaces de rede do sistema e seus endereços IP | `interfaces` |
| `mac` | Descobre o endereço MAC de um IP na rede local via tabela ARP | `mac [ip]` |
| `vendor` | Identifica o fabricante de um dispositivo pelo prefixo OUI do MAC address | `vendor <mac>` |

---

### 🔍 Enumeração

Coleta de informações detalhadas sobre domínios e infraestrutura.

| Comando | Função | Uso |
|---------|--------|-----|
| `dns` | Consulta registros DNS do alvo: A (IPv4), CNAME (alias), MX (e-mail), NS (nameservers), PTR (reverso) | `dns [alvo]` |
| `whois` | Consulta dados de registro do domínio via protocolo WHOIS (porta 43) — dono, datas, registrar | `whois [alvo]` |
| `asn` | Descobre o ASN (Autonomous System Number) — qual provedor/organização controla aquele IP | `asn [alvo]` |
| `geo` | Geolocaliza um IP: país, cidade, coordenadas, ISP e timezone | `geo [ip]` |
| `subdomains` | Enumera subdomínios de um domínio testando uma wordlist (www, mail, api, admin, dev...) | `subdomains [dominio]` |
| `dnssec` | Verifica se o domínio usa DNSSEC (assinaturas criptográficas nos registros DNS) | `dnssec [dominio]` |
| `zonetransfer` | Tenta uma transferência de zona DNS (AXFR) — teste de segurança contra exposição de registros | `zonetransfer [dominio]` |
| `cdn` | Detecta se o site está atrás de um CDN (Cloudflare, CloudFront, Akamai, Fastly, etc.) | `cdn [dominio]` |

---

### 🚪 Port Scanning

Escaneamento de portas com múltiplas técnicas, desde o básico até scans furtivos.

| Comando | Função | Uso |
|---------|--------|-----|
| `scan` | Escaneia as ~25 portas mais comuns (HTTP, SSH, FTP, SMTP, MySQL, etc.) | `scan` |
| `fullscan` | Escaneia TODAS as 65.535 portas TCP — completo mas demorado | `fullscan` |
| `cscan` | Escaneia portas específicas que você escolher | `cscan <portas>` (ex: `cscan 1-1024` ou `cscan 22,80,443`) |
| `tcpscan` | Scan TCP padrão (connect) — estabelece conexão completa para verificar porta aberta | `tcpscan` |
| `udpscan` | Scan UDP — verifica portas que usam protocolo UDP (DNS, NTP, SNMP...) | `udpscan` |
| `synscan` | Scan SYN (half-open) — envia apenas SYN, mais rápido e discreto (requer nmap/root) | `synscan [portas]` |
| `ackscan` | Scan ACK — útil para mapear regras de firewall e detectar portas filtradas | `ackscan [portas]` |
| `finscan` | Scan FIN — envia pacotes com flag FIN para evadir firewalls simples | `finscan [portas]` |
| `nullscan` | Scan NULL — envia pacotes sem nenhuma flag TCP (stealth) | `nullscan [portas]` |
| `xmasscan` | Scan XMAS — envia pacotes com flags FIN+PSH+URG ativadas simultaneamente | `xmasscan [portas]` |
| `winscan` | Window Scan — analisa o campo Window Size da resposta para detectar portas | `winscan [portas]` |
| `idlescan` | Idle Scan — usa um host "zombie" para escanear sem revelar seu próprio IP | `idlescan <zombie> [portas]` |
| `fragscan` | Fragment Scan — fragmenta pacotes para tentar passar por firewalls/IDS | `fragscan [portas]` |
| `adaptive` | Scan com timing adaptativo (T0=paranoid até T5=insane) | `adaptive [timing 0-5]` |

---

### 🖥️ Identificação de Serviços

Detecta quais serviços estão rodando e suas versões.

| Comando | Função | Uso |
|---------|--------|-----|
| `banner` | Captura o banner de um serviço — a mensagem de boas-vindas que revela nome e versão | `banner <porta>` |
| `svcdetect` | Detecta automaticamente serviços em múltiplas portas comuns do alvo | `svcdetect` |
| `version` | Tenta identificar a versão exata de um serviço usando sondas específicas | `version <porta>` |
| `httpdetect` | Detecta serviço HTTP: versão do protocolo, status, headers e servidor | `httpdetect [porta]` |
| `sshdetect` | Detecta serviço SSH: versão do protocolo e software (OpenSSH, Dropbear, etc.) | `sshdetect [porta]` |
| `ftpdetect` | Detecta serviço FTP e verifica se aceita login anônimo | `ftpdetect [porta]` |
| `smtpdetect` | Detecta serviço SMTP e suas capacidades (STARTTLS, AUTH, etc.) | `smtpdetect [porta]` |
| `smbdetect` | Detecta serviço SMB (compartilhamento de arquivos Windows) nas portas 445 e 139 | `smbdetect` |
| `snmpdetect` | Detecta serviço SNMP enviando uma consulta com community string "public" | `snmpdetect` |
| `dbdetect` | Escaneia portas de bancos de dados comuns: MySQL, PostgreSQL, MongoDB, Redis, etc. | `dbdetect` |
| `mqttdetect` | Detecta broker MQTT (protocolo IoT) tentando uma conexão MQTT CONNECT | `mqttdetect [porta]` |
| `redisdetect` | Detecta Redis enviando comando PING e tentando obter versão e modo | `redisdetect [porta]` |

---

### 🧠 Fingerprinting

Técnicas de identificação do sistema operacional e tipo de dispositivo.

| Comando | Função | Uso |
|---------|--------|-----|
| `osdetect` | Combina múltiplas técnicas (TTL, TCP stack, MSS) para adivinhar o sistema operacional | `osdetect` |
| `devicetype` | Identifica o tipo de dispositivo (servidor, roteador, switch, impressora, IoT) pelas portas abertas | `devicetype` |
| `tcpstack` | Analisa características da implementação TCP/IP para inferir o OS | `tcpstack` |
| `ttl` | Analisa o valor TTL das respostas ping — cada OS usa um TTL padrão diferente (Linux=64, Windows=128) | `ttl` |
| `mss` | Analisa o Maximum Segment Size negociado na conexão TCP — revela informações sobre MTU e tunelamento | `mss` |
| `winsize` | Analisa o tamanho do buffer TCP — cada OS configura valores padrão diferentes | `winsize` |

---

### 🔐 SSL / TLS

Análise completa de certificados e configurações de criptografia.

| Comando | Função | Uso |
|---------|--------|-----|
| `cert` | Exibe todos os detalhes do certificado SSL: CN, emissor, SANs, datas, serial number | `cert` |
| `certval` | Valida o certificado: verifica cadeia de confiança, hostname match e expiração | `certval` |
| `ciphers` | Enumera quais cipher suites o servidor aceita na negociação TLS | `ciphers` |
| `tlsver` | Testa quais versões de TLS o servidor suporta (1.0, 1.1, 1.2, 1.3) | `tlsver` |
| `hsts` | Verifica se o servidor envia o header HSTS (força uso de HTTPS) e seus parâmetros | `hsts` |
| `alpn` | Detecta suporte a ALPN (negociação de protocolo) — indica se suporta HTTP/2 | `alpn` |
| `weakciphers` | Verifica se o servidor aceita cifras fracas (RC4, DES, NULL, etc.) | `weakciphers` |
| `certexpiry` | Verifica quantos dias faltam para o certificado expirar, com classificação de urgência | `certexpiry` |

---

### 🌐 HTTP Analysis

Análise detalhada do servidor web e sua configuração.

| Comando | Função | Uso |
|---------|--------|-----|
| `headers` | Exibe todos os cabeçalhos HTTP retornados pelo servidor | `headers` |
| `secheaders` | Audita headers de segurança (HSTS, CSP, X-Frame-Options, etc.) com pontuação 0-100% | `secheaders` |
| `cookies` | Analisa cookies: verifica flags de segurança (Secure, HttpOnly, SameSite) | `cookies` |
| `redirects` | Segue a cadeia completa de redirects HTTP (301, 302, 307...) até a URL final | `redirects` |
| `compression` | Detecta quais métodos de compressão o servidor suporta (gzip, deflate, br, zstd) | `compression` |
| `httpmethods` | Descobre quais métodos HTTP estão habilitados (GET, POST, PUT, DELETE, TRACE...) | `httpmethods` |
| `http2` | Detecta suporte a HTTP/2 via negociação ALPN na conexão TLS | `http2` |
| `http3` | Detecta suporte a HTTP/3 (QUIC) verificando o header Alt-Svc | `http3` |
| `robots` | Baixa e analisa o robots.txt — mostra quais paths estão bloqueados para crawlers | `robots` |
| `sitemap` | Baixa e analisa o sitemap.xml — lista as URLs indexadas do site | `sitemap` |
| `webtech` | Detecta tecnologias usadas no site: framework, CMS, servidor, linguagem, CDN | `webtech` |

---

### 📡 Packet Analysis

Captura e análise de pacotes de rede em tempo real.

| Comando | Função | Uso |
|---------|--------|-----|
| `capture` | Captura pacotes ao vivo da interface de rede usando tcpdump | `capture [quantidade]` |
| `pcap` | Lê e exibe o conteúdo de um arquivo PCAP salvo | `pcap <arquivo>` |
| `protostats` | Captura pacotes e mostra estatísticas por protocolo (TCP, UDP, ICMP, ARP, DNS) | `protostats` |
| `tcpstream` | Captura e analisa o fluxo TCP para um alvo/porta específicos (SYN, ACK, FIN, RST) | `tcpstream [porta]` |
| `dnsanalysis` | Captura e analisa pacotes DNS — mostra queries e responses em tempo real | `dnsanalysis` |
| `httpanalysis` | Captura pacotes HTTP/HTTPS mostrando requests e responses | `httpanalysis [alvo]` |
| `tlshandshake` | Analisa o handshake TLS: tempo, versão, cipher, ALPN, compressão | `tlshandshake` |
| `icmp` | Análise detalhada de pacotes ICMP: TTL, RTT, packet loss, estatísticas | `icmp` |
| `bandwidth` | Mede a taxa de transferência (RX/TX) de uma interface de rede em tempo real | `bandwidth` |

---

### 📊 Performance

Métricas de qualidade e desempenho da conexão de rede.

| Comando | Função | Uso |
|---------|--------|-----|
| `latency` | Mede a latência (RTT) até o alvo com classificação de qualidade | `latency` |
| `packetloss` | Mede a taxa de perda de pacotes com 20 pings e classifica a qualidade | `packetloss` |
| `jitter` | Mede a variação na latência (jitter) — importante para VoIP e streaming | `jitter` |
| `mtudisc` | Descobre o MTU máximo suportado até o alvo usando busca binária | `mtudisc` |
| `pathmtu` | Descobre o MTU do caminho completo usando tracepath | `pathmtu` |
| `throughput` | Estima a vazão (throughput) da conexão baixando dados do alvo | `throughput` |

---

### 📄 Relatórios

Exporte os resultados dos scans em diversos formatos.

| Comando | Função | Uso |
|---------|--------|-----|
| `exportjson` | Exporta todos os resultados coletados na sessão para um arquivo JSON estruturado | `exportjson [arquivo]` |
| `exporthtml` | Gera um relatório HTML visual com tema roxo/preto, tabelas e badges | `exporthtml [arquivo]` |
| `exportcsv` | Exporta os dados em formato CSV para análise em planilhas | `exportcsv [arquivo]` |
| `exportxml` | Exporta os dados em formato XML estruturado | `exportxml [arquivo]` |
| `exportpdf` | Gera relatório PDF (requer wkhtmltopdf ou weasyprint instalado) | `exportpdf [arquivo]` |
| `compare` | Compara dois scans realizados na mesma sessão e mostra as diferenças | `compare` |

> **Nota:** Os comandos de exportação salvam os resultados de todos os scans realizados durante a sessão atual. Execute os scans desejados antes de exportar.

---

### ⚙️ Comandos do Sistema

| Comando | Função | Uso |
|---------|--------|-----|
| `target` | Altera o alvo atual sem reiniciar a ferramenta | `target <novo_alvo>` |
| `trace` | Executa traceroute mostrando cada hop até o destino | `trace` |
| `netinfo` | Mostra informações da rede local: IP privado, IP público, hostname, interfaces | `netinfo` |
| `clear` | Limpa a tela do terminal | `clear` |
| `splash` | Mostra a tela inicial novamente com o banner e informações do alvo | `splash` |
| `help` | Lista todos os comandos disponíveis organizados por categoria | `help` |
| `exit` | Encerra o Shockwave | `exit` |

---

## 📁 Estrutura do Projeto

```
shockwave-complete/
├── shockwave/
│   ├── __init__.py              # Versão do pacote
│   ├── __main__.py              # Ponto de entrada (python -m shockwave)
│   ├── app.py                   # Aplicação principal e dispatcher de comandos
│   ├── ui.py                    # Interface visual (Rich) e formatadores
│   ├── theme.py                 # Paleta de cores roxo/preto e gradientes
│   ├── ascii_art.py             # Arte ASCII do banner
│   └── modules/
│       ├── resolver.py          # Host Resolver
│       ├── ping_sweep.py        # Ping e Ping Sweep
│       ├── port_scan.py         # 14 tipos de Port Scan
│       ├── dns_records.py       # Consultas DNS
│       ├── traceroute.py        # Traceroute
│       ├── http_headers.py      # HTTP Headers
│       ├── whois_lookup.py      # WHOIS Lookup
│       ├── geolocate.py         # GeoIP Lookup
│       ├── net_info.py          # Informações de rede local
│       ├── network_discovery.py # ARP, CIDR, Gateway, MAC, Vendor
│       ├── enumeration.py       # ASN, Subdomains, DNSSEC, CDN
│       ├── service_detection.py # Banner, SSH, FTP, SMTP, SMB, SNMP, MQTT, Redis
│       ├── fingerprinting.py    # OS Detection, TTL, MSS, Window Size
│       ├── ssl_tls.py           # Certificados, Ciphers, TLS, HSTS, ALPN
│       ├── http_analysis.py     # Security Headers, Cookies, WebTech
│       ├── packet_analysis.py   # Captura, PCAP, Protocol Stats
│       ├── performance.py       # Latência, Jitter, MTU, Throughput
│       └── reports.py           # JSON, HTML, CSV, XML, PDF
├── assets/
│   └── shockwave.png
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🔧 Requisitos

| Requisito | Versão | Obrigatório |
|-----------|--------|-------------|
| Python | >= 3.8 | Sim |
| Rich | >= 13.0.0 | Sim |
| nmap | qualquer | Não (scans avançados) |
| tcpdump | qualquer | Não (packet analysis) |
| traceroute | qualquer | Não (traceroute) |
| dig | qualquer | Não (DNS avançado) |
| wkhtmltopdf | qualquer | Não (exportação PDF) |

---

## ⚠️ Aviso Legal

Esta ferramenta deve ser utilizada **exclusivamente em ambientes autorizados** para fins legítimos de diagnóstico, auditoria de segurança e estudo. O uso em redes ou sistemas sem autorização prévia é ilegal e antiético.

**Use com responsabilidade.**

---

<p align="center">
  <b>SHOCKWAVE v2.0.0</b> | Ferramenta de Diagnóstico de Rede
</p>
