# ⚡ SHOCKWAVE

> **Ferramenta de Análise de Redes — Decepticon Intelligence Unit**
>
> *"Logic. Superiority. Objective: Control."*

**SHOCKWAVE** é uma ferramenta de diagnóstico e análise de redes para terminal, desenvolvida em Python. Ela reúne diversas funcionalidades de reconhecimento e troubleshooting em uma interface interativa inspirada no universo Transformers.

---

## ✨ Funcionalidades

| Módulo | Comando | Descrição |
|--------|---------|-----------|
| Resolve Host | `resolve` | Resolve um hostname para IPv4 |
| Ping | `ping [count]` | Testa a conectividade com o alvo |
| Ping Sweep | `sweep <base_ip> [start-end]` | Descobre hosts ativos em uma faixa de IP |
| Port Scan | `scan` | Escaneia as portas mais comuns utilizando múltiplas threads |
| Custom Port Scan | `cscan <range>` | Escaneia portas definidas pelo usuário (`1-1024`, `22,80,443`, etc.) |
| DNS Records | `dns` | Consulta registros A, AAAA, MX, NS, CNAME e PTR |
| Traceroute | `trace` | Exibe o caminho dos pacotes até o destino |
| HTTP Headers | `headers` | Obtém os headers HTTP do servidor |
| WHOIS Lookup | `whois` | Consulta informações WHOIS via porta 43 |
| Geolocate IP | `geo` | Localiza aproximadamente um endereço IP |
| Local Network Info | `netinfo` | Exibe o IP local e o IP público da máquina |

---

## 🚀 Instalação

Clone o repositório:

```bash
git clone https://github.com/marcogasparotto/shockwave.git
cd shockwave
```

Crie um ambiente virtual (opcional, mas recomendado):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

---

## ▶️ Como usar

Executar diretamente:

```bash
python -m shockwave google.com
```

Ou instalar o projeto localmente:

```bash
pip install -e .
shockwave google.com
```

---

## 💻 Comandos

Após iniciar o programa, estarão disponíveis:

| Comando | Descrição |
|---------|-----------|
| `resolve` | Resolver hostname |
| `ping [count]` | Executar ping |
| `sweep <ip>` | Descobrir hosts ativos |
| `scan` | Escanear portas comuns |
| `cscan <range>` | Escanear portas personalizadas |
| `dns` | Consultar registros DNS |
| `trace` | Executar traceroute |
| `headers` | Obter headers HTTP |
| `whois` | Consulta WHOIS |
| `geo` | Geolocalizar IP |
| `netinfo` | Informações da rede local |
| `target <host>` | Alterar o alvo atual |
| `banner` | Exibir o banner |
| `clear` | Limpar o terminal |
| `help` | Mostrar ajuda |
| `exit` | Encerrar o programa |

---

## 📦 Dependências

- Python 3.8+
- rich ≥ 13
- requests
- dnspython
- Ferramentas do sistema:
  - `ping`
  - `traceroute`
  - `dig`

---

## 📸 Exemplo

```text
$ shockwave google.com

Target: google.com

shockwave >

> scan
[+] 22/tcp   SSH
[+] 80/tcp   HTTP
[+] 443/tcp  HTTPS

> dns
A      142.250.xxx.xxx
AAAA   2800:...
MX     smtp.google.com
```

---

## ⚠️ Aviso

O SHOCKWAVE foi desenvolvido para fins de estudo, diagnóstico e administração de redes.

Utilize a ferramenta apenas em sistemas e redes para os quais você possua autorização.

---

## 🚧 Versão

**v0.1.0** — Primeira versão pública.
