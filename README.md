# SHOCKWAVE

**Network Diagnostic Toolkit** — Decepticon Intelligence Unit

> *"Logic. Superiority. Objective: Control."*

Ferramenta de analise de redes com interface terminal tematica, construida em Python.

## Modulos

| # | Modulo | Comando | Descricao |
|---|--------|---------|-----------|
| 1 | Resolve Host | `resolve` | Resolucao DNS → IPv4 |
| 2 | Ping | `ping [count]` | Testa alcancabilidade do alvo |
| 3 | Ping Sweep | `sweep <base_ip> [start-end]` | Varre faixa de IPs |
| 4 | Port Scan | `scan` | Varre portas comuns (FTP, SSH, HTTP, MySQL, Redis, etc.) com threads |
| 5 | Custom Port Scan | `cscan <range>` | Voce escolhe o range (ex: `1-1024` ou `22,80,443`) |
| 6 | DNS Records | `dns` | Registros A, CNAME, PTR, MX, NS |
| 7 | Traceroute | `trace` | Caminho salto a salto |
| 8 | HTTP Headers | `headers` | Fingerprint de servidor (headers de resposta) |
| 9 | WHOIS Lookup | `whois` | Consulta direto via socket na porta 43 |
| 10 | Geolocate IP | `geo` | Localizacao aproximada via ip-api |
| 11 | Local Network Info | `netinfo` | IP local e IP publico da sua maquina |

## Instalacao

```bash
# Clonar o repositorio
git clone https://github.com/marcogasparotto/shockwave.git
cd shockwave

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

```bash
# Executar com um alvo
python -m shockwave google.com

# Ou instalar e usar o comando
pip install -e .
shockwave google.com
```

### Comandos Disponiveis

Dentro do prompt interativo `shockwave >`:

```
resolve          - Resolver hostname para IPv4
ping [count]     - Ping no alvo
sweep <ip>       - Ping sweep em faixa de rede
scan             - Scan de portas comuns
cscan <range>    - Scan de portas customizado
dns              - Registros DNS
trace            - Traceroute
headers          - Headers HTTP
whois            - WHOIS lookup (porta 43)
geo              - Geolocalizacao de IP
netinfo          - Info da rede local
target <alvo>    - Mudar alvo
clear            - Limpar tela
banner           - Mostrar splash screen
help             - Ajuda
exit             - Sair
```

## Requisitos

- Python 3.8+
- rich >= 13.0.0
- Ferramentas de rede do sistema (ping, traceroute, dig)

## Versao

**v0.1.0** - Release inicial
