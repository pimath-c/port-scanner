# port-scanner

Scanner de portas TCP simples, escrito em C, usando `connect()` não bloqueante
e um pool de threads para escanear várias portas em paralelo. Tem três alvos
de build, todos sobre o mesmo núcleo de escaneamento:

- **CLI** (Linux/macOS/BSD, `src/`) — linha de comando, POSIX sockets + pthreads.
- **GUI GTK 3** (Linux, `gui/`) — interface gráfica para desktops Linux.
- **Windows** (`windows/`) — CLI e GUI nativas para Windows (Winsock2 + Win32
  API/threads puros), compiladas com `mingw-w64` a partir do Linux. Geram um
  único `.exe` portátil, sem instalador nem DLLs externas — só depende de
  DLLs padrão do Windows (`ws2_32`, `user32`, `comctl32` etc.).

## Build

CLI (Linux/macOS/BSD):

```sh
make
```

Requer um compilador C (gcc/clang) e a biblioteca pthreads (padrão em
sistemas Linux/BSD/macOS).

GUI GTK 3 (opcional, Linux):

```sh
# Ubuntu/Debian
sudo apt-get install libgtk-3-dev

make gui
```

## App para Windows

Se você está no Windows, use `port-scanner-gui.exe` — é a forma mais simples
de rodar o scanner: baixe o `.exe`, dê dois cliques, sem instalação.

Binários já compilados estão em [`dist/`](dist/) (`port-scanner.exe` e
`port-scanner-gui.exe`) — não precisa compilar nada, só baixar o arquivo.

Os `.exe` (CLI e GUI) são cross-compilados aqui no Linux com `mingw-w64` e
depois **rodam nativamente no Windows** — não precisam de WSL, Python, GTK,
nem de nenhum runtime extra instalado na máquina.

Para compilar você mesmo (a partir de Linux, com `mingw-w64` instalado):

```sh
# Ubuntu/Debian
sudo apt-get install gcc-mingw-w64-x86-64

make windows        # gera port-scanner.exe e port-scanner-gui.exe
# ou individualmente:
make windows-cli
make windows-gui
```

Basta copiar o(s) `.exe` gerado(s) para uma máquina Windows e executar — não
há instalador porque não é necessário: é um binário único e portátil.

### Interface gráfica (Windows e Linux)

```sh
./port-scanner-gui        # Linux (GTK 3)
port-scanner-gui.exe      # Windows
```

A janela permite configurar host, portas, threads, timeout, captura de
banner e exibição de todas as portas (não só as abertas), com resultados
atualizados em tempo real (coloridos por status) e um botão **Parar** para
cancelar um scan em andamento.

## Uso (CLI)

```sh
./port-scanner <host> [opcoes]       # Linux/macOS/BSD
port-scanner.exe <host> [opcoes]     # Windows
```

### Opções

| Opção                 | Descrição                                                  | Padrão   |
|------------------------|-------------------------------------------------------------|----------|
| `-p, --ports`          | Portas a escanear: lista, faixa ou combinação (`22,80,8000-8100`) | `1-1024` |
| `-t, --threads`        | Número de threads concorrentes                              | `100`    |
| `-T, --timeout`        | Timeout de conexão em milissegundos                          | `500`    |
| `-b, --banner`         | Tenta capturar o banner do serviço em portas abertas (passivo) | desligado |
| `-B, --active-banner`  | Banner grab ativo: se o serviço fica em silêncio, envia um probe (GET HTTP em portas web, `\r\n` genérico nas demais). Implica `-b` | desligado |
| `-a, --all`            | Mostra todas as portas (aberta/fechada/filtrada), não só as abertas | desligado |
| `-u, --udp`            | Escaneamento UDP em vez de TCP                               | desligado (TCP) |
| `-D, --discover`       | Descoberta de host antes de escanear: pula hosts que não respondem a nenhum probe TCP comum (80/443/22/445/3389) | desligado |
| `-o, --output <file>`  | Exporta os resultados para um arquivo                       |          |
| `-f, --format <fmt>`   | Formato de exportação: `txt`, `json` ou `csv`. Sem `-f`, é deduzido da extensão de `-o` (ou `txt`) |          |
| `--history`            | Salva o resultado no histórico local do host                | desligado |
| `--diff`               | Compara com o último scan salvo no histórico e mostra o que mudou (também salva o resultado atual) | desligado |
| `-w, --watch <s>`      | Repete o scan a cada `<s>` segundos até `Ctrl+C`             |          |
| `-h, --help`           | Mostra a ajuda                                               |          |

O argumento de alvo aceita um host único, uma lista separada por vírgulas
e/ou um bloco CIDR IPv4 (ex: `10.0.0.1,192.168.1.0/24,example.com`); blocos
CIDR são expandidos host a host (rede e broadcast excluídos), com um limite
de 4096 endereços por bloco para evitar varreduras acidentalmente enormes.

### Exemplos

Escanear as 1024 portas mais comuns de um host:

```sh
./port-scanner scanme.nmap.org
```

Escanear uma faixa específica com mais threads e capturando banners:

```sh
./port-scanner 192.168.0.1 -p 1-65535 -t 300 -b
```

Escanear portas específicas e mostrar o resultado completo (incluindo
fechadas/filtradas):

```sh
./port-scanner example.com -p 21,22,25,80,443,3306 -a
```

Escanear portas UDP (DNS e NTP têm probes dedicados; as demais usam um
datagrama vazio):

```sh
./port-scanner 8.8.8.8 -p 53,123 -u -a -b
```

Escanear uma sub-rede inteira com descoberta de host e banner grab ativo,
exportando para JSON:

```sh
./port-scanner 192.168.1.0/24 -D -p 22,80,443 -B -o rede.json -f json
```

Acompanhar um host ao longo do tempo, revarrendo a cada 5 minutos e
mostrando o que mudou desde a última passada (o histórico fica em
`~/.port-scanner/history/`):

```sh
./port-scanner example.com -p 1-1024 -b --diff -w 300
```

## Histórico e diff

Com `--history` ou `--diff`, cada scan de um host é anexado a
`~/.port-scanner/history/<host>.log`. Com `--diff`, antes de salvar o
resultado atual o scanner compara com o último registro salvo e imprime as
portas que abriram, fecharam ou mudaram de status/banner desde então —
útil tanto isoladamente quanto combinado com `-w` para vigiar mudanças em
tempo real.

## Advisories de versão desatualizada

Sempre que um banner é capturado (`-b`/`-B`), o scanner o compara com uma
tabela estática de versões conhecidas como desatualizadas ou vulneráveis
(ex: `vsftpd 2.3.4` — backdoor CVE-2011-2523 — ou OpenSSH/Apache/nginx
abaixo de uma versão mínima razoável) e imprime um aviso abaixo da porta
correspondente quando há correspondência. É uma checagem offline e
best-effort — não substitui uma varredura de CVEs real.

## Testes automatizados

```sh
make test
```

Compila e roda `tests/test_main.c`, que cobre o parser de portas/alvos
(incluindo expansão de CIDR), exportação (JSON/CSV, com escaping), as
advisories embutidas e o round-trip de histórico/diff. O GitHub Actions
(`.github/workflows/ci.yml`) roda `make` + `make test` em todo push/PR,
além de builds separados da GUI GTK3 e dos binários Windows (cross-compile).

## Como funciona

- O host é resolvido uma única vez via `getaddrinfo`.
- Cada porta é testada com um `connect()` em modo não bloqueante, usando
  `poll()` para aplicar o timeout configurado — isso evita que portas
  filtradas por firewall travem o scan inteiro.
- Um pool fixo de threads consome a lista de portas a partir de uma fila
  compartilhada protegida por mutex.
- Quando `-b` é usado, para cada porta aberta o scanner aguarda até 1s por
  dados enviados pelo serviço (banner) logo após a conexão.
- `Ctrl+C` interrompe o scan de forma limpa, imprimindo os resultados
  obtidos até o momento.
- Com `-u`, cada porta usa um socket UDP `connect()`ado: uma resposta marca
  a porta como `open`, um ICMP "port unreachable" (que o kernel entrega como
  `ECONNREFUSED`) marca como `closed`, e silêncio dentro do timeout é
  reportado como `open|filtered` — a mesma ambiguidade inerente a qualquer
  scanner UDP, já que não há handshake para confirmar o estado. Para
  aumentar a taxa de resposta, portas 53 (DNS) e 123 (NTP) usam probes
  específicos do protocolo; as demais recebem um datagrama vazio.
- Com `-B`, se nenhum dado chegar nos primeiros ~300ms após o connect, o
  scanner envia um probe (GET HTTP em portas web conhecidas, `\r\n`
  genérico nas demais) e aguarda mais um pouco pela resposta antes de
  desistir.
- `-D` não faz ICMP echo (exigiria socket raw/privilégios); considera o
  host "up" se qualquer uma das portas de sondagem comuns conectar ou for
  ativamente recusada (RST) — ambos os casos provam que algo respondeu na
  rede. Um host atrás de firewall que descarta tudo silenciosamente pode
  gerar um falso negativo.

## Limitações conhecidas

- Faz apenas TCP connect scan / UDP scan orientado a resposta (não há SYN
  scan), então não requer privilégios de root.
- A captura de banner TCP é passiva por padrão (`-b`): não envia payloads
  específicos por protocolo, então serviços que esperam o cliente falar
  primeiro (por exemplo, HTTP) não retornarão banner sem uma requisição —
  para isso, use `-B`. Para UDP, apenas DNS e NTP têm probes dedicados;
  outras portas dependem do serviço responder a um datagrama vazio.
- A descoberta de host (`-D`) e as advisories de versão (na captura de
  banner) são heurísticas best-effort, não uma verificação completa de
  alcançabilidade nem um feed de CVEs em tempo real.
