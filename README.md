# port-scanner

Scanner de portas TCP simples, escrito em C, usando `connect()` não bloqueante
e um pool de threads (pthreads) para escanear várias portas em paralelo.
Inclui uma CLI e uma interface gráfica (GTK 3), ambas construídas sobre o
mesmo núcleo de escaneamento (`src/scanner.c`).

## Build

CLI:

```sh
make
```

Requer um compilador C (gcc/clang) e a biblioteca pthreads (padrão em
sistemas Linux/BSD/macOS).

Interface gráfica (opcional, requer GTK 3):

```sh
# Ubuntu/Debian
sudo apt-get install libgtk-3-dev

make gui
```

## Interface gráfica

```sh
./port-scanner-gui
```

A janela permite configurar host, portas, threads, timeout, captura de
banner e exibição de todas as portas (não só as abertas), com resultados
atualizados em tempo real (coloridos por status) e um botão **Parar** para
cancelar um scan em andamento.

## Uso (CLI)

```sh
./port-scanner <host> [opcoes]
```

### Opções

| Opção              | Descrição                                                  | Padrão   |
|---------------------|-------------------------------------------------------------|----------|
| `-p, --ports`       | Portas a escanear: lista, faixa ou combinação (`22,80,8000-8100`) | `1-1024` |
| `-t, --threads`     | Número de threads concorrentes                              | `100`    |
| `-T, --timeout`     | Timeout de conexão em milissegundos                          | `500`    |
| `-b, --banner`      | Tenta capturar o banner do serviço em portas abertas         | desligado |
| `-a, --all`         | Mostra todas as portas (aberta/fechada/filtrada), não só as abertas | desligado |
| `-h, --help`        | Mostra a ajuda                                               |          |

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

## Limitações conhecidas

- Faz apenas TCP connect scan (não há SYN scan / UDP scan), então não
  requer privilégios de root.
- A captura de banner é passiva: não envia payloads específicos por
  protocolo, então serviços que esperam o cliente falar primeiro (por
  exemplo, HTTP) não retornarão banner sem uma requisição.
