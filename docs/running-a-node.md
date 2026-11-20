# Rodando um nó Winflux

> **Software de testes (testnet).** Sem auditoria externa. Não use com dinheiro real nem guarde valor relevante.
> Qualquer pessoa pode rodar um nó sem pedir permissão; o seu nó verifica tudo por conta própria.

## 1. Requisitos
- Python 3.11+ e `pip install -r requirements.txt` (só `cryptography`; `pytest` para os testes).
- Disco: a cadeia fica num SQLite (`<datadir>/chain.db`); a testnet é pequena (dezenas de MB no começo).
- Rede: uma porta TCP de P2P (padrão **8333**) aberta de entrada se quiser receber conexões; a **API** (padrão
  `127.0.0.1:8080`) é só local por padrão.

## 2. Obter o gênese (a identidade da rede)
O gênese é só um arquivo de dados. O `chain_id` é derivado dele e **cada nó o verifica sozinho**: dois nós só se
conectam se tiverem exatamente o mesmo gênese. Pegue o `genesis-testnet.json` publicado pela comunidade (veja
`docs/testnet.md`) **e confira o `chain_id` com alguém de confiança por outro canal**. Para gerar o seu próprio:

```bash
python -m winflux.tools.netgen --name testnet --out genesis-testnet.json
```

## 3. Rodar
```bash
python -m winflux.node.main --genesis genesis-testnet.json --datadir ~/.winflux \
    --listen 0.0.0.0:8333 --api 127.0.0.1:8080 --seed IP_DE_UM_NO:8333
```
Para minerar, crie uma carteira e passe o endereço (a chave **não** fica no nó):
```bash
python -m winflux.cli --wallet minha.json create          # senha via WINFLUX_WALLET_PASSWORD ou prompt; mostra o endereço wflx1…
python -m winflux.node.main --genesis genesis-testnet.json --seed IP:8333 --mine wflx1...
```
Anote a **chave de recuperação** (`wflxk1-…`) que a carteira mostra ao ser criada: é a única forma de recuperar os fundos.
O nó para com `Ctrl+C`/`SIGTERM` (fecha o banco e a API com calma).

### Opções
| Opção | Padrão | Para quê |
|---|---|---|
| `--genesis` | (obrigatório) | arquivo de gênese |
| `--datadir` | `winflux-data` | cadeia (`chain.db`) e `peers.json` |
| `--listen` | `0.0.0.0:8333` | P2P |
| `--api` | `127.0.0.1:8080` | API HTTP/JSON (vazio desativa) |
| `--seed` | — | `host:porta` de um nó conhecido (repetível). Sem seeds, o nó só aceita conexões de entrada |
| `--mine` | — | endereço que recebe as recompensas; liga a mineração (rede PoW) |
| `--max-outbound` / `--max-inbound` | 8 / 32 | conexões P2P |
| `--max-inbound-per-ip` | 8 | conexões de entrada por IP (loopback isento) |
| `--api-rate` | 600 | requisições/min **por IP** na API |
| `--api-tx-rate` | 60 | `POST /api/tx` por min por IP |
| `--api-trust-proxy` | desligado | usa o último `X-Forwarded-For` (só atrás do **seu** proxy) |
| `--log-level` | `info` | `debug`, `info`, `warning`, `error` |
| `--log-file` | — | além do console, grava em arquivo (rotação 5 MB × 3) |

## 4. Expor a API com segurança
A API não tem contas nem privilégios (qualquer carteira usa qualquer nó), mas **não tem TLS**. Para expô-la à internet,
ponha um proxy reverso com HTTPS na frente (nginx, Caddy…), mantenha `--api 127.0.0.1:8080` e passe
`--api-trust-proxy` **somente** se o proxy for seu e sobrescrever/acrescentar o `X-Forwarded-For`. Sem essa opção o
cabeçalho é ignorado (é forjável) e todos os clientes atrás do proxy compartilhariam um único balde de limite.

## 5. Limites e proteção contra abuso (já embutidos)
- **P2P:** mensagem máxima 4 MB (16 KB antes do handshake e tetos menores por tipo: ping 256 B, inv 256 KB, tx 512 KB…);
  limite de mensagens/s no total e por tipo, e de bytes/s por peer. Dicas em excesso (`inv`/`addr`/`ping`) são
  descartadas; pedidos em excesso são **atrasados** e somam pontos de mau comportamento (100 pontos = banimento de 1 h).
  Blocos que o seu próprio nó pediu na sincronização não contam para o limite de bytes.
- **Conexões:** limite total e por IP; reconexão com recuo exponencial (5 s, 10 s… até 5 min) e esquecimento de
  endereços mortos (nunca dos `--seed`).
- **API:** corpo ≤ 200 KB, cabeçalhos ≤ 16 KB, 256 conexões (32 por IP), timeout de 20 s por pedido (anti-slowloris),
  limite de taxa **antes** de ler o corpo, e limite mais estrito para `POST /api/tx`. Respostas: `429` (com
  `Retry-After`), `413`, `431`, `408`, `503`; erros internos viram `500 {"error":"erro interno"}` sem detalhes.

## 6. Logs
Formato: `AAAA-MM-DDTHH:MM:SS NÍVEL logger: mensagem`. O que **nunca** é registrado: corpo de mensagens P2P ou HTTP,
transações, senhas, sementes, chaves privadas/de recuperação, conteúdo de carteira. Erros vindos de peers/clientes
registram só o **tipo** da exceção; mensagens de regra do protocolo (`bloco 12 rejeitado: ...`) podem aparecer. Como rede
de segurança, todo texto passa por um filtro que redige padrões como `senha=…`, `seed: …`, `wflxk1-…`, `Bearer …`.
Endereços IP de peers aparecem em `info`/`debug` (necessário para operar); se isso for sensível no seu caso, use
`--log-level warning`.
Mensagens úteis: `peer pronto`, `novo topo N hash`, `bloco minerado`, `REORG`, `banido <ip>`, `FALHA DE ARMAZENAMENTO`.

## 7. Operação
- **Backup:** copie `<datadir>/` com o nó parado (ou use `sqlite3 chain.db ".backup ..."`). A cadeia é refeita pela rede se
  perdida; **o que não se refaz é a sua carteira** (`minha.json` + chave de recuperação).
- **Atualizar:** pare o nó, atualize o código, reinicie. Mudança de regra de consenso vira nova versão do protocolo
  anunciada com antecedência; o `proto` é conferido no handshake.
- **Reset da testnet:** o gênese novo gera outro `chain_id`; apague o `--datadir` antigo.
- **Códigos de saída:** `0` normal; `2` gênese ausente/inválido ou banco corrompido; `1` erro de sistema (porta em uso etc.).

## 8. Problemas comuns
| Sintoma | Causa provável |
|---|---|
| `erro de sistema ao iniciar o nó: Address already in use` | porta P2P/API ocupada: troque `--listen`/`--api` |
| `peers=0` e altura parada | sem `--seed`, porta do seed fechada ou **gênese diferente** (confira o `chain_id`) |
| `banido <ip>` nos logs | o peer violou limites/regras (ou é de outra rede): é o comportamento esperado |
| `429` na API | passou do limite por IP: espere ou ajuste `--api-rate` |
| `FALHA DE ARMAZENAMENTO` | disco cheio/sem permissão; pare o nó e verifique `<datadir>/chain.db` |
