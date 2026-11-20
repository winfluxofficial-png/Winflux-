# Changelog

## 0.1.0rc1 — release candidate da testnet
Primeira versão para testes reais da testnet. **Não é uma versão para dinheiro real** (sem auditoria externa, hardware
de atestação simulado).

### Protocolo / consenso
- **A3 `note_claim`:** liquidação on-chain de notas offline encadeadas em vagas com chave própria; conflito (gasto
  duplo) indenizado pelo colateral sob R1–R9; `MAX_SETTLED_PER_SLOT = 64`; estado da vaga (`spends`/`settled`)
  comprometido na raiz de estado via `claimed_by` (formato do `state_root` inalterado). Ver `docs/protocol.md`.
- Limite conhecido: o teto R2 usa o valor da vaga, não o de cada nota contestada.
- Nenhum parâmetro monetário alterado.

### Carteiras e ferramentas
- **A4 reconciliação:** `GET /api/vault/<id>`, `GET /api/vaults/<endereço>`, diário do dono, `reconcile(...)`; CLI
  `vaults`, `reconcile`, `vault-refund`. Sem fechamento antecipado de vaga (inseguro; ver `docs/protocol.md`).
- **Carteira Android v0.1** (`android-wallet/`): online (HD, enviar/receber). Núcleo testado na JVM contra o Python; UI não compilada.
- `build_note_claim`, `Vault.from_dict`, `HDWallet` inalterado.

### Operação / endurecimento
- Rate limiting no P2P (mensagens/s, bytes/s, por tipo, tamanho por tipo, limite por IP, recuo de reconexão) e na API
  (taxa por IP antes de ler o corpo, limite próprio para `POST /api/tx`, caps de conexão, anti-slowloris, validação estrita).
- Logging com níveis, rotação e redação de segredos (`winflux/logs.py`); mineração e laços de rede resilientes a erros;
  erros de inicialização claros; flags `--log-level`, `--log-file`, `--max-inbound-per-ip`, `--api-rate`,
  `--api-tx-rate`, `--api-trust-proxy`; `version` em `/api/status`.
- `scripts/run_local_testnet.py` (3 nós + 1 minerador), `scripts/smoke_test.py` (nó, mineração, tx, sincronização,
  nó tardio, vault + `note_claim` + reconciliação).
- Docs: `running-a-node.md`, `testnet.md`, `test-plan.md`, `security-assumptions.md`.

### Testes
- Suíte `pytest`: ver `docs/test-plan.md` (contagem exata e como rodar). Smoke em processos reais: `WINFLUX_SMOKE=1`.

## Antes
Etapas 1–3 e A1–A2 (blockchain, P2P, API, CLI, carteira HD, cofres, vouchers, notas offline, provas de cofre,
state_root, R1–R9): ver `README.md` e `docs/protocol.md`.
