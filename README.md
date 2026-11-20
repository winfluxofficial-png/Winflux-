# Winflux (WFLX) — blockchain própria

> Nome oficial: **Winflux (WFLX)**. Histórico: Nexora/NXR (já existia) → Kelvora/KVRA → Winflux/WFLX.
> A disponibilidade de marca e de símbolo **ainda não está confirmada**: ver `docs/naming.md`.
> **Software de testes. Não use com dinheiro real** antes de auditoria criptográfica,
> testes adversariais e revisão independente.

| Parâmetro | Valor |
|---|---|
| Oferta máxima | 100.000.000 WFLX (`10^16` unidades) |
| Casas decimais | 8 (menor unidade `0,00000001 WFLX`) |
| Emissão | limitada: gênese + recompensa por bloco com halving, sempre sob o teto |
| Criação adicional | proibida (validada por todo nó: coinbase ≤ recompensa + taxas; oferta ≤ teto) |
| Hash / assinatura | SHA-256 / Ed25519 |
| Modelo | UTXO, valores inteiros |
| Consenso | **PoW aberto** (sem autoridades, lançamento justo, zero pré-mineração) para a rede pública; PoA só na devnet local |

## Status

| Etapa | Estado |
|---|---|
| 1 Blockchain básica (gênese, blocos, encadeamento, persistência SQLite) | ✅ testada |
| 2 Criptografia e carteiras (Ed25519, endereços `wflx1…`, keystore cifrado) | ✅ testada |
| 3 Sistema monetário (UTXO, taxas, teto de oferta, anti gasto duplo/replay) | ✅ testada |
| 0 Consolidação (achados da auditoria: taxa por byte, limite de bloco, carteira HD, chave de recuperação, `chain_id` único) | ✅ testada (`docs/audit-fase0.md`) |
| 1a Tipos de transação e cofres offline na camada de consenso (3b-1): `vault_open`, `voucher_claim`, `vault_refund`, voucher binário, Ed25519/P-256, coinbase com hash anterior | ✅ testada (239 testes, 13 mutações) |
| A1 `state_root` no cabeçalho, checkpoints e provas de cofre verificáveis offline | ✅ testada |
| Exposição determinística do colateral (R1-R9) e correção do bug de reapresentação | ✅ testada |
| A2 Notas transferíveis: chave por vaga, formato binário, verificador offline, simulador de hardware e atestação (405 testes, 33 mutações) | ✅ testada |
| A3 `note_claim` (liquidação de notas on-chain, conflito/compensação R1-R9, undo, fuzz e mutações; 497 testes) | ✅ testada (`docs/protocol.md`) |
| A4 reconciliação (API de cofres, diário do dono, relatório diário × cadeia, CLI `reconcile`/`vault-refund`; sem fechamento antecipado, ver `docs/protocol.md`) | ✅ testada (533 testes) |
| 1b Identificador de esquema e endereço v2, chaves de vaga pós-quânticas (LMS), formato binário de transação | ⏳ |
| Carteira Android v0.1 (online: HD, enviar/receber; núcleo testado na JVM contra o Python; UI não compilada) | 🟡 `android-wallet/` |
| Android offline (diagnóstico de hardware, NFC/BLE), PWA | ⏳ |
| 4 Rede P2P (handshake, mempool, propagação, sincronização, banimento), API HTTP, nó e carteira CLI | ✅ testada (3 nós + processos reais) |
| 4b PWA (celular/PC) | ⏳ depois da API |
| 5 PoW com ajuste de dificuldade, maior-trabalho, reorganizações atômicas, maturidade de coinbase, gênese justo (`netgen`) | ✅ testada (`docs/decentralization.md`) |
| 6+ Android nativo, testes entre redes, documentação pública | ⏳ |

## Rodar uma rede PoW (sem permissão de ninguém)

```bash
python -m winflux.tools.netgen --name testnet --out genesis.json        # gênese justo: sem pré-mineração, sem autoridades
python -m winflux.cli --wallet w.json create                            # carteira + chave de recuperação
python -m winflux.node.main --genesis genesis.json --listen 0.0.0.0:8333 --mine <endereço>   # nó + minerador
python -m winflux.node.main --genesis genesis.json --datadir n2 --listen 0.0.0.0:8334 --api 127.0.0.1:8081 --seed IP:8333
python -m winflux.cli --node http://127.0.0.1:8081 --wallet w.json balance | send <endereço> <valor>
```
Leia `docs/decentralization.md` (princípios, o que o código garante e o que **não** garante, decisões pendentes).

## Uso

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

pytest                                   # suíte completa
PYTHONPATH=. python scripts/demo_local.py   # gênese -> transferência -> bloco -> confirmações
PYTHONPATH=. python scripts/demo_offline_vault.py   # cofre offline, gasto duplo, compensação e devolução
PYTHONPATH=. python scripts/demo_chained_notes.py    # Alice -> Bob -> Carlos -> Dave offline (hardware SIMULADO)
PYTHONPATH=. python scripts/demo_note_claim.py       # liquidação on-chain (note_claim), gasto duplo e colateral
python -m winflux.tools.devnet init --dir devnet   # cria genesis.json + chaves cifradas (5.000.000 WFLX no gênese)
# a senha vem de WINFLUX_DEVNET_PASSWORD ou de um prompt (nunca da linha de comando)
```

`devnet init` cria `genesis.json`, `producer.key.json` (autoridade PoA) e `faucet.key.json`
(recebe os 5.000.000 WFLX iniciais). O `chain_id` é derivado do gênese. A senha padrão (`devnet-only-password`) só
é usada quando não há variável nem terminal interativo; serve apenas para testes locais.

Carteira recomendada: `winflux.wallet.hd.HDWallet` (troco em endereço novo, chave de recuperação `wflxk1-…`).

## Estrutura

```text
winflux/
├── crypto/      hashing.py address.py keys.py        SHA-256, endereços, Ed25519, keystore
├── blockchain/  transaction.py block.py params.py genesis.py utxo.py vaults.py ledger.py validation.py chain.py
├── offline/     voucher.py proofs.py note.py verifier.py attestation.py hardware_sim.py
│                                                      voucher, provas de cofre, notas encadeadas, verificador, hardware SIMULADO
├── blockchain/  exposure.py state_root.py             limites de exposição (R1-R9), raiz Merkle de cofres
├── consensus/   interface.py poa.py pow.py            PoA (devnet) e PoW (rede pública)
├── node/        storage.py mempool.py node.py main.py nó completo (cadeia+mempool+P2P+minerador)
├── wallet/      wallet.py hd.py transaction_builder.py vault_builder.py
├── network/p2p.py  api/server.py  cli.py              P2P, API HTTP, carteira de linha de comando
├── tools/       devnet.py netgen.py localnet.py       devnet PoA local; gênese PoW justo; testnet local multiprocesso
├── logs.py      network/limits.py                     logging com redação de segredos; token bucket (P2P/API)
web-wallet/ (PWA)   android-wallet/ (nativo, futuro)   tests/   docs/   scripts/
```

Mudança em relação ao briefing: as regras de validação de transações ficam em
`blockchain/validation.py` (e não em `node/validator.py`) para evitar dependência circular
entre cadeia e nó e para o app Android/ferramentas reutilizarem o mesmo código de regras.

Documentação: `docs/offline-chained-payments.md` (**arquitetura aprovada dos pagamentos offline encadeados**),
`docs/security-assumptions.md` (hipóteses de segurança), `docs/running-a-node.md` (operar um nó), `docs/testnet.md` (testnet, testnet local e smoke test), `docs/protocol.md` (regras das Etapas 1–3), `docs/offline-payments.md` (cofres e vouchers:
especificação e modelo de ameaças — **requisito central**) e `docs/architecture.md` (riscos e decisões).
