# Plano de testes — Winflux 0.1.0rc1 (testnet)

Objetivo: dar a quem vai testar um roteiro claro do que já está automatizado, o que precisa de olho humano e o que
**ainda não dá para testar**. Use uma máquina limpa; nada aqui deve ser feito com dinheiro real.

## 0. Portões automáticos (devem passar antes de qualquer teste manual)
```bash
pip install -r requirements.txt
python -m pytest -q                                   # suíte completa (≈20 s)
WINFLUX_SMOKE=1 python -m pytest tests/test_localnet_smoke.py -q     # 5 processos reais (≈1 min)
PYTHONPATH=. python scripts/smoke_test.py             # o mesmo, com saída passo a passo
```
Critério: 0 falhas; `5/5 passos OK`. Se falhar, guarde a saída e os logs (`--keep` preserva `logs/`).

## 1. Rede local (1 máquina)
`PYTHONPATH=. python scripts/run_local_testnet.py --dir local-testnet --block-time 4`

| # | O que fazer | Esperado |
|---|---|---|
| 1.1 | `curl :18080/api/status` em cada nó | mesma `chain_id`, `peers ≥ 1`, `height` crescendo, `version` = 0.1.0rc1 |
| 1.2 | Matar um nó (`kill`) e religá-lo com o mesmo `--datadir` | volta na altura anterior e recupera os blocos perdidos |
| 1.3 | Parar o minerador por 1 min e religar | rede segue; minerador retoma sem reorg inesperado |
| 1.4 | Enviar tx pela CLI a um nó não-minerador | aparece no mempool dos outros e é minerada; saldo bate em todos |
| 1.5 | Enviar a mesma tx duas vezes / gastar a mesma moeda em duas txs | segunda é recusada (400) |
| 1.6 | Reiniciar tudo com `--keep` | cadeia retomada, saldos iguais |

## 2. Várias máquinas (rede real)
Mesmo gênese em todas (conferir `chain_id`), `--seed` apontando para 2+ nós de operadores diferentes, porta P2P aberta.
Verifique convergência de topo (`tip`) e de `supply`; derrube um seed e confirme que os demais seguem conectados;
inicie um nó novo do zero e confirme que sincroniza a cadeia inteira. **Não testado ainda:** latência alta, NAT, IPv6.

## 3. Resistência a abuso (com cuidado, só na sua rede)
| # | Ataque simulado | Esperado |
|---|---|---|
| 3.1 | 1000 `GET /api/status` em rajada do mesmo IP | `429` com `Retry-After` depois da rajada; nó segue normal |
| 3.2 | `POST /api/tx` com corpo de 5 MB, Content-Length falso, JSON inválido | `413`/`400`, nunca `500`; sem custo de memória perceptível |
| 3.3 | Abrir 100 conexões ociosas na API | `503` acima do limite por IP; ociosas caem em ≤ 20 s (`408`) |
| 3.4 | Cliente P2P cru enviando lixo / mensagem de 1 MB antes do handshake | desconectado e banido (`banido <ip>` no log) |
| 3.5 | Enxurrada de `ping`/`inv` | descartados sem derrubar o nó |
| 3.6 | Ler os logs após 3.1–3.5 | nenhum corpo de mensagem, nenhuma chave/senha |
Para 3.x: scripts de exemplo estão em `tests/test_hardening.py` (os mesmos cenários, automatizados).

## 4. Carteira
Criar, anotar a chave de recuperação, apagar o keystore, **restaurar** com `recover`, conferir que saldo e endereços
voltam; enviar com troco; enviar mais do que o saldo (erro claro); enviar para endereço inválido (erro claro). No app
Android: compilar no Android Studio (a UI **ainda não foi compilada**), criar/restaurar/enviar contra um nó local.

## 5. Pagamentos offline
| # | Cenário | Como | Esperado |
|---|---|---|---|
| 5.1 | Caminho feliz | `scripts/smoke_test.py` (passo 5) ou `scripts/demo_note_claim.py` | cofre aberto, nota Bob→Carol liquidada, saldo de Carol = valor − taxa |
| 5.2 | Gasto duplo | `scripts/demo_note_claim.py` | 2º ramo pago pelo colateral; cofre marcado `fraud` |
| 5.3 | Reconciliação | `winflux.cli … reconcile <vault_id> --journal vault-journal.json` | estados por vaga e avisos coerentes |
| 5.4 | Reapresentar a mesma cadeia | enviar o `note_claim` de novo | recusado (`já liquidada`) |
| 5.5 | **Reembolso após o prazo** | `vault-refund` | **só automatizado em testes unitários.** Ao vivo exige esperar `vault_ttl_min` (≥ 1 dia) + `claim_window` (7 dias) em tempo real, qualquer que seja o tempo de bloco (os prazos são `DAY // block_time`). Para testá-lo ao vivo é preciso um gênese com prazos curtos (decisão de projeto, fora desta versão). |

## 6. O que NÃO está coberto nesta versão
Atestação de hardware real, NFC/BLE, PWA, histórico por endereço, TLS nativo, proteção contra eclipse/Sybil, testes
de longa duração (dias), carga com milhares de txs/s, auditoria externa, UI Android compilada. Veja
`docs/security-assumptions.md` e `docs/testnet.md`.

## 7. Como relatar
Versão (`/api/status` → `version`), `chain_id`, `--log-level debug` do trecho relevante, passos para reproduzir.
Vulnerabilidades: em privado (ver `docs/testnet.md`).
