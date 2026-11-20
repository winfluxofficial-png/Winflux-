# Testnet Winflux

> **Para testar, não para guardar valor.** A testnet pode ser reiniciada a qualquer momento (novo gênese = novo
> `chain_id`), as moedas **não têm valor** e o software não passou por auditoria externa. A criptografia de hardware
> do pagamento offline é **simulada**; não há atestação de dispositivos reais ainda (ver `docs/security-assumptions.md`).

## O que é
Uma rede PoW pública com **lançamento justo**: zero pré-mineração, zero alocações, zero autoridades e nenhuma chave
administrativa (`docs/decentralization.md`). Toda moeda nasce de mineração aberta. Parâmetros padrão do `netgen`:
bloco-alvo de 60 s, dificuldade inicial de ~2^20 hashes, maturidade da recompensa de 100 blocos, taxa mínima de
1000 unidades (1 WFLX = 10⁸ unidades). O que é testado aqui, além do básico: pagamentos offline encadeados com
cofres (`vault_open`, `note_claim`, `vault_refund`), reconciliação do dono e as defesas de rede.

## Entrar na testnet pública
1. Obtenha o `genesis-testnet.json` e uma lista de seeds (`host:8333`) de quem a opera, e **verifique o `chain_id` por um
   segundo canal**. Quem publica o arquivo não ganha poder algum: cada nó recomputa o hash do gênese.
2. Rode o nó (`docs/running-a-node.md`):
   `python -m winflux.node.main --genesis genesis-testnet.json --seed SEED1:8333 --seed SEED2:8333`
3. Confira: `curl -s http://127.0.0.1:8080/api/status` → `peers ≥ 1` e a `height` crescendo.
4. Carteira: `python -m winflux.cli --node http://127.0.0.1:8080 --wallet minha.json create` e use `balance`, `send`.
5. Moedas de teste: **não há faucet** (seria um ponto de controle). Minere com `--mine <seu endereço>` ou peça a quem
   minera. Recompensas só são gastáveis após 100 blocos.

## Lançar uma nova testnet (quem opera o 1º nó)
```bash
python -m winflux.tools.netgen --name testnet --out genesis-testnet.json      # anote o chain_id impresso
python -m winflux.node.main --genesis genesis-testnet.json --listen 0.0.0.0:8333 --mine wflx1... --seed ...
```
Publique o arquivo (repositório, página, o que preferir) **junto do `chain_id`** e de 2+ seeds de operadores
independentes. Revise antes os parâmetros em `docs/decentralization.md` (tempo de bloco, dificuldade inicial,
maturidade): são decisões de projeto, não do script.

## Testnet local (4 processos na sua máquina)
```bash
PYTHONPATH=. python scripts/run_local_testnet.py --dir local-testnet --block-time 4
```
Sobe **3 nós conectados + 1 minerador** (P2P `18333–18336`, API `18080–18083`, tudo em 127.0.0.1), com gênese gerado
pelo `netgen` e dificuldade calibrada para ~`--block-time` s por bloco. Cria `genesis.json`, `miner.wallet.json`
(senha de devnet: **só local**), `logs/<nó>.log`. `Ctrl+C` encerra; `--keep` retoma a rede anterior. Exemplo:
```bash
WINFLUX_WALLET_PASSWORD=devnet-only-password PYTHONPATH=. python -m winflux.cli \
    --node http://127.0.0.1:18081 --wallet local-testnet/miner.wallet.json balance
```
Na rede local a maturidade é 2 blocos e o tempo de bloco é curto; os demais parâmetros são os do `netgen`.

## Smoke test
```bash
PYTHONPATH=. python scripts/smoke_test.py          # sobe a testnet local, testa e derruba (≈1 min)
PYTHONPATH=. python scripts/smoke_test.py --nodes http://127.0.0.1:18080,http://127.0.0.1:18081 \
    --wallet local-testnet/miner.wallet.json       # contra uma rede já rodando
```
Passos: (1) nós sobem, mesma rede, conectados; (2) mineração produz blocos e paga o minerador; (3) transação enviada a um
nó que não minera propaga, é minerada e aparece em todos; (4) convergência de topo/oferta e **nó tardio** que sincroniza a
cadeia inteira; (5) **fluxo offline**: abre cofre com chave por vaga, paga Bob → Carol offline, liquida com `note_claim`
num nó diferente, confere saldo, estado do cofre, relatório de reconciliação e a rejeição da reapresentação. Saída `0`
= tudo passou. `SMOKE_TRACE=1` mostra o traceback de uma falha; `--keep` preserva os logs.

## Limitações conhecidas (leia antes de testar)
- Pagamento offline com hardware real (NFC/BLE, atestação) **não existe** ainda; o simulador cobre só a lógica.
- Sem TLS na API (use proxy), sem explorer, sem faucet, histórico por endereço indisponível na API.
- Sem DoS "de verdade": os limites ajudam contra abuso simples; um atacante com muitos IPs e poder de hash pode degradar a
  rede. Sem proteção contra *eclipse* (use seeds de operadores independentes).
- A rede pode ser reiniciada; guarde apenas o que puder perder.

## Reportar problemas
Inclua: versão (commit), `chain_id`, trecho do log **com `--log-level debug`** (o log já omite segredos, mas releia antes de
colar), passos para reproduzir e a saída de `python scripts/smoke_test.py`. Vulnerabilidades: não abra issue pública;
contate os mantenedores em privado.
