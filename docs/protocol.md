# Protocolo Winflux — especificação (Etapas 1–3)

## Unidades e endereços
- 1 WFLX = 10^8 unidades. Todo valor é inteiro; floats são proibidos no protocolo.
- Endereço = `wflx1` + base32 minúsculo de `SHA-256(pubkey)[:20] ‖ checksum(4)`,
  `checksum = SHA-256("WFLX-ADDR-V1" ‖ hash160)[:4]`. Só a forma canônica é válida.

## Serialização
JSON canônico (chaves ordenadas, sem espaços, ASCII, sem NaN). Parsing estrito: campos extras,
tipos errados e tamanhos absurdos são rejeitados antes de qualquer verificação cara.

## Transação
`{version, chain_id, coinbase_height, inputs[{txid,index,pubkey,signature}], outputs[{value,address}]}`
- `txid = SHA-256("WFLX-TXID-V1" ‖ JSON(corpo sem assinaturas))`.
- Mensagem assinada: `"WFLX-TX-SIGN-V1" ‖ txid` (compromete chain_id, entradas e saídas ⇒ sem replay entre redes).
- Taxa = Σ entradas − Σ saídas (implícita), ≥ `min_fee`.

### Regras de validação (transação comum)
1. `version == 1`, `chain_id` igual ao da rede, ≥1 entrada e ≥1 saída, limites de tamanho/quantidade.
2. Saídas: inteiro, `0 < valor ≤ max_supply`, endereço válido, soma ≤ `max_supply`.
3. Cada entrada existe no UTXO set, sem duplicata na transação (gasto duplo interno).
4. `pubkey` hasheia para o endereço dono da saída gasta; assinatura Ed25519 válida.
5. Σ entradas ≥ Σ saídas (conservação) e taxa ≥ `max(min_fee, min_fee_per_byte × tamanho_da_tx)` (tamanho = JSON canônico, com assinaturas).

## Bloco
Cabeçalho `{height, prev_hash, timestamp, merkle_root, producer, nonce, meta}`;
`hash = SHA-256("WFLX-BLOCK-HEADER-V1" ‖ JSON(cabeçalho))`. A assinatura do produtor não entra no hash.
- Gênese: altura 0, `meta = hash dos parâmetros da rede`; uma coinbase com as alocações.
- Regras: tamanho total das transações ≤ `max_block_bytes`; altura = anterior+1; `prev_hash` correto; `timestamp` > anterior e ≤ agora+2h;
  raiz de Merkle correta; txids únicos; consenso válido; exatamente uma coinbase, na posição 0;
  transações aplicadas em ordem (uma pode gastar saída criada antes no mesmo bloco).
- Coinbase: `coinbase_height == altura`, sem entradas, valor ≤ `min(recompensa(altura), max_supply − oferta_atual) + taxas`.
- Bloco inválido não altera o estado (aplicação atômica com desfazimento).

## Política monetária
`recompensa(h) = block_reward >> (h // halving_interval)`, limitada pela oferta restante.
Gênese configurável (devnet padrão: 5.000.000 WFLX). Nenhuma outra forma de criar moeda existe.

## Consenso (testnet)
PoA em rodízio: o produtor do bloco `h` é `authorities[(h−1) mod n]`, assinatura Ed25519 sobre
`"WFLX-BLOCK-SIG-V1" ‖ hash`. Limitação: se a autoridade da vez estiver offline a cadeia para.


## Cofres offline (Etapa 3b-1)
Tipos de transação (`kind` + `payload`, parsing estrito): `transfer`, `vault_open`, `voucher_claim`, `vault_refund`, `note_claim`.
Não existe fechamento antecipado de cofre. Especificação completa e modelo de ameaças: `offline-payments.md`.

- **Oferta**: `Σ UTXO + Σ valor travado nos cofres ≤ max_supply`; colateral queimado sai da conta.
- **`vault_open`**: entradas financiam `Σ(cap + colateral)`; carga útil `{device_key, key_type, slots, collateral_pct,
  ttl_blocks, refund_address, pop}`; `pop` = assinatura da chave do dispositivo sobre o corpo da tx (sem o `pop`).
  Taxa ≥ `max(min_fee, min_fee_per_byte × tamanho)`.
- **`voucher_claim`**: carga `{voucher}` (175 B hex); sem entradas; saída única `(valor − min_fee) → receptor`, taxa fixa
  `min_fee`; qualquer um pode retransmitir. Vaga livre paga do teto; vaga ocupada por outro voucher paga do colateral
  (`min(valor, colateral)`), marca o cofre como fraudulento; o mesmo voucher nunca é liquidado duas vezes.
  Prazo: bloco de inclusão ≤ `expires_height + claim_window_blocks`.
- **`vault_refund`**: só no bloco `> expires_height + claim_window_blocks`; devolve teto não pago (+ colateral se não houve
  fraude; se houve, o colateral restante é queimado), menos `min_fee`.
- **Coinbase**: `payload = {"prev_hash": hash do bloco anterior}` (txids de coinbase nunca coincidem entre redes).
- **Voucher**: layout binário fixo; identidade = SHA-256 do corpo (sem assinatura); P-256 exige S baixo.


## `note_claim` — liquidação de notas offline (A3)
Liquida **uma folha-endereço** de uma cadeia de notas offline numa vaga com chave própria (`slot.key`). Vagas com chave
própria **não** aceitam `voucher_claim`; vagas sem chave **não** aceitam `note_claim`.

- **Carga útil** (parsing estrito): `{vault_id, slot, leaf, hops:[{tx, key_type, pubkey, sig}]}`; `tx` = `OfflineTx` binária
  em hex. Sem entradas; saída única `(valor_da_folha ou indenização − min_fee) → endereço da folha`; taxa fixa `min_fee`;
  qualquer um pode submeter (a saída é determinada pela folha). A prova de cofre **não** vai na cadeia: o estado já está lá.
- **Cadeia** (`offline.note.verify_hop_chain`, função pura): 1..`MAX_HOPS` saltos; rede e cofre corretos; 1º salto gasta
  `root_note_id(vault_id, slot)` com valor `cap` e é assinado pela chave da vaga; cada salto seguinte gasta uma saída
  **NOTA** do anterior e é assinado pela chave cujo compromisso é o dono dessa saída; conservação exata; assinaturas válidas
  (P-256 com S baixo). A atestação de hardware **não** é regra de consenso (é política do receptor offline).
- **Folha**: deve ser KIND_ADDRESS e ≥ `max(min_voucher_value, min_fee+1)` (folhas menores ficam sem liquidação e voltam
  ao dono no `vault_refund`). Prazo igual ao do voucher: inclusão ≤ `expires_height + claim_window_blocks`.
- **Estado da vaga** (por vaga): `spends` (nota → txid offline que a gastou na cadeia) e `settled` (folhas liquidadas),
  comprometidos na raiz de estado via `claimed_by = H("WFLX-NOTESTATE-V1" ‖ spends ‖ settled)` (formato do `state_root`
  inalterado). No máximo `MAX_SETTLED_PER_SLOT = 64` folhas por vaga.
- **Sem conflito** (todo salto é novo ou igual ao já registrado): paga o valor da folha do depósito (`paid += valor`) e
  registra os saltos novos. Folhas distintas de uma mesma árvore consistente liquidam normalmente (a conservação garante
  `Σ ≤ cap`). **Conflito** (algum salto gasta uma nota já gasta por *outra* tx offline): o ramo perdedor é indenizado pelo
  colateral por `plan_compensation` (R1–R5, R8, R9), marca o cofre como fraudulento e **não** é registrado (seus
  descendentes continuam conflitando). Ordem de pagamento = ordem na cadeia (R5). A mesma folha nunca é paga duas vezes (R3).
- **Limite conhecido**: R2 usa o valor da vaga (`cap`) como teto da soma das indenizações da vaga, não o valor de cada nota
  contestada separadamente. É um limite válido (e ainda sujeito a R1, o colateral), porém mais frouxo que o ideal para
  conflitos em notas intermediárias de valor menor; refinar exige contador por nota (mudança de estado; novos testes).

## Reconciliação do dono do cofre (A4)
**Decisão de projeto: nenhuma transação nova de consenso.** Um "fechamento antecipado" da vaga seria inseguro: o dono
poderia encerrar a vaga depois de já ter emitido a nota offline, desfazendo pagamentos que o recebedor aceitou. Por isso a
única saída continua sendo `vault_refund` após `expires_height + claim_window_blocks` (e o consenso é o mesmo da A3).
A4 entrega as ferramentas para o dono **saber** o que aconteceu antes de reembolsar:

- **API de leitura** (sem privilégio): `GET /api/vault/<id>` (vagas, colateral, `claim_deadline`, altura) e
  `GET /api/vaults/<endereço-de-reembolso>` (até 100 cofres do endereço).
- **Diário do dono** (`wallet/reconcile.py::Journal`, JSON `v:1`, arquivo 0600): cada nota-raiz assinada pelo dono
  (`vault_id`, `slot`, `root_txid`). `record_hop` recusa saltos que não gastam a raiz da vaga.
- **`reconcile(vault, journal, params, height)`** compara diário × cadeia e usa `plan_refund` (a mesma conta do consenso)
  para projetar o reembolso. Estado por vaga: `UNUSED`, `OUTSTANDING` (emitida, janela aberta), `PARTIAL`, `SETTLED`,
  `LAPSED` (janela fechada com algo não liquidado: o recebedor perdeu o direito e o valor volta ao dono). Sinalizadores:
  `DIVERGENT` (a cadeia mostra um gasto da raiz que o diário não registra: chave possivelmente exposta/clonada ou diário
  incompleto), `CONFLICT` (colateral já indenizou: gasto duplo), `DOUBLE_ISSUED` (o diário tem duas raízes na mesma vaga).
  A janela segue o consenso: claims são aceitos enquanto a altura de inclusão ≤ `claim_deadline`; o reembolso vale quando
  a altura de inclusão > `claim_deadline` (testado em cada altura de fronteira).
- **CLI**: `vaults`, `reconcile <vault_id> [--journal arq]`, `vault-refund <vault_id>` (não pede senha: o reembolso vai
  ao endereço gravado no cofre; qualquer pessoa pode submetê-lo).
- **Limites**: o diário só é confiável se o dono o gravar a cada emissão (o aparelho offline é quem sabe); ele não prova
  nada à cadeia, serve ao próprio dono. Um dono malicioso não é impedido por A4: é impedido por colateral e R1–R9.

## State root, checkpoints e provas (A1)
- Todo bloco tem `state_root` no cabeçalho (entra no hash): raiz Merkle do registro de cofres APÓS o bloco. Todo nó a
  recomputa e rejeita o bloco se não conferir. Estrutura e defesas em `blockchain/state_root.py`.
- **Checkpoint** = cabeçalho de bloco assinado por uma autoridade (PoA). **Prova de cofre** = checkpoint + parâmetros
  estáticos do cofre + estado + registro da vaga + dois caminhos Merkle. Verificável offline em ~0,2 ms; 1,2-1,9 KB em JSON.
- Parâmetro novo: `max_compensations_per_slot` (R9). Regras de indenização do colateral (R1-R9): `offline-chained-payments.md` §3.
- Limitação: recomputar a raiz é O(cofres × vagas) por bloco; precisa de cache incremental antes de rede pública.


## Notas transferíveis (A2)
- `vault_open` aceita `slot_keys` (lista com uma chave pública por vaga, mesmo `key_type` do cofre; P-256 comprimida, sem repetição).
  A chave vai no registro, no `state_root` e na prova. Vaga com chave própria **não** aceita `voucher_claim` (só `note_claim`, A3).
- Formato binário da transação offline e regras do verificador: `offline-chained-payments.md` §7. Ainda **não** há `note_claim`.


## Consenso PoW, forks e reorganizações (Fase 5)
- `consensus = "pow"`: bloco válido se `int(hash_do_cabeçalho) ≤ alvo`; `producer` e `signature` vazios; recompensa vai ao endereço da coinbase.
- **Alvo derivado do histórico** (não está no cabeçalho): a cada `pow_retarget_interval` blocos,
  `alvo' = alvo × clamp(tempo_real, esperado/4, esperado×4) / esperado`, com `esperado = (intervalo−1) × target_block_time`, limitado a `pow_limit`.
- **Maior trabalho acumulado vence** (`trabalho(bloco) = 2²⁵⁶ ÷ (alvo+1)`). Empate: o primeiro visto permanece.
- Blocos laterais passam só nas regras sem estado; ao superar a cadeia ativa, o ledger desfaz até o ancestral comum e aplica o novo ramo
  validando tudo. Ramo inválido ⇒ restauração da cadeia anterior e marcação de invalidez do ramo (e descendentes). Persistência da reorg é atômica (SQLite).
- `coinbase_maturity`: recompensas (altura > 0) só podem ser gastas após esse nº de blocos. O gênese é isento.
- Parâmetros novos (entram no hash do gênese): `consensus`, `pow_limit`, `pow_retarget_interval`, `coinbase_maturity`.

## Rede P2P (Fase 4)
TCP, mensagens `uint32 BE tamanho + JSON {"t","d"}` (máx. 4 MiB). `version`(proto, chain_id, hash do gênese, nonce, altura, trabalho, porta) → `verack`;
`inv/getdata/block/tx`; sincronização por localizador: `getblocks{locator}` → `blocks{blocks,more}` (≤ 500 blocos/2 MiB); `getaddr/addr`; `getmempool`; `ping/pong`.
Defesas: gênese/chain_id incompatível ⇒ banimento; autoconexão e duplicata detectadas; pontuação de mau comportamento com decaimento e banimento a 100;
rajadas de `inv` são descartadas sem punição; mensagem/bloco inválido ⇒ penalidade; órfãos (≤ 100) ficam em memória até o pai chegar.
Mempool: só transações válidas contra o estado atual, sem substituição (primeira vence), expulsão por menor taxa/byte, revalidação a cada bloco.

## API HTTP (somente leitura + envio)
`GET /api/{status,params,peers,mempool,block/<altura|hash>,tx/<txid>,address/<endereço>}`, `POST /api/tx`. Escuta em 127.0.0.1 por padrão.
