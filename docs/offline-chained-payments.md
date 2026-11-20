# Pagamentos offline encadeados na Winflux — arquitetura aprovada

Estado: decisões **aprovadas**; **A1, as regras de exposição do colateral e a A2 (notas, verificador offline, simulador de hardware)
implementadas e testadas**; o restante (A3, A4, B, C) é plano. Complementa `offline-payments.md` (cofres e vouchers) e substitui sua decisão "sem
transitividade": dinheiro recebido offline passa a poder ser repassado offline, sob os limites abaixo.
Hipóteses de segurança: `security-assumptions.md`.

## 1. Decisões aprovadas
1. **Notas transferíveis** (Alice → Bob → Carlos offline), com cadeia de proveniência verificável.
2. **Profundidade máxima de repasse offline: 1 sem hardware seguro; 3 com hardware seguro** atestado e de uso único.
   O nível efetivo de uma nota é o do **pior salto**.
3. **O colateral da vaga raiz responde por fraudes de qualquer salto**, **com limites determinísticos de exposição**
   (§3): múltiplas fraudes ou reivindicações sobre a mesma cadeia nunca geram indenização acima do valor garantido.
4. Nenhuma promessa de prevenção absoluta de gasto duplo offline: sem rede não há consistência garantida (teorema CAP).
   Garantimos **prevenção sob hipóteses de hardware**, **perda limitada** e **compensação determinística** quando elas falham.

## 2. Modelo
- **Cofre/vaga raiz** (já implementado): valor + colateral travados na cadeia; a vaga é a nota raiz, de valor `cap`.
- **Nota**: valor ligado a uma chave de uso único. Gastá-la assina uma **transação offline** com saídas
  (valor, nova chave dona ou endereço final). Conservação: Σ saídas ≤ valor da nota; sem taxa offline.
- **Proveniência**: cada pagamento leva a cadeia `[vaga raiz → t1 → t2 …]` + prova do cofre + atestações.
- **Quem recebe verifica localmente**: prova do cofre (checkpoint, A1), assinaturas de cada salto, conservação,
  profundidade e teto do nível, atestação, margem de prazo, vaga/nota nunca vistas antes, lista de bloqueio.
- **Estados**: `RECEBIDA_OFFLINE` → `LIQUIDANDO` → `CONFIRMADA(n)` → `FINAL`; falhas `CONFLITO_REJEITADO`, `COMPENSADA`,
  `PERDA`, `EXPIRADA`. Nunca se mostra uma nota offline como confirmada.

### Níveis e limites (testnet, a calibrar)
| Nível provado em todos os saltos | Profundidade | Teto por nota |
|---|---|---|
| Software (chave clonável) | 1 | pequeno |
| Hardware atestado, uso único | 3 | médio |
| Elemento seguro com saldo (futuro) | 5 | alto |

## 3. Exposição do colateral (implementado em `blockchain/exposure.py`)
Para uma vaga com teto `C` e colateral inicial `K = ceil(C·ρ)`, uma nota **contestada** `x` (duas transações distintas
gastam a mesma nota) tem valor `v(x)`. Quando um claim perde a corrida, a indenização é **função pura do estado
on-chain**:

| Regra | Enunciado |
|---|---|
| R1 | Σ indenizações da vaga ≤ colateral restante (≤ K) |
| R2 | Σ indenizações por nota contestada ≤ `v(x)` (o valor efetivamente em jogo) |
| R3 | O mesmo claim é indenizado no máximo uma vez (reapresentação recusada) |
| R4 | Cada indenização ≤ valor da folha reivindicada |
| R5 | Ordem de pagamento = ordem de aplicação na cadeia (bloco, posição); esgotado o teto, o resto recebe 0 |
| R8 | Indenização abaixo do mínimo (`max(min_voucher, min_fee+1)`) é recusada (poeira) |
| R9 | No máximo `max_compensations_per_slot` (padrão 16) indenizações por vaga (limita estado e custo) |

**Garantias (invariantes testados):** saída total de uma vaga ≤ `C + min(K, C)`; saída total do cofre ≤ valor travado
na abertura; cada claim é pago uma vez; `locked ≥ 0`; oferta conservada (UTXO + travado = oferta). O colateral que
sobra depois de fraude é **queimado** no refund (ver `offline-payments.md`, R6).

**Exposição máxima de Alice por vaga: `min(K, C)`**, mesmo que um intermediário malicioso (com cúmplices) gere
muitos ramos conflitantes. Alice controla esse risco escolhendo `C`, `ρ` e a política de repasse. Com ρ > 100 %, o
excedente não amplia indenizações (R2), só a dissuasão pela queima.

Exemplo (`C = 10`, `ρ = 300 %`, `K = 30`): voucher A de 10 ocupa a vaga; B de 7 é indenizado (7); C de 7 recebe só 3
(R2: sobram 3 do valor 10); D de 5 é recusado (R2); o colateral restante, 20, é queimado no refund.

**Estado atual × planejado:** as regras R1-R4, R8, R9 já valem para o voucher (nota raiz com uma saída final;
nota contestada = a raiz, `v = C`). Para notas encadeadas (A3) a **mesma função** será usada com um mapa
`nota contestada → total indenizado` no registro.

### Bug encontrado e corrigido nesta etapa
A regra anterior permitia **reapresentar um voucher já indenizado**: com o mesmo valor, a transação idêntica derrubava
a produção de blocos (`ValueError` fora de `ValidationError`); com valor diferente (colateral parcial), pagava de novo
(Carol recebeu 9,99998 por um voucher de 8). Corrigido por R3 + guarda de outpoint duplicado; testes de regressão e
mutação cobrem os dois casos.

## 4. Fluxos
**Alice → Bob → Carlos** (vaga de 30, colateral 30):
```
online  : Alice abre cofre (vaga 30 + colateral 30); registra raiz de chaves
offline : Bob  -> Alice : pedido {chave nova de Bob, request_id}
          Alice -> Bob  : t1 {nota raiz -> 30 p/ chave de Bob} + prova do cofre + atestação   [Bob verifica]
          Carlos -> Bob : pedido {chave nova de Carlos}
          Bob -> Carlos : [t1, t2 {30 -> 10 p/ Carlos, 20 p/ troco de Bob}] + prova + atestações [Carlos verifica]
online  : qualquer um liquida (note_claim): a cadeia aplica cada transação offline UMA vez, por id
          (idempotente: a ordem de sincronização não importa)
fraude  : Bob assina t2' (30 -> Eve) com a mesma nota: quem aplicar primeiro vence; o outro é indenizado
          sob R1-R9 e o cofre é marcado como fraudulento
```

## 5. Mudanças de protocolo
| Item | Estado |
|---|---|
| `state_root` (Merkle do registro de cofres) no cabeçalho do bloco | **Feito (A1)** |
| Checkpoints (cabeçalho assinado) e provas de cofre (~1,2-1,9 KB JSON, 0,2 ms para verificar) | **Feito (A1)** |
| Limites de exposição R1-R9 | **Feito** (voucher); notas em A3 |
| Chave própria por vaga (`slot_keys`), formato binário da transação offline, verificador offline | **Feito (A2)** |
| `note_claim` + registro de notas/transações aplicadas, com undo | A3 |
| Profundidade máxima de consenso, taxa por byte nos claims de cadeia | A3 |
| LM-OTS híbrido, lista de dispositivos fraudulentos nos checkpoints | C |

## 6. Plano
| Fase | Entrega | Hardware |
|---|---|---|
| A1 | Checkpoints e provas de cofre | não — **concluída** |
| A2 | Formato de nota, verificador offline do destinatário, simulador de hardware (uso único + atestação de teste) | não — **concluída** |
| A3 | `note_claim`, registro, conflitos e testes adversariais (conflitantes, clonagem, backup, adulteração, reuso, ordem) | não |
| A4 | Reconciliação da carteira (prazos, conflitos, repetição) | não |
| B1 | App de diagnóstico no Android (StrongBox, atestação, uso único, apagamento da chave, backup) | **celular** |
| B2 | Transportes QR (PWA), NFC e BLE (nativo) | celular |
| C | API/P2P para liquidação, integração PWA/Android, LM-OTS híbrido | celular |


## 7. A2 — o que foi implementado
**Consenso (aditivo):** `vault_open` aceita `slot_keys` (uma chave pública por vaga). A chave entra no registro, no `state_root` e na
prova de cofre. Uma vaga com chave própria **não pode** ser liquidada por `voucher_claim` (só por `note_claim`, A3): assim a chave
de uso único é a única autoridade sobre a vaga. Enquanto o `note_claim` não existe, um cofre com `slot_keys` só pode ser devolvido
(`vault_refund`) depois do prazo.

**Formato (`offline/note.py`):** nota raiz = vaga (`H(vault_id, vaga)`); transação offline binária (106 + 41·n + 16 bytes, n ≤ 4
saídas): `versão, hash da rede, vault_id, nota gasta, valor, saídas[valor, tipo NOTA|ENDEREÇO, dono], request_id`. Dono de uma
NOTA = compromisso de hash `H(tipo, chave)`: a chave só é revelada ao gastar. Conservação exata (Σ saídas = valor da nota).
`txid` não cobre assinatura/chave (maleabilidade inofensiva).

**Verificador (`offline/verifier.py`)** — o que prova, em ordem: (1) prova do cofre contra checkpoint assinado, com memória
monotônica do receptor; vaga livre, cofre aberto e sem fraude, com chave própria e prazo suficiente; (2) cada salto: rede e cofre
certos, nota gasta e valor esperados, conservação, a chave que assinou é a dona (1º salto: a chave da vaga; seguintes:
compromisso da saída), assinatura válida (P-256 com S baixo), encadeamento contíguo; (3) a folha é do destinatário (chave ou
endereço) e o `request_id` confere; (4) **nível efetivo = pior salto** e política: profundidade 1 (software) / 3 (hardware),
tetos por nível; (5) memória local de notas já vistas (gasto duplo visto por este receptor).
Resultado: `RECEBIDA_OFFLINE` (pendente). `accept()` grava na memória local antes de confirmar ao pagador.

**Nível de hardware de um salto:** só com atestação válida **dessa chave**, uso único e TEE/StrongBox; para saltos ≥ 2 o desafio da
atestação deve ser o `request_id` da transação que criou a nota. Qualquer problema (vencida, revogada, outra raiz, outra chave,
desafio errado, sem atestação, software, sem uso único) **rebaixa a software**, que tem os limites mais restritivos.

**Simulador (`offline/hardware_sim.py`) e atestação (`offline/attestation.py`):** formato JSON simulado com a semântica da atestação
de chave do Android; o verificador real entra atrás da mesma interface na Fase B. O simulador modela: chave não exportável, não
clonável, apagada após uso único (restaurar backup não a ressuscita) e o adversário `break_single_use()`.

**Demo:** `scripts/demo_chained_notes.py`.
