# Pagamentos offline na Winflux — especificação e modelo de ameaças (Etapa 3b-0)

Estado: **Revisão 2. Camada de consenso (3b-1) IMPLEMENTADA e testada**: tipos `vault_open`, `voucher_claim`,
`vault_refund`, registro de cofres com undo, voucher binário (175 B), Ed25519 e P-256 (S baixo), coinbase com hash do
bloco anterior. **Ainda NÃO implementados:** verificador offline do receptor, pedido/recibo, checkpoints e provas de
cofre (3b-2/3b-3), transporte QR/BLE/NFC, chaves de vaga pós-quânticas (§15, decisão 6) e hardware Android.

> **Atualização (aprovação das notas transferíveis):** a decisão "sem transitividade" deste documento foi substituída por
> `offline-chained-payments.md`. Cofres/vouchers continuam como base; o voucher é o caso particular de nota raiz com saída final.
> A regra de compensação foi endurecida (R1-R9, `blockchain/exposure.py`) após a descoberta de um bug de reapresentação.

### Revisão 2 — o que mudou e por quê
A revisão adversarial da Revisão 1 encontrou três falhas, corrigidas abaixo:
1. **`vault_close` removido.** Um dono podia fechar o cofre logo depois da abertura e continuar pagando
   offline; receptores com prova antiga não sabiam que o prazo real (`fechamento + janela`) já era curto.
   Agora só existe a expiração: o prazo de claim é sempre `expires_height + claim_window` e o TTL mínimo é curto.
2. **`voucher_hash` agora cobre só o corpo do voucher**, não a assinatura. Com ECDSA P-256 (maleável), um
   terceiro poderia reapresentar o mesmo voucher com outra assinatura válida; a cadeia o trataria como
   "voucher distinto" e pagaria do colateral. Além disso, assinaturas P-256 devem ter **S baixo** (obrigatório).
3. **A chave de dispositivo `D` é pública na cadeia** (o receptor precisa dela), logo é alvo de um computador
   quântico relevante, que forjaria vouchers contra todos os cofres abertos. Decisão pendente de aprovação (§15):
   chaves de uso único baseadas só em SHA-256 (LMS/LM-OTS), uma por vaga, com a cadeia guardando apenas a raiz de Merkle.
Também: coinbase deve comprometer o hash do bloco anterior (§12) para não haver txids de coinbase iguais entre redes.
 Os números marcados
"(a calibrar)" são valores iniciais de testnet, não decisões finais.

> Nenhuma assinatura digital impede, sozinha, que quem controla uma chave assine duas
> transferências conflitantes quando está desconectado. Este documento não promete segurança
> absoluta: ele separa o que o protocolo **garante**, o que **depende de hardware** e o que
> **permanece como risco**.

## 1. Objetivo e não-objetivos

Objetivo: duas pessoas, ambas sem internet, transferem WFLX por QR Code, BLE ou NFC, com
assinatura no aparelho de origem, armazenamento e comprovante no destino, liquidação posterior
na blockchain, proteção contra reuso e estados explícitos.

Não-objetivos (decisões de projeto):
- **Sem "nível 0" como pagamento.** Uma transação assinada comum nunca é aceita como *pagamento* offline: sem
  reserva prévia na cadeia o receptor não tem como avaliar o risco de gasto duplo. Ela pode, no máximo, ser
  guardada como **recebimento pendente sem garantia** (`PENDENTE_SEM_GARANTIA`): não vira saldo, não libera
  bem ou serviço, e a interface nunca a mostra como "pago".
- **Sem transitividade.** Valor recebido offline só se torna gastável depois do claim confirmado.
  Vouchers não são reencaminháveis.
- **Sem autoridade central** (sem mint, sem servidor que registre fichas).
- Privacidade forte (e-cash cego) fica fora desta fase.

## 2. Terminologia

| Termo | Significado |
|---|---|
| Cofre (vault) | Estado de consenso que trava valor + colateral para pagamentos offline |
| Vaga (slot) | Unidade do cofre; paga no máximo uma vez; tem teto de valor |
| Chave de dispositivo `D` | Chave que assina vouchers; pode estar em hardware. Ed25519 ou P-256 |
| Chave do dono | Chave da carteira comum; controla abertura, fechamento e devolução |
| Voucher | Promessa assinada por `D`: "a vaga `i` do cofre `V` paga `a` ao endereço `R`" |
| Claim | Transação on-chain que resgata um voucher |
| Colateral | Valor adicional travado por vaga, usado para compensar vítimas de duplicidade |
| Checkpoint | Compromisso assinado pelas autoridades com a raiz do registro de cofres |

## 3. Garantias, dependências e riscos

**G — garantido pelo protocolo (sem hardware especial):**
- G1. O valor de um cofre não pode ser gasto online em paralelo (está travado no registro).
- G2. Cada vaga paga o valor cheio no máximo uma vez (`vault_id, slot` único).
- G3. Um voucher só vale para o receptor, o pedido e a rede para os quais foi emitido.
- G4. O receptor consegue verificar a autenticidade do voucher e a existência do cofre sem internet.
- G5. A liquidação é determinística: todos os nós chegam ao mesmo resultado.
- G6. Quem foi lesado por duplicidade é compensado pelo colateral da vaga, até o seu limite.
- G7. O dono nunca é lesado pelo receptor; se perder o aparelho, recupera o saldo após a janela.

**H — depende de hardware seguro:**
- H1. Impedir que a chave `D` seja copiada para outro aparelho (chave não exportável + atestação).
- H2. Impedir reuso de vaga após restaurar backup (chave de uso único por voucher, ou contador em
  elemento seguro).

**R — risco que permanece:**
- R1. Sem hardware, o atacante pode vender a mesma vaga a `m` receptores. Com teto `c` e colateral
  `ρ·c`, ele obtém bens de `m·c` e perde no máximo `(1+ρ)·c`; compensa quando `m > 1+ρ`. As
  vítimas perdem até `(m−1−ρ)·c`. **O colateral dissuade, não impede.**
- R2. O receptor perde o direito se não liquidar dentro da janela.
- R3. Compromisso do hardware (TEE/SE quebrado, atestação revogada sem o receptor saber).
- R4. Vínculo de identidades (cofre, endereços, recibos) reduz a privacidade.
- R5. Confiança nas autoridades para checkpoints (PoA) até o PoW definir outra solução.
- R6. Em caso de fraude, **todo** o colateral restante do cofre é queimado (inclusive o de vagas honestas). Dissuade, mas
  pune também o dono cuja chave foi clonada por um ladrão. Alternativa a avaliar: queimar só o da vaga fraudada.

## 4. Níveis de segurança do pagador

| Nível | Chave `D` | Impede clonagem | Impede rollback | Uso |
|---|---|---|---|---|
| L1 | Software (PWA, Android sem hardware adequado) | Não | Não | Valores baixos; colateral dissuade |
| L2 | Hardware atestada, **uma chave por voucher** com uso único | Sim, se não exportável | Sim, se o hardware impõe o limite | Valores médios |
| L3 | Elemento seguro com saldo/contador internos | Sim | Sim | Valores altos (futuro) |

Observações verificadas na documentação pública (ver §14): o Android 12 (API 31) permite limitar
usos de uma chave e apaga a chave ao esgotar o contador; há sinalizadores para saber se o hardware
impõe isso. A atestação tem cadeia mais longa e de tamanho variável, certificados de curta duração e
raiz ECDSA P-384 (além da RSA antiga). Ed25519 em hardware **não foi verificado**: por isso `D` pode
ser P-256.

### Política do receptor (limites por voucher — valores de testnet, a calibrar)

| Nível comprovado | Teto por voucher | Exige |
|---|---|---|
| L1 | 5 WFLX | Cofre ativo, colateral ≥ 100 % |
| L2 | 100 WFLX | + atestação válida, nível de segurança TEE/StrongBox, uso único atestado |
| L3 | 1.000 WFLX | + atestação do elemento seguro |

O receptor pode adotar limites mais rígidos. Nenhum nível é aceito sem prova de cofre.

## 5. Parâmetros de rede (novos, em `ChainParams`)

| Parâmetro | Valor inicial | Observação |
|---|---|---|
| `target_block_time` | 5 s (devnet) / 60 s (alvo público) | Converte tempo ↔ altura |
| `vault_max_slots` | 64 | Limita o estado por cofre |
| `vault_collateral_min_pct` | 100 (ρ=1) | Colateral mínimo por vaga |
| `vault_ttl_min_blocks` | 1 dia | Vida mínima (curta, para o dono recuperar o saldo cedo) |
| `vault_ttl_max_blocks` | 30 dias | Vida máxima antes da expiração |
| `claim_window_blocks` | 7 dias | Janela de contestação após fechamento/expiração |
| `min_voucher` | 10 × `min_fee` | Abaixo disso o claim não compensa a taxa |
| `vault_max_value` | 10.000 WFLX | Teto de exposição por cofre |
| `checkpoint_interval` | 100 blocos | Frequência dos checkpoints |
| `receiver_min_margin` | 48 h | Margem mínima até o fim da janela para o receptor aceitar |

## 6. Estado de consenso: registro de cofres

Registro derivado da cadeia (reconstruído e revalidado na carga, com undo por bloco), ao lado do
UTXO set.

```text
Vault {
  vault_id        = txid da transação vault_open
  owner_address, refund_address
  device_key, key_type ("ed25519" | "p256")
  opened_height, expires_height, state ∈ {OPEN, CLOSED}
  fraud: bool
  slots[i] = { cap, collateral_left, claimed_by: voucher_hash | null }
}
```

**Contabilidade da oferta:** `oferta = Σ UTXO + Σ (caps livres + colateral restante dos cofres)`.
Colateral queimado reduz a oferta. O teto `max_supply` vale sobre essa soma.

### 6.1 Tipos de transação (novo campo `kind` + `payload`, validação estrita)

**`vault_open`** — entradas comuns financiam o cofre.
- payload: `device_key, key_type, slots:[cap…], collateral_pct, ttl_blocks, refund_address, pop`
- `pop` = assinatura de `D` sobre o hash do corpo (prova de posse; impede registrar chave alheia).
- Regras: `1 ≤ N ≤ vault_max_slots`; `cap_i ≥ min_voucher`; `collateral_pct ≥ mínimo`;
  `vault_ttl_min ≤ ttl ≤ vault_ttl_max`; `Σ(cap_i + colateral_i) ≤ vault_max_value`; saídas = só troco;
  entradas = `Σ(cap_i + col_i) + saídas + taxa`; `expires_height = h + ttl`.

**`voucher_claim`** — sem entradas; qualquer pessoa pode submeter.
- payload: `voucher` (175 bytes, §7) .
- Regras: cofre existe e `height ≤ limite_de_claim` (§6.2); `slot < N`; `min_voucher ≤ amount ≤ cap`;
  assinatura de `D` válida; saída única `(amount − min_fee) → receiver` e taxa exatamente `min_fee`.
- Efeito, vaga livre: paga de `cap`; marca `claimed_by = H(voucher)`; o resto de `cap` volta no refund.
- Efeito, vaga já usada por outro voucher: se `collateral_left > 0`, paga
  `min(amount, collateral_left) − min_fee` do colateral e marca `fraud = true` (se esse valor for ≤ 0, o claim é rejeitado). Se for o **mesmo**
  voucher: rejeitado (reuso).

**`vault_close` — REMOVIDO na Revisão 2** (ver acima). O cofre termina apenas por expiração em `expires_height`;
quem quiser recuperar o saldo cedo abre cofres com TTL curto.

**`vault_refund`** — sem assinatura; qualquer um pode submeter após o fim da janela.
- Efeito: devolve ao `refund_address` as caps livres e a diferença `cap − amount` das vagas pagas;
  devolve o colateral restante se `fraud = false`; **queima** o colateral restante se `fraud = true`.
  Taxa descontada do total devolvido.

### 6.2 Limite de claim
`limite = expires_height + claim_window`, sempre. Como `expires_height` é fixado na abertura e consta na
prova do cofre, o receptor sabe o prazo real. Nada que o dono faça depois encurta esse prazo, então ele não
consegue pagar offline e retirar o saldo antes de o receptor sincronizar.

### 6.3 Ordem e disputa
Dentro de um bloco vale a ordem das transações; entre blocos, a ordem da cadeia. Na primeira
liquidação da vaga paga-se o valor; as seguintes pagam do colateral.

## 7. Formatos de mensagem (binário fixo, sem ambiguidade)

Escolha: layout binário fixo para o voucher assinado (≈175 bytes, cabe em QR único); sem dependência de CBOR.

```text
voucher_body (111 bytes) =
  version(1) ‖ chain_id_hash(32) ‖ vault_id(32) ‖ slot(u16 BE) ‖ amount(u64 BE)
  ‖ receiver_hash160(20) ‖ request_id(16)
voucher = voucher_body ‖ signature(64)
assinatura de D sobre: "WFLX-VOUCHER-V1" ‖ voucher_body
voucher_hash = SHA-256("WFLX-VOUCHER-ID-V1" ‖ voucher_body)      # SEM a assinatura (anti-maleabilidade)
```
(P-256: assinatura bruta `r ‖ s` de 64 bytes, com **S ≤ n/2 obrigatório**; clientes Android devem
normalizar a assinatura DER do Keystore para S baixo antes de enviar.)

**Pedido** (receptor → pagador): `version, chain_id_hash, receiver_address, amount?, request_id (16 B aleatórios),
eph_pub (X25519), expiração_do_pedido`.

**Voucher + provas** (pagador → receptor, cifrado): `voucher`, `prova_do_cofre`, `atestação?`.

**Recibo** (receptor → pagador): `voucher_hash, request_id, receiver_pubkey, assinatura` sobre
`"WFLX-RECEIPT-V1" ‖ voucher_hash ‖ request_id`.

**Prova do cofre** (centenas de bytes a ~1 KB): registro do cofre + caminho Merkle até a
`vault_root` de um **checkpoint** + certificado do checkpoint (altura, hash do bloco, `vault_root`, assinaturas das
autoridades). O cofre só é utilizável depois de entrar num checkpoint (atraso de ativação ≤ `checkpoint_interval`).

**Atestação**: cadeia X.509 (2–5 KB), enviada uma vez e guardada pelo receptor (cache por hash de `D`).

**Canal**: X25519 efêmero + ChaCha20-Poly1305 na camada de aplicação, independente do transporte;
o `request_id` e o endereço do receptor entram no contexto da chave de sessão.

**Transportes**
- QR: quadros animados quando necessário (voucher puro cabe em um QR).
- BLE: serviço GATT/L2CAP com fragmentação; pareamento não é pré-requisito.
- NFC: Android nativo (leitor + emulação de cartão, HCE). Não disponível na PWA.

## 8. Verificação pelo receptor (checklist; qualquer falha rejeita)

1. `chain_id_hash`, versão e comprimentos corretos.
2. `receiver_hash160` e `request_id` iguais aos do pedido; valor igual ao combinado.
3. Assinatura de `D` válida.
4. Prova de cofre válida contra checkpoint assinado, **não mais antigo que o último checkpoint que o receptor já conhece**; cofre `OPEN`, sem `fraud`, fora da lista local de bloqueio.
5. `slot < N`, `min_voucher ≤ amount ≤ cap`.
6. Vaga **não vista antes** no banco local do receptor (qualquer remetente).
7. Margem: `limite_de_claim − altura_estimada ≥ receiver_min_margin`. A altura é estimada com o
   relógio do **próprio receptor** e o último checkpoint. Nenhum tempo declarado pelo pagador é usado.
8. Nível comprovado e teto por voucher (§4). Para L2/L3: atestação com raízes fixadas, lista de revogação em cache, nível de segurança do hardware, chave de uso único.
9. (Opcional) troca de hashes de vagas vistas com receptores próximos.

## 9. Estados

**Pagador:**
`RASCUNHO → ASSINADA_OFFLINE → ENTREGUE → LIQUIDANDO → CONFIRMADA(n) → FINAL`
Falhas: `EXPIRADA`, `CONFLITO_REJEITADO`, `COLATERAL_PERDIDO`.
Regra de ouro: a vaga é gravada como usada **antes** de o voucher sair do aparelho (write-ahead).
Se o aparelho travar no meio, a vaga se perde; ela nunca é reutilizada.

**Receptor:**
`PEDIDO → RECEBIDA_NAO_VERIFICADA → ACEITA_OFFLINE(nível, teto) → CLAIM_ENVIADO → CONFIRMADA(n) → FINAL`
Falhas: `REJEITADA(motivo)`, `CLAIM_REJEITADO → COMPENSADA | PERDA`, `PRAZO_PERDIDO`.

`ACEITA_OFFLINE` aparece como **pendente**, nunca como saldo gastável. A interface mostra o prazo.
Se um claim for desfeito por reorganização, o estado volta a `ACEITA_OFFLINE` com o mesmo prazo.

## 10. Liquidação e conciliação
1. O receptor, ao ficar online, submete `voucher_claim` (via API → mempool → bloco).
2. O pagador, ao ficar online, compara os vouchers emitidos (log local write-ahead) com o estado do cofre.
   Vaga paga a outro voucher, ou claim que não casa com o log, indica **clonagem ou rollback** → alerta e parada de uso do cofre.
3. O cofre expira em `expires_height`; após `expires_height + claim_window`, `vault_refund`.
4. O app do receptor avisa a contagem regressiva do prazo e submete o claim assim que houver rede.

## 11. Modelo de ameaças

| # | Ameaça | Mitigação | Residual |
|---|---|---|---|
| T1 | Reapresentar o mesmo voucher a outro receptor | Vínculo a `receiver`/`request_id` | — |
| T2 | Dois vouchers distintos para a mesma vaga a receptores distintos | Compensação por colateral; L2/L3 impedem | R1 em L1 |
| T3 | Clonar a carteira em 2º celular | Chave `D` não exportável + atestação (L2/L3) | L1 aceita |
| T4 | Restaurar backup e reusar a vaga | Chave de uso único por voucher / SE | Depende de hardware (H2) |
| T5 | Retirar o saldo antes do claim | Sem fechamento antecipado; refund só após `expires_height + claim_window` | Saldo travado até lá |
| T6 | Gastar o mesmo saldo online | Saldo travado no registro | — |
| T7 | Reenviar o claim | Vaga marcada com hash do voucher | — |
| T8 | Alterar valor/destino do voucher | Assinatura sobre todos os campos | — |
| T9 | MITM/relay em BLE/NFC | Canal cifrado, confirmação de valor e endereço nas duas telas; pagamento vai ao endereço do receptor | Relay só faz ele pagar quem ele escolheu |
| T10 | Atestação falsa, expirada ou revogada | Raízes fixadas; revogação em cache; política por nível | Revogação desatualizada |
| T11 | Manipular o relógio do pagador | Nenhum tempo do pagador é confiado | — |
| T12 | Spam de cofres/claims | Taxa mínima, `min_voucher`, `vault_max_value`, limite por bloco | A calibrar |
| T13 | Receptor perde a janela | Alertas; janela longa | R2 |
| T14 | Produtor reordena claims | PoA: autoridade confiável | PoW: ordem do minerador |
| T15 | Remetente conluiado consigo mesmo | Compensação sai do colateral dele | Neutro |
| T16 | Checkpoint forjado | Assinaturas das autoridades | R5 |
| T17 | Rastreamento de identidade | Endereços novos por pedido | R4 |
| T18 | Perda do aparelho | Refund ao dono após a janela | Fundos travados por até TTL+janela |
| T19 | Voucher reapresentado com assinatura alterada (P-256 maleável) | Hash só do corpo; S baixo obrigatório | — |
| T20 | Computador quântico forja vouchers com a chave pública `D` | Chaves de uso único por vaga baseadas em SHA-256 (§15, decisão 6) | Pendente até a decisão; sem isso, `D` é alvo |

## 12. Compatibilidade com o código existente (planejado, **não executado**)

Preservado sem mudança de comportamento: `crypto/*`, `units`, `blockchain/utxo.py` (UTXO),
`wallet/*`, `node/storage.py`, os 103 testes.

Mudanças previstas na Etapa 3b-1/3b-3:
- `Transaction`: campos `kind` (padrão `"transfer"`) e `payload` (padrão `None`).
- `Block`: `vault_root` no cabeçalho (padrão vazio); checkpoints.
- `ChainParams`: parâmetros do §5.
- `blockchain/vaults.py` (novo): registro + undo; `validation.py`: regras dos novos tipos.
- `crypto/keys.py`: verificação P-256 (ECDSA) além de Ed25519.
- Genesis e txids mudam de valor (campos novos); os testes não dependem de valores fixos, mas
  isso será conferido ao implementar.

## 13. Plano de testes (critérios de aceite da 3b-1)
Gasto duplo da mesma vaga; mesmo voucher reapresentado; voucher para outro receptor; assinatura
adulterada em cada campo; claim após limite; claim dentro e fora da janela (`expires_height + claim_window`);
refund antes do fim da janela rejeitado; voucher P-256 com S alto rejeitado e hash independente da assinatura; fraude com colateral parcial e esgotado; contabilidade da oferta
(colateral queimado); teto de cofre; spam de cofres; reorganização desfazendo claim e refund;
atomicidade de bloco inválido; determinismo entre dois nós reaplicando a mesma cadeia.

## 14. Fontes consultadas (verificar novamente ao implementar)
- Android: `KeyGenParameterSpec.Builder.setMaxUsageCount` (API 31) e sinalizadores
  `FEATURE_KEYSTORE_SINGLE_USE_KEY` / `FEATURE_KEYSTORE_LIMITED_USE_KEY` —
  https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setmaxusagecount
- Android Developers Blog, "Upgrading Android Attestation: Remote Provisioning" (2022) —
  https://android-developers.googleblog.com/2022/03/upgrading-android-attestation-remote.html
- Rotação da raiz de atestação (RSA → ECDSA P-384), análise de terceiros —
  https://protectt.ai/blog/android-key-attestation-root-certificate-rotation
- Chrome, Web NFC (somente NDEF, sem ponto a ponto nem HCE; contexto seguro) —
  https://developer.chrome.com/docs/capabilities/nfc

## 15. Decisões que precisam da sua aprovação
1. Voucher em **layout binário fixo** (175 bytes) em vez de CBOR.
2. Valores iniciais do §5 e os tetos por nível do §4.
3. `D` poder ser **Ed25519 ou P-256**.
4. **Checkpoints assinados por autoridades** para provas offline (válidos na testnet PoA; o PoW exigirá nova solução).
5. Sem transitividade offline e sem "nível 0".
6. **Chaves de vaga resistentes a computador quântico:** cada vaga com chave de uso único baseada em SHA-256
   (LMS/LM-OTS, RFC 8554 e NIST SP 800-208; confirmar ao implementar), com a cadeia guardando só a raiz de Merkle e
   o voucher carregando ~1,1-1,3 KB de assinatura. Opcionalmente somada a uma assinatura P-256 de hardware.
7. **Coinbase comprometendo o hash do bloco anterior** (campo na carga útil da Fase 1), para que redes distintas nunca
   produzam o mesmo txid de coinbase.
8. **Escopo da queima de colateral** em caso de fraude: todo o cofre (implementado) ou só a vaga fraudada (ver R6).
