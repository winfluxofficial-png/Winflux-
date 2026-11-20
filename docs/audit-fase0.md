# Auditoria da Fase 0 (Etapas 1-3) — achados e situação

Método: testes existentes + sondas adversariais (fuzz de parsing e validação, propriedades sob operações
aleatórias, maleabilidade de assinatura, escala) + revisão do código. **Não é uma auditoria formal.**
Os testes de sonda agora são permanentes em `tests/test_robustness.py`.

| # | Achado | Situação |
|---|---|---|
| 1 | Taxa fixa por transação (espaço de bloco subprecificado) | **Corrigido**: `taxa ≥ max(min_fee, min_fee_per_byte × bytes)` + testes e mutação |
| 2 | Sem limite de bytes por bloco (teórico 200 MB) | **Corrigido**: `max_block_bytes` (padrão 1 MB), validação e gerador de blocos |
| 3 | Troco voltava ao endereço de origem | **Corrigido na carteira nova** `HDWallet`: troco sempre em endereço novo, pulando endereços já vistos; o `build_transfer` legado ainda usa o endereço de origem (documentado, será descontinuado) |
| 4 | `chain_id` repetido entre gêneses diferentes permite replay (coinbases iguais) | **Corrigido**: a coinbase compromete o hash do bloco anterior (txids distintos entre redes, teste) e `devnet init` deriva o `chain_id` do gênese |
| 5 | PoA de uma autoridade (censura, sem finalidade) | Esperado em testnet; tratado no portão de consenso (Fase 6) |
| 6 | Timestamps sem mediana dos blocos anteriores | Adiado para o consenso público |
| 7 | Sem maturidade de coinbase / reorganização | Adiado (necessário antes do PoW) |
| 8 | UTXO set todo em memória, carga revalida tudo | Aceitável em testnet (3.000 blocos em 0,8 s); snapshots depois |
| 9 | Serialização JSON (tx simples = 550 B) | Aberto: formato binário com identificador de esquema (Fase 1, parte restante). O voucher offline já é binário (175 B) |
| 10 | Semente em memória sem zeragem; sem frase de recuperação; senha na linha de comando | **Parcialmente corrigido**: chave de recuperação (`wflxk1-…`, com checksum e forma canônica) e senha do devnet só por variável de ambiente ou prompt. Python não permite zerar memória com garantia (limitação conhecida) |

Bugs encontrados *durante* a correção (todos cobertos por teste):
- O troco da `HDWallet` reutilizava um endereço que já tinha recebido fundos sem ser "entregue" pela carteira.
- A chave de recuperação aceitava o último caractere adulterado (base32 não canônico).

Sem problemas encontrados: maleabilidade de txid, exceções inesperadas no parsing, violações de invariante
de oferta, aceitação de gasto duplo (testado com 20 mil mutações de bloco, 5 mil de transação e 400 operações aleatórias).


## Revisão da Fase 1a / A1
| Achado | Situação |
|---|---|
| Voucher já indenizado podia ser reapresentado: derrubava a produção de blocos (`ValueError`) ou pagava de novo (9,99998 por um voucher de 8) | **Corrigido** (R3, guarda de outpoint duplicado), testes de regressão e mutação |
| Verificador de prova quebrava com `TypeError` diante de `state`/`key_type` não hasheáveis | **Corrigido** (achado por fuzz), só `ValidationError` agora |
| Recompute da `state_root` é O(cofres × vagas) por bloco | **Aberto** (cache incremental antes de uso público) |
| `ValueError` fora de `ValidationError` em `Ledger.apply` pode derrubar o produtor se o `check` falhar | **Mitigado** pela guarda em `check`; manter fuzz de ledger |


## Revisão da A2
| Achado | Situação |
|---|---|
| **`key_type` não hasheável em `vault_open` levantava `TypeError` dentro da validação de CONSENSO** (derrubaria o produtor de blocos) | **Corrigido**, fuzz de carga útil permanente para `vault_open`, `voucher_claim` e `vault_refund` |
| Mesmo defeito (`x in dict` com valor não hasheável) na verificação de atestação | **Corrigido** (achado por fuzz); auditoria por grep de todos os `in <dict>` sem `isinstance` |
| Lacuna de teste: atestação válida mas sem propriedades de hardware (software, sem uso único) não era exercitada | **Corrigido** (mutação V7 detectada) |
| Hardware comprometido só é adversário se adulterado ANTES do primeiro uso da chave (depois de apagada, não volta) | Modelado no simulador e no demo |
| P1: validação de tipo do campo `key` na prova | Mutante equivalente (a folha Merkle já amarra o valor); mantida como defesa em profundidade |
