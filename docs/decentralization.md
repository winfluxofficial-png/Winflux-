# Princípio de descentralização da Winflux

A Winflux é um protocolo monetário aberto, público e *permissionless*. Não possui proprietário, administrador central ou
entidade com autoridade privilegiada sobre a rede.

Qualquer pessoa pode executar um nó, verificar transações, participar do mecanismo de consenso e desenvolver implementações
compatíveis com o protocolo, sem necessidade de autorização.

A emissão monetária, a validação de transações, a liquidação de pagamentos e as regras de segurança são determinadas pelo
protocolo e verificadas independentemente pelos participantes.

Nenhuma entidade possui poderes administrativos para criar moedas arbitrariamente, congelar carteiras, reverter transações,
alterar saldos ou impor atualizações aos participantes.

A evolução do protocolo ocorre por desenvolvimento aberto, revisão pública e adoção voluntária de versões pelos operadores da rede.

A continuidade da Winflux não depende de seus desenvolvedores originais, de seus servidores ou de qualquer organização específica.

O objetivo é construir uma infraestrutura monetária descentralizada, resistente à censura e capaz de continuar funcionando
independentemente de quem a criou.

---

## Como cada afirmação é garantida no código (e testada)

| Princípio | Mecanismo | Teste |
|---|---|---|
| Sem proprietário/administrador | Rede PoW **rejeita** `authorities` nos parâmetros; não há chave especial em lugar nenhum | `test_decentralization.py::test_public_network_has_no_privileged_party` |
| Lançamento justo | `netgen` gera gênese com **zero alocações** (sem pré-mineração, sem faucet) | `test_fair_launch_genesis_has_no_premine_no_authority` |
| Qualquer um participa do consenso | Qualquer endereço minera; nada identifica o produtor (`producer`/`signature` vazios) | `test_any_address_can_mine_without_permission` |
| Qualquer um roda um nó | `python -m winflux.node.main` com o gênese; o nó verifica tudo sozinho | `test_network.py` (3 nós, sincronização) |
| Emissão só pelo protocolo | Coinbase ≤ recompensa(altura) + taxas; oferta ≤ teto, verificada por todo nó | `test_money.py`, `test_only_mining_creates_coins…` |
| Ninguém congela/reverte/altera saldos | Gastar depende só da assinatura do dono; não existe tipo de transação administrativo | `test_only_mining…`, `test_no_admin_backdoors_in_source` |
| Sem atualização imposta | Nós com regras diferentes rejeitam o gênese/versão do outro: é adoção voluntária (fork de quem discorda) | `test_different_network_is_refused` |
| Funciona sem os criadores | Sem servidores centrais: descoberta por pares (`addr`), sementes são só pontos de partida substituíveis; carteiras falam com **qualquer** nó | `test_partition_then_heal…`, `test_api_and_cli_end_to_end` |
| Resistência à censura | Mempool aberto, difusão P2P, mineração aberta; cadeia de maior trabalho vence (reorg) | `test_pow_reorg.py` |

## Honestidade técnica: o que o software NÃO garante sozinho

Um protocolo só é descentralizado **na prática** quando muita gente independente o opera. Isto depende do mundo, não do código:

1. **Descentralização é um fato social.** Com poucos mineradores/nós, quem os controla controla a rede (ataque de 51%).
   O código não impede isso; só torna tudo verificável.
2. **"Ninguém reverte transações" é probabilístico.** Reorganizações existem: uma transação só é praticamente final após
   várias confirmações. Recompensas de mineração amadurecem em `coinbase_maturity` blocos.
3. **Lançamento justo ≠ distribuição justa.** Sem pré-mineração, quem minera cedo e com mais hardware acumula mais. Os
   criadores também podem minerar; o que não podem é ter privilégio de protocolo.
4. **As sementes (`--seed`) são pontos de entrada, não autoridades.** Publique várias, de pessoas diferentes. Hoje não há DNS seeds.
5. **Segurança do PoW depende do algoritmo.** SHA-256 permite ASICs (centralização de hardware). Decisão aberta
   (ver "Decisões pendentes").
6. **Ninguém auditou este código.** É software de testes. Não use com dinheiro real antes de auditoria independente.

## Decisões pendentes (precisam de revisão pública antes de uma rede com valor)

| Decisão | Estado atual | Observação |
|---|---|---|
| Algoritmo de PoW | SHA-256 do cabeçalho | Trocar por algo resistente a ASIC é só implementar `Consensus` |
| Tempo de bloco | 60 s no `netgen` (vaults escalam junto) | O devnet usa 5 s; PoW público com 5 s teria muitos órfãos |
| Dificuldade inicial | `--initial-hashes` (padrão 2²⁰) | Escolher conforme o hashrate esperado no lançamento |
| Maturidade de coinbase | 100 blocos | |
| Pagamentos offline sobre PoW | **NÃO adaptados**: provas de cofre usam *checkpoint assinado por autoridade* (PoA) | Em PoW o checkpoint tem de ser um cabeçalho com trabalho + alvo; ver `security-assumptions.md` H3/H11 |
| Formato binário de tx, assinaturas pós-quânticas | Fase 1b | |
| Marca "Winflux/WFLX" | Sem pesquisa de disponibilidade | `docs/naming.md` |

## Como lançar uma rede (não requer permissão de ninguém)

```bash
python -m winflux.tools.netgen --name mainnet --out genesis.json   # gera o gênese justo (zero pré-mineração)
# PUBLIQUE o genesis.json (ou só o chain_id + hash do gênese) em vários lugares independentes.
python -m winflux.node.main --genesis genesis.json --listen 0.0.0.0:8333 --mine <seu endereço>
# outros: --seed SEU_IP:8333
python -m winflux.cli --wallet w.json create      # carteira HD com chave de recuperação
```
