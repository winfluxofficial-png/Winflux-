# Arquitetura e riscos

## Camadas
`crypto` → `blockchain` (regras puras, sem rede/IO) → `consensus` (plugável) → `node` (storage, mempool, rede, API) →
clientes (PWA, Android). Regras e clientes compartilham o mesmo protocolo documentado em `protocol.md`;
a carteira nunca guarda saldo: consulta nós, e a chave privada nunca sai do dispositivo.

## Decisões
- UTXO set é estado derivado: reconstruído e **revalidado** a cada inicialização (o disco não é confiável).
- SQLite (WAL, `synchronous=FULL`) para blocos; sem banco central de saldos.
- Keystore: scrypt (n=2^15) + AES-256-GCM, endereço como dado autenticado; arquivo `0600`, nunca sobrescreve.

## Pendências conhecidas (não esquecer)
- **Sem mempool/rede ainda** (Etapa 4). Sem limites de taxa/DoS por peer ainda.
- **Maturidade de coinbase** e **reorganizações**: necessárias antes do PoW (Etapa 5); o `UTXOSet` já tem undo.
- **PoA** é centralizado e para se a autoridade da vez cair; só serve para a testnet.
- **Marca**: nome "Winflux"/símbolo "WFLX" ainda sem pesquisa de disponibilidade.
- **Backup/recuperação de chave** (frase-semente) ainda não existe: perder a senha = perder os fundos.
- Nenhuma auditoria externa foi feita.
