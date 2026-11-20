# Hipóteses de segurança (Winflux)

> Software de testes. Nada aqui é promessa de segurança absoluta. Pagamento offline **nunca** previne gasto duplo por
> si só: limita o dano e o compensa de forma determinística.

## O que o consenso GARANTE (verificado por todo nó, testado)
- Oferta ≤ teto; nenhuma criação de moeda fora da coinbase; valores inteiros.
- Cada nota/vaga paga no máximo uma vez com valor do depósito; gasto duplo de nota é detectado na liquidação (`note_claim`)
  e o ramo perdedor só é indenizado pelo colateral, sob limites R1–R9 (nunca acima do colateral nem do valor da vaga).
- Estado determinístico e reversível (reorganizações), comprometido no `state_root` de cada bloco.

## O que NÃO é garantido
- **Gasto duplo offline** não é impedido: quem possui a chave da vaga pode gastá-la em dois lugares. O receptor só vê o
  problema ao liquidar. A proteção é: colateral (ρ ≥ 1), tetos de valor e de profundidade, nível de hardware, prazo.
- **Hardware**: a atestação (Secure Element/TEE/StrongBox) e a chave de uso único são SIMULADAS (`hardware_sim.py`).
  Toda proteção baseada em hardware depende de: raiz de confiança do fabricante íntegra, firmware sem falhas,
  impossibilidade de clonar/restaurar o estado da chave. Nada disso foi verificado em dispositivos reais.
- **Software sem hardware**: profundidade 1 e teto baixo (política do receptor, não consenso).
- **Quântico**: a chave de uma nota só é revelada ao gastar (compromisso de hash), reduzindo a exposição; Ed25519/P-256
  continuam quebráveis por um computador quântico. Chaves de vaga pós-quânticas (LMS) estão no roadmap (fase 1b).
- **Disponibilidade**: se o dono não liquidar dentro de `claim_window`, o valor volta ao dono do cofre (`vault_refund`).
  Receptores precisam submeter o `note_claim` antes do prazo; por isso o verificador exige margem mínima.
- **Poeira**: folhas abaixo de `max(min_voucher_value, min_fee+1)` não são liquidáveis.
- **Limites de estado**: ≤ 16 indenizações (R9) e ≤ 64 folhas liquidadas por vaga.
- **Sem auditoria externa.** Parâmetros (colateral, janelas, tetos) são de testnet e precisam ser calibrados.
