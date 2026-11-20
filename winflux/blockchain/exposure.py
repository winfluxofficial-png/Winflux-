"""Limites DETERMINÍSTICOS de exposição do colateral (docs/offline-chained-payments.md, §Exposição).

Função pura e crítica para o consenso: dado o estado de uma vaga e um claim que perdeu a corrida
(conflito), calcula quanto o colateral paga, ou recusa. O resultado depende só do estado on-chain e do
claim, nunca de dados fora da cadeia, e a ordem é a ordem de aplicação na cadeia.

Regras (R1-R5, R8, R9):
  R1  a soma das indenizações da vaga nunca passa do colateral restante da vaga;
  R2  para cada nota contestada, a soma das indenizações nunca passa do VALOR dessa nota
      (o que estava efetivamente em jogo), por mais ramos perdedores que existam;
  R3  o mesmo claim/voucher é indenizado no máximo uma vez (reapresentação é recusada);
  R4  cada indenização é no máximo o valor da folha reivindicada;
  R5  ordem de pagamento = ordem de aplicação na cadeia (bloco, posição); esgotado o teto, o resto recebe 0;
  R8  indenização abaixo do mínimo é recusada (evita poeira e crescimento de estado);
  R9  no máximo `max_events` indenizações por vaga (limita o estado e o custo de verificação).
"""
from ..errors import ValidationError


def plan_compensation(*, collateral_left: int, compensated_total: int, contested_value: int,
                      paid_leaves, max_events: int, leaf_id: str, leaf_value: int,
                      min_payout: int) -> int:
    """Retorna o valor a indenizar (> 0) ou levanta ValidationError.

    `compensated_total`: soma já indenizada para ESTA nota contestada.
    `paid_leaves`: ids de claims já indenizados na vaga.
    """
    if leaf_value <= 0 or contested_value <= 0:
        raise ValidationError("valores de indenização inválidos")
    if leaf_id in paid_leaves:
        raise ValidationError("claim já indenizado")                                   # R3
    if len(paid_leaves) >= max_events:
        raise ValidationError("limite de indenizações da vaga atingido")               # R9
    if collateral_left <= 0:
        raise ValidationError("colateral da vaga esgotado")                            # R1
    room = contested_value - compensated_total
    if room <= 0:
        raise ValidationError("limite de indenização do valor contestado atingido")    # R2
    payout = min(leaf_value, collateral_left, room)                                    # R1, R2, R4
    if payout < min_payout:
        raise ValidationError("compensação abaixo do mínimo")                          # R8
    return payout
