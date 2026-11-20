package br.winflux.wallet

import br.winflux.wallet.core.BcEd25519
import br.winflux.wallet.core.Ed25519

/** Ed25519 usado nos testes de JVM (BouncyCastle, igual ao app). */
val testEd: Ed25519 = BcEd25519
