package br.winflux.wallet

import br.winflux.wallet.core.BcEd25519
import br.winflux.wallet.core.Ed25519

/** Ed25519 used in the JVM tests (BouncyCastle, same as the app). */
val testEd: Ed25519 = BcEd25519
