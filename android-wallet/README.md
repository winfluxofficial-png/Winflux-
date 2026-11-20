# Winflux Wallet (Android) — v0.1 testnet

Carteira **online** para a testnet: criar/restaurar (chave de recuperação `wflxk1-…`, compatível com `winflux/wallet/hd.py`),
saldo, receber (QR + endereço novo a cada recebimento), enviar (revisão de valor/taxa antes de confirmar), escolher o nó.
Kotlin + Jetpack Compose. A semente fica cifrada por chave não exportável do Android Keystore (StrongBox se houver),
sem backup em nuvem, tela protegida contra captura (`FLAG_SECURE`).

**NÃO inclui ainda**: pagamentos offline (notas/NFC/BLE), atestação de hardware, leitura de QR por câmera, biometria
para enviar, histórico de transações. Testnet apenas.

## Estado da verificação (honesto)
- `core/` (endereços, HD, chave de recuperação, JSON canônico, txid, assinatura, seleção de moedas, taxa, motor de carteira)
  é Kotlin puro e foi **compilado e testado na JVM** (15 testes) contra vetores gerados pelo código Python de referência:
  a transação assinada sai **idêntica byte a byte** (JSON, txid, assinaturas Ed25519, taxa por byte).
- `net/`, `store/` e `ui/` **não foram compilados nem executados** (exigem o Android SDK, indisponível onde foi escrito).
  Abra no Android Studio, sincronize o Gradle e corrija o que o compilador apontar (versões de AGP/Compose podem precisar de ajuste).
- Não foi testado em aparelho nem contra um nó rodando.

## Rodar
1. Suba um nó: `python -m winflux …` com API (`--api-port 8081`, ver README da raiz). No celular use o IP do PC na Wi-Fi
   (`http://192.168.x.x:8081`); no emulador, `http://10.0.2.2:8081` (padrão). `http` só é aceito para IPs privados; fora disso, `https`.
2. Android Studio → *Open* esta pasta → Run. Testes do núcleo: `./gradlew :app:testDebugUnitTest` (gere o wrapper com `gradle wrapper`).

## Regenerar vetores de teste
Os vetores (`app/src/test/.../Vectors.kt`) vêm do código Python; se mudar formato de tx/endereço/HD no nó, regenere-os e rode os testes.

## Próximos passos
Câmera para ler QR, BiometricPrompt no envio, histórico (exige índice por endereço no nó), TLS, e então o módulo offline
(A3 já está no nó; A4 e o lado de hardware/NFC no app).
