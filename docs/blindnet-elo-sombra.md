# BlindNet: Elo-Sombra

`Elo-Sombra` e a camada que liga um dispositivo local ao app sem expor o
identificador real do dispositivo e sem usar um hash previsivel como chave.

O objetivo e simples:

```text
o app sabe controlar um dispositivo,
mas nao sabe nem carrega o id real usado dentro da LAN do Guardian.
```

## Ideia principal

Nao usar:

```text
hash = SHA256("luz_sala")
AES_key = hash
```

Isso e fraco porque nomes de dispositivos podem ser previsiveis.

Usar:

```text
device_secret = 32 bytes aleatorios gerados pelo Guardian
device_tag    = HMAC(device_secret, contexto)
as_key        = HKDF(device_secret, contexto)
```

O `device_secret` e a capacidade real. Quem tem esse segredo consegue gerar a
chave correta para cifrar o `Active Substance`.

## O que o Guardian guarda

```text
device_real_id
device_secret_atual
device_secret_anterior
epoch_atual
politicas locais
estado de rotacao
```

Exemplo de `device_real_id`:

```text
mqtt topic real
gpio interno
id local do dispositivo
```

Esse valor nunca precisa sair do Guardian.

## O que o app guarda

```text
nome amigavel: "Luz da sala"
device_tag
device_secret ou capability derivada
epoch
metadados visuais do app
```

O nome amigavel e apenas interface do usuario. Ele nao entra no protocolo.

## Derivacoes

Identificador opaco do dispositivo:

```text
device_tag = HMAC-SHA256(
    key = device_secret,
    msg = "blindnet/device-tag/v1" || network_id || epoch
)
```

Chave para cifrar o Active Substance:

```text
as_key = HKDF-SHA256(
    input_key_material = device_secret,
    salt = network_id || epoch,
    info = "blindnet/as-key/v1"
)
```

## Fluxo de uso

```text
1. Usuario escolhe um dispositivo no app.
2. App deriva as_key usando device_secret + epoch.
3. App cifra o Active Substance.
4. App monta Capsule Pill com active_hash.
5. App assina o Capsule Pill.
6. App envia Action Pill ao Guardian mais proximo.
7. Guardians repassam por BLE/swarm.
8. Cada Guardian tenta digerir o AS com seus device_secrets locais.
9. Apenas o Guardian correto consegue abrir e executar.
```

## Rotacao

O `device_secret` nao deve ser eterno.

O Guardian pode rotacionar capacidades ao longo do tempo:

```text
device_secret_atual    -> usado normalmente
device_secret_anterior -> aceito por uma janela curta
next_rotation_at       -> tempo com jitter por dispositivo
```

Durante uma sessao admin autorizada:

```text
1. Guardian gera novo segredo.
2. App autenticado recebe a nova capability.
3. App confirma recebimento.
4. Guardian grava no config_store.
5. Segredo antigo expira depois da janela de tolerancia.
```

## Regra mental

```text
Hash identifica.
Segredo autoriza.
HKDF deriva chave.
Assinatura prova origem.
Cache mata repeticao.
```

O `Elo-Sombra` existe para impedir que o identificador do dispositivo vire uma
senha fraca ou um rastro permanente dentro da BlindNet.
