# Action Pill test tools

Scripts simples para gerar a chave emissora e mandar uma `ActionPill` por BLE.

## 1. Dependencias

```powershell
python -m pip install -r tools/action_pill/requirements.txt
```

## 2. Gerar chave publica para o ESP

```powershell
python tools/action_pill/generate_issuer_key.py --out-dir test_keys
```

Suba `test_keys/issuer_public_key.pem` na tela de setup do ESP. O script tambem imprime:

- `issuer_key_id`: deve bater com o que o firmware calcula internamente.
- `device_secret`: cadastre no admin em `/ribosome/add` com o mesmo `mqtt_client_id` que voce vai usar em `--device-id`.

## 3. Gerar/enviar uma Action Pill

```powershell
python tools/action_pill/send_action_pill_ble.py `
  --private-key C:\Users\Samue\Desktop\TrabalhoESP\BlindNet\tools\action_pill\test_keys/issuer_private_key.pem `
  --device-secret 270b1b26e0e48fd1e0777cb5bb0aa907ce806f7f3da115cff69d08b3345b25ec`
  --device-id lamp01 `
  --topic blindnet/lamp01/cmd `
  --amino TOGGLE
```

Para gerar o binario sem enviar por BLE:

```powershell
python tools/action_pill/send_action_pill_ble.py ... --no-send
```

## 4. Desbloquear admin temporario

Conecte no AP temporario `ZoneGuard_Admin`, aberto, e rode:

```powershell
python tools/action_pill/sign_admin_challenge.py `
  --private-key C:\Users\Samue\Desktop\TrabalhoESP\BlindNet\tools\action_pill\test_keys\issuer_private_key.pem
```

O script busca `http://192.168.4.1/challenge`, assina com ECDSA/SHA-256 usando a chave privada e envia a assinatura para `/unlock`.
