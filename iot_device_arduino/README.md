# BlindNet IoT Arduino

Sketch simples para simular um dispositivo IoT conectado ao Guardian.

## Como usar

1. Abra `guardian_led_device/guardian_led_device.ino` no Arduino IDE.
2. Instale a biblioteca `PubSubClient` pelo Library Manager.
3. Selecione a placa ESP32 usada no dispositivo IoT.
4. Ajuste no topo do sketch:
   - `WIFI_SSID`: AP normal do Guardian.
   - `WIFI_PASSWORD`: senha do AP normal do Guardian.
   - `MQTT_CLIENT_ID`: id que vai aparecer no admin e ser cadastrado no ribosome.
   - `COMMAND_TOPIC`: topic usado dentro do active_substance.
5. Grave no ESP do dispositivo IoT.

## Comandos aceitos

O Guardian publica no broker `192.168.4.1:1883`.

- Payload vazio: alterna o LED, usado por `AMINO_TOGGLE`.
- `1` ou `ON`: liga o LED.
- `0` ou `OFF`: desliga o LED.
- `TOGGLE`: alterna o LED, util para teste manual.

O LED fica no GPIO 15.
