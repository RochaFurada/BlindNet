# BlindNet

BlindNet is an experimental security architecture for local IoT networks. It moves low-power or weakly protected devices behind ESP32-based Guardians, validates commands through a cryptographic pipeline, and exposes only a small local control surface to the protected devices.

The project was built as a working prototype: Guardians run on ESP32 with ESP-IDF, IoT devices can be simulated with Arduino sketches, and client-side tools generate signed Action Pills that travel through BLE/G2G before becoming local MQTT commands.

Presentation site: https://blind-net.vercel.app/

## Core Idea

Most IoT devices are easy to discover, fingerprint, and attack once they are directly visible on a local network. BlindNet changes that topology.

Instead of allowing the phone, the router, or an external client to talk directly to each device, a Guardian becomes the local security boundary:

- IoT devices connect to the Guardian AP, not directly to the main LAN.
- Devices receive commands through a local MQTT broker controlled by the Guardian.
- External commands arrive as Action Pills, not as raw MQTT messages.
- The Guardian validates authorship, replay protection, target semantics, and device-specific encryption before publishing anything.
- Multiple Guardians can relay opaque Action Pills over BLE/G2G until the correct Guardian can digest them.

In short: the IoT device stays simple, while the Guardian carries the security logic.

## Architecture Overview

```text
Client / App
    |
    | signed Action Pill over BLE
    v
Guardian
    |
    | Capsule Pill validation
    | anti-replay cache
    | G2G relay
    | Active Substance digestion
    | RNA / Membrane semantic validation
    v
Local MQTT broker
    |
    v
Protected IoT device
```

The system separates command transport, authorization, semantic validation, and final execution.

## Main Concepts

### Guardian

The Guardian is an ESP32 running the BlindNet firmware. It manages:

- AP/STA Wi-Fi operation.
- Setup and maintenance/admin modes.
- Local MQTT broker.
- BLE G2G communication.
- Action Pill reception, relay, and processing.
- Device registry and ribosome storage.
- Optional gateway/security services.

The high-level runtime coordination is handled by the Rust `conscience` module inside the `cortex` component. It acts as a state machine for boot, setup, normal operation, admin mode, relay, and digestion.

### Action Pill

An Action Pill is the command container used by BlindNet. It is split into two major parts:

- `Capsule Pill`: signed metadata used for authorization, freshness, replay protection, and routing.
- `Active Substance`: encrypted command payload intended for a specific protected device.

This split lets a Guardian validate and relay the capsule without necessarily understanding the internal command. Only the Guardian with the correct device secret can digest the Active Substance.

### Stomach

The Stomach is the first digestion layer. It receives complete Action Pills, checks whether the capsule was already seen, and prevents duplicated work through the capsule cache.

### Ribosome Table

The Ribosome Table stores known protected devices and their execution context:

- MQTT client/device identifier.
- Device secret.
- RNA binding.
- Epoch/versioning metadata.

It is the table that tells the Guardian which local devices may be able to digest a given Active Substance.

### Active Enzyme

The Active Enzyme tries to decrypt the Active Substance using the device secret from a ribosome entry. If the secret is wrong, the payload remains opaque.

### RNA and Amino Acids

RNA represents the command language allowed for a device. Amino Acids are the allowed atomic actions, such as a `TOGGLE` command for a light.

This prevents the system from treating every decrypted payload as valid. A command still needs to match the semantic vocabulary assigned to that device.

### Membrane

The Membrane is the final semantic filter. It checks whether a digested Active Substance fits the RNA of the target device before the broker publishes anything.

### G2G Relay

Guardians discover each other through BLE and can relay Action Pills between nodes. A Guardian may receive an Action Pill, check its cache, relay it to peers, and then try to digest it locally.

This allows the client to send a command without knowing exactly which Guardian owns the final device.

## Repository Structure

```text
BlindNet/
├── firmware/                  # ESP-IDF firmware for the Guardian
│   ├── main/                  # ESP-IDF app entrypoint
│   └── components/
│       ├── cortex/            # Rust orchestration/state machine and FFI layer
│       ├── action_pill/       # Capsule Pill and Active Substance logic
│       ├── membrane/          # RNA, Amino Acids, Ribosome Table and storage
│       ├── g2g_ble/           # BLE transport between Guardians
│       ├── MQTT_broker/       # Embedded Mosquitto-based MQTT broker
│       ├── admin_server/      # Setup/admin HTTP server
│       ├── wifi_manager/      # AP/STA Wi-Fi control
│       ├── config_store/      # Persistent Guardian configuration
│       ├── stomach/           # Capsule cache / anti-replay support
│       └── ...                # Gateway, firewall, policy and support modules
├── tools/
│   └── action_pill/           # Python tooling for keys, admin challenge and BLE sending
└── iot_device_arduino/        # Simple Arduino IoT device simulator
```

The interactive presentation was moved to a separate deployment/repository and is available at:

https://blind-net.vercel.app/

## Firmware

The Guardian firmware is an ESP-IDF project targeting ESP32.

### Requirements

- ESP-IDF compatible with the project configuration.
- ESP32 target.
- Rust Xtensa toolchain for the `cortex` component.
- Python environment configured for ESP-IDF tools.

### Build

From `firmware/`:

```bash
idf.py set-target esp32
idf.py build
```

### Flash and Monitor

```bash
idf.py flash monitor
```

The application entrypoint is small by design:

```c
void app_main(void)
{
    ESP_ERROR_CHECK(blindnet_boot());
}
```

The boot flow then enters the `cortex` component, where the Guardian decides whether to start setup mode or normal operation.

## Setup and Admin Flow

When a Guardian has no saved configuration, it starts a temporary setup AP. Through the setup/admin interface, the owner configures:

- Main Wi-Fi credentials.
- Guardian AP credentials.
- Zone information.
- Issuer public key.

In normal operation, holding the setup/admin button opens a temporary admin window. The admin network is intentionally short-lived and requires proof of identity through a signed challenge before configuration pages are exposed.

The admin flow is used to approve devices, bind them to RNA, and store the device secret in the Ribosome Table.

## Action Pill Tools

Python tools live in `tools/action_pill`.

Install dependencies:

```bash
python -m pip install -r tools/action_pill/requirements.txt
```

Generate issuer key material for local tests:

```bash
python tools/action_pill/generate_issuer_key.py --out-dir tools/action_pill/test_keys
```

Send an Action Pill over BLE:

```bash
python tools/action_pill/send_action_pill_ble.py \
  --private-key tools/action_pill/test_keys/issuer_private_key.pem \
  --device-secret <device_secret_hex> \
  --device-id lamp01 \
  --topic blindnet/lamp01/cmd \
  --amino TOGGLE
```

On PowerShell, replace `\` line continuations with backticks.

### Important Security Note

Files under `tools/action_pill/test_keys/` are test material only. Do not reuse those keys in a real deployment. Before publishing or sharing the repository broadly, rotate any key material used during demonstrations and make sure no real private keys or real device secrets are committed.

## Arduino IoT Device Simulator

The folder `iot_device_arduino/` contains a simple ESP32 Arduino sketch that connects to the Guardian AP and subscribes to MQTT commands.

The current test device:

- Uses MQTT broker `192.168.4.1:1883`.
- Subscribes to a configured command topic.
- Toggles an LED on GPIO 15.
- Uses `PubSubClient`.

This simulator is intentionally simple: the protected device does not implement the BlindNet cryptographic pipeline. It only receives the final command after the Guardian has validated it.

## Security Model

BlindNet is designed around layered defense:

- Device obfuscation: protected devices are moved behind a Guardian boundary.
- Command authenticity: Capsule Pills are signed by the issuer key.
- Replay resistance: nonce/digest data is cached by the Stomach.
- Payload confidentiality: Active Substance is encrypted with a device-specific secret.
- Semantic authorization: RNA and Membrane prevent invalid commands from being executed.
- Local execution: devices receive only local MQTT messages after validation.
- Guardian relay: G2G allows opaque forwarding without exposing the payload to every node.

The prototype currently demonstrates command authorization, local publication and G2G relay. Denial-of-service hardening for BLE noise and hostile radio traffic is an identified future improvement.

## Current Status

Working prototype validated with:

- ESP32 Guardians.
- BLE Action Pill delivery.
- Guardian-to-Guardian relay.
- Local MQTT broker.
- Arduino-based IoT LED device.
- Admin challenge authentication.
- Device registration through the Guardian admin flow.
- Active Substance digestion and command publication.

This is not a production-ready security product. It is a research/prototype architecture intended to demonstrate how layered authorization, local network isolation and semantic command filtering can be combined on constrained hardware.

## Roadmap

- Improve BLE/G2G scheduling and robustness under heavy traffic.
- Add stronger DoS resistance for BLE ingress.
- Expand RNA/Amino Acid definitions for more device classes.
- Improve observability and structured logs for multi-Guardian tests.
- Add automated integration tests for Action Pill generation and parsing.
- Separate demo material, private keys and presentation assets from firmware releases.

## License

No license has been declared yet. Treat the code as private/proprietary unless a license is added.
