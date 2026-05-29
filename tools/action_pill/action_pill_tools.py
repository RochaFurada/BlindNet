from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import math
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


CAPSULE_PILL_VERSION = 3
CAPSULE_PILL_NONCE_LEN = 16
CAPSULE_PILL_NETWORK_ID_LEN = 16
CAPSULE_PILL_ISSUER_KEY_ID_LEN = 16
CAPSULE_PILL_SIGNATURE_MAX_LEN = 96
CAPSULE_PILL_DIGEST_LEN = 32

CAPSULE_PILL_ACTION_MQTT = 1
CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER = 1

ACTIVE_SUBSTANCE_VERSION = 2
ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN = 256
ACTIVE_SUBSTANCE_NONCE_LEN = 12
ACTIVE_SUBSTANCE_TAG_LEN = 16
ACTIVE_SUBSTANCE_DEVICE_ID_LEN = 32
ACTIVE_SUBSTANCE_TOPIC_LEN = 32

ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM = 1
ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM = 2

ACTION_PILL_LEN = 480
G2G_BLE_FRAGMENT_MAX_LEN = 220
G2G_WIRE_VERSION = 1
G2G_WIRE_TYPE_ACTION_PILL = 1
G2G_WIRE_HEADER_LEN = 46
G2G_WIRE_PAYLOAD_MAX = G2G_BLE_FRAGMENT_MAX_LEN - G2G_WIRE_HEADER_LEN

G2G_SERVICE_UUID = "0150534e-4152-542d-5041-2d4732474e42"
G2G_RX_UUID = "01454d47-4152-462d-5852-2d4732474e42"

HKDF_SALT_PREFIX = b"BlindNet active enzyme salt v1"
HKDF_INFO_PREFIX = b"BlindNet active substance decrypt key v1"

AMINO_VALUE_NONE = 0
AMINO_VALUE_BOOL = 1
AMINO_VALUE_INT = 2

AMINOS = {
    "ON": (1, AMINO_VALUE_NONE),
    "OFF": (2, AMINO_VALUE_NONE),
    "OPEN": (3, AMINO_VALUE_NONE),
    "CLOSE": (4, AMINO_VALUE_NONE),
    "SET_SPEED": (5, AMINO_VALUE_INT),
    "SET_LEVEL": (6, AMINO_VALUE_INT),
    "READ_STATE": (7, AMINO_VALUE_NONE),
    "TOGGLE": (8, AMINO_VALUE_NONE),
    "LOCK": (9, AMINO_VALUE_NONE),
    "UNLOCK": (10, AMINO_VALUE_NONE),
    "SET_TEMPERATURE": (11, AMINO_VALUE_INT),
    "SET_MODE": (12, AMINO_VALUE_INT),
}


@dataclass(frozen=True)
class ActionPillBuild:
    action_pill: bytes
    message_id: bytes
    issuer_key_id: bytes
    network_id: bytes
    active_hash: bytes
    signature: bytes


def parse_hex_exact(value: str, length: int, name: str) -> bytes:
    text = value.strip().replace(":", "").replace("-", "").replace(" ", "")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} precisa ser hex valido") from exc
    if len(raw) != length:
        raise argparse.ArgumentTypeError(
            f"{name} precisa ter {length} bytes ({length * 2} hex chars)"
        )
    return raw


def c_string_field(value: str, size: int, name: str) -> bytes:
    raw = value.encode("utf-8")
    if not raw or len(raw) >= size:
        raise ValueError(f"{name} deve ter entre 1 e {size - 1} bytes UTF-8")
    return raw + b"\x00" * (size - len(raw))


def load_private_key(path: Path):
    from cryptography.hazmat.primitives import serialization

    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def public_key_pem_from_private(private_key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def issuer_key_id_from_public_pem(public_pem: bytes) -> bytes:
    normalized = public_pem.replace(b"\r\n", b"\n").replace(b"\r", b"")
    return hashlib.sha256(normalized).digest()[:CAPSULE_PILL_ISSUER_KEY_ID_LEN]


def derive_network_id_from_config(zone_id: int, guardian_id: int, policy_version: int) -> bytes:
    return (
        struct.pack("<I", zone_id)
        + struct.pack("<I", guardian_id)
        + struct.pack("<I", policy_version)
        + struct.pack("<I", zone_id)
    )


def make_command_plaintext(
    device_id: str,
    topic: str,
    amino_name: str,
    value: Optional[int],
) -> bytes:
    amino_key = amino_name.upper()
    if amino_key not in AMINOS:
        raise ValueError(f"amino desconhecido: {amino_name}")

    amino_id, payload_type = AMINOS[amino_key]
    if payload_type == AMINO_VALUE_NONE:
        if value is not None:
            raise ValueError(f"{amino_key} nao aceita --value")
        payload_i32 = 0
    else:
        if value is None:
            raise ValueError(f"{amino_key} precisa de --value")
        payload_i32 = int(value)

    return struct.pack(
        "<32s32siB3si",
        c_string_field(device_id, ACTIVE_SUBSTANCE_DEVICE_ID_LEN, "device-id"),
        c_string_field(topic, ACTIVE_SUBSTANCE_TOPIC_LEN, "topic"),
        amino_id,
        payload_type,
        b"\x00\x00\x00",
        payload_i32,
    )


def hkdf_sha256_one_block(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    out_len: int,
) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t1[:out_len]


def encrypt_active_substance(
    plaintext: bytes,
    device_secret: bytes,
    epoch: int,
    cipher: int,
) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(plaintext) > ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN:
        raise ValueError("plaintext maior que ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN")

    if cipher == ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM:
        key_len = 16
    elif cipher == ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM:
        key_len = 32
    else:
        raise ValueError("cipher nao suportado")

    nonce = os.urandom(ACTIVE_SUBSTANCE_NONCE_LEN)
    salt = HKDF_SALT_PREFIX + struct.pack("<I", epoch) + nonce
    info = HKDF_INFO_PREFIX + bytes([ACTIVE_SUBSTANCE_VERSION, cipher])
    key = hkdf_sha256_one_block(device_secret, salt, info, key_len)

    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    ciphertext = sealed[:-ACTIVE_SUBSTANCE_TAG_LEN]
    tag = sealed[-ACTIVE_SUBSTANCE_TAG_LEN:]

    padded_ciphertext = ciphertext + b"\x00" * (
        ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN - len(ciphertext)
    )
    return struct.pack(
        "<BBH12s16s256s",
        ACTIVE_SUBSTANCE_VERSION,
        cipher,
        len(ciphertext),
        nonce,
        tag,
        padded_ciphertext,
    )


def make_empty_active_substance(cipher: int) -> bytes:
    if cipher not in (
        ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM,
        ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM,
    ):
        raise ValueError("cipher nao suportado")

    # O firmware exige ciphertext_len > 0 para o envelope ser valido.
    dummy_ciphertext = b"\x00"
    padded_ciphertext = dummy_ciphertext + b"\x00" * (
        ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN - len(dummy_ciphertext)
    )
    return struct.pack(
        "<BBH12s16s256s",
        ACTIVE_SUBSTANCE_VERSION,
        cipher,
        len(dummy_ciphertext),
        os.urandom(ACTIVE_SUBSTANCE_NONCE_LEN),
        b"\x00" * ACTIVE_SUBSTANCE_TAG_LEN,
        padded_ciphertext,
    )


def active_substance_hash(active: bytes) -> bytes:
    version, cipher, ciphertext_len = struct.unpack_from("<BBH", active, 0)
    nonce = active[4:16]
    tag = active[16:32]
    ciphertext = active[32 : 32 + ciphertext_len]
    h = hashlib.sha256()
    h.update(struct.pack("<B", version))
    h.update(struct.pack("<B", cipher))
    h.update(struct.pack("<H", ciphertext_len))
    h.update(nonce)
    h.update(tag)
    h.update(ciphertext)
    return h.digest()


def capsule_signing_digest(capsule_without_signature: bytes) -> bytes:
    fields = struct.unpack("<BBBBII16s16s32s16sBB2s96s", capsule_without_signature)
    (
        version,
        flags,
        action_class,
        reserved0,
        issued_ms,
        expires_ms,
        network_id,
        nonce,
        active_hash,
        issuer_key_id,
        signature_alg,
        _signature_len,
        _reserved1,
        _signature,
    ) = fields

    h = hashlib.sha256()
    h.update(struct.pack("<B", version))
    h.update(struct.pack("<B", flags))
    h.update(struct.pack("<B", action_class))
    h.update(struct.pack("<B", reserved0))
    h.update(struct.pack("<I", issued_ms))
    h.update(struct.pack("<I", expires_ms))
    h.update(network_id)
    h.update(nonce)
    h.update(active_hash)
    h.update(issuer_key_id)
    h.update(struct.pack("<B", signature_alg))
    return h.digest()


def capsule_digest(capsule: bytes) -> bytes:
    signature_len = capsule[93]
    signature = capsule[96 : 96 + signature_len]
    h = hashlib.sha256()
    h.update(capsule_signing_canonical(capsule))
    h.update(struct.pack("<B", signature_len))
    h.update(signature)
    return h.digest()


def capsule_signing_canonical(capsule: bytes) -> bytes:
    fields = struct.unpack("<BBBBII16s16s32s16sBB2s96s", capsule)
    return (
        struct.pack("<BBBBII", *fields[:6])
        + fields[6]
        + fields[7]
        + fields[8]
        + fields[9]
        + struct.pack("<B", fields[10])
    )


def sign_digest_der(private_key, digest: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    if len(signature) > CAPSULE_PILL_SIGNATURE_MAX_LEN:
        raise ValueError("assinatura DER maior que o firmware aceita")
    return signature


def build_action_pill(
    private_key,
    device_secret: Optional[bytes],
    network_id: bytes,
    device_id: Optional[str],
    topic: Optional[str],
    amino: str,
    value: Optional[int],
    epoch: int,
    issued_ms: int,
    expires_ms: int,
    cipher: int = ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM,
    empty_active: bool = False,
) -> ActionPillBuild:
    public_pem = public_key_pem_from_private(private_key)
    issuer_key_id = issuer_key_id_from_public_pem(public_pem)
    if empty_active:
        active = make_empty_active_substance(cipher)
    else:
        if device_secret is None:
            raise ValueError("device_secret e obrigatorio sem empty_active")
        if device_id is None:
            raise ValueError("device_id e obrigatorio sem empty_active")
        if topic is None:
            raise ValueError("topic e obrigatorio sem empty_active")
        plaintext = make_command_plaintext(device_id, topic, amino, value)
        active = encrypt_active_substance(plaintext, device_secret, epoch, cipher)
    active_hash = active_substance_hash(active)

    capsule_nonce = os.urandom(CAPSULE_PILL_NONCE_LEN)
    unsigned_capsule = struct.pack(
        "<BBBBII16s16s32s16sBB2s96s",
        CAPSULE_PILL_VERSION,
        0,
        CAPSULE_PILL_ACTION_MQTT,
        0,
        issued_ms,
        expires_ms,
        network_id,
        capsule_nonce,
        active_hash,
        issuer_key_id,
        CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER,
        0,
        b"\x00\x00",
        b"\x00" * CAPSULE_PILL_SIGNATURE_MAX_LEN,
    )

    digest = capsule_signing_digest(unsigned_capsule)
    signature = sign_digest_der(private_key, digest)
    capsule = struct.pack(
        "<BBBBII16s16s32s16sBB2s96s",
        CAPSULE_PILL_VERSION,
        0,
        CAPSULE_PILL_ACTION_MQTT,
        0,
        issued_ms,
        expires_ms,
        network_id,
        capsule_nonce,
        active_hash,
        issuer_key_id,
        CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER,
        len(signature),
        b"\x00\x00",
        signature + b"\x00" * (CAPSULE_PILL_SIGNATURE_MAX_LEN - len(signature)),
    )

    action_pill = capsule + active
    if len(action_pill) != ACTION_PILL_LEN:
        raise AssertionError(f"ActionPill len inesperado: {len(action_pill)}")

    return ActionPillBuild(
        action_pill=action_pill,
        message_id=capsule_digest(capsule),
        issuer_key_id=issuer_key_id,
        network_id=network_id,
        active_hash=active_hash,
        signature=signature,
    )


def build_g2g_fragments(action_pill: bytes, message_id: bytes) -> list[bytes]:
    if len(action_pill) > 768:
        raise ValueError("action_pill maior que G2G_ACTION_PILL_MAX_LEN")
    if len(message_id) != CAPSULE_PILL_DIGEST_LEN:
        raise ValueError("message_id precisa ter 32 bytes")

    frag_count = math.ceil(len(action_pill) / G2G_WIRE_PAYLOAD_MAX)
    fragments: list[bytes] = []
    for frag_index in range(frag_count):
        offset = frag_index * G2G_WIRE_PAYLOAD_MAX
        payload = action_pill[offset : offset + G2G_WIRE_PAYLOAD_MAX]
        frame = bytearray(G2G_WIRE_HEADER_LEN + len(payload))
        frame[0] = G2G_WIRE_VERSION
        frame[1] = G2G_WIRE_TYPE_ACTION_PILL
        struct.pack_into("<H", frame, 4, len(action_pill))
        struct.pack_into("<H", frame, 6, offset)
        struct.pack_into("<H", frame, 8, frag_index)
        struct.pack_into("<H", frame, 10, frag_count)
        struct.pack_into("<H", frame, 12, len(payload))
        frame[14:46] = message_id
        frame[G2G_WIRE_HEADER_LEN:] = payload
        fragments.append(bytes(frame))
    return fragments


async def send_fragments_ble(
    fragments: list[bytes],
    address: Optional[str],
    name_contains: Optional[str],
    service_uuid: str = G2G_SERVICE_UUID,
    char_uuid: str = G2G_RX_UUID,
    timeout: float = 15.0,
    response: bool = True,
) -> None:
    from bleak import BleakClient, BleakScanner

    target = address
    if not target:
        service_lc = service_uuid.lower()
        name_lc = name_contains.lower() if name_contains else None

        def match(device, adv):
            service_match = service_lc in [u.lower() for u in adv.service_uuids]
            name = device.name or adv.local_name or ""
            name_match = name_lc is None or name_lc in name.lower()
            return service_match and name_match

        device = await BleakScanner.find_device_by_filter(match, timeout=timeout)
        if not device:
            raise RuntimeError("ESP G2G BLE nao encontrado no scan")
        target = device.address

    async with BleakClient(target, timeout=timeout) as client:
        for fragment in fragments:
            await client.write_gatt_char(char_uuid, fragment, response=response)
            await asyncio.sleep(0.05)
