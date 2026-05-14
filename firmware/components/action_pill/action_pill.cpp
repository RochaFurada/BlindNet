#include "action_pill.hpp"

#include <cstring>

/*
 * Estado inicial do Action Pill. A camada externa e descartavel; CP e AS
 * carregam o nucleo criptografico que nao deve ser reescrito no relay.
 */
void action_pill_init(action_pill_t *pill)
{
    if (!pill) return;

    std::memset(pill, 0, sizeof(*pill));
    pill->version = ACTION_PILL_VERSION;
    capsule_pill_init(&pill->capsule);
    active_substance_init(&pill->active);
}

/*
 * Monta um Action Pill com AS cifrado e CP ainda sem assinatura.
 * O app/autorizador deve assinar o CP depois que active_hash estiver fixado.
 */
esp_err_t action_pill_set_encrypted(
    action_pill_t *pill,
    capsule_pill_action_class_t action_class,
    uint32_t issued_ms,
    uint32_t expires_ms,
    const uint8_t network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t capsule_nonce[CAPSULE_PILL_NONCE_LEN],
    const uint8_t issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    active_substance_cipher_t cipher,
    const uint8_t active_nonce[ACTIVE_SUBSTANCE_NONCE_LEN],
    const uint8_t active_tag[ACTIVE_SUBSTANCE_TAG_LEN],
    const void *ciphertext,
    size_t ciphertext_len
)
{
    if (!pill) return ESP_ERR_INVALID_ARG;

    action_pill_init(pill);

    esp_err_t err = active_substance_set_ciphertext(
        &pill->active,
        cipher,
        active_nonce,
        active_tag,
        ciphertext,
        ciphertext_len
    );
    if (err != ESP_OK) return err;

    err = capsule_pill_configure(
        &pill->capsule,
        action_class,
        issued_ms,
        expires_ms,
        network_id,
        capsule_nonce,
        issuer_key_id
    );
    if (err != ESP_OK) return err;

    err = capsule_pill_bind_active(&pill->capsule, &pill->active);
    if (err != ESP_OK) return err;

    return capsule_pill_set_signature_alg(
        &pill->capsule,
        CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER
    );
}

/*
 * Reembala o Action Pill para relay. CP e AS sao copiados intactos.
 * Use depois do cache cp_digest e antes da validacao pesada, para preservar
 * a oclusao temporal do fluxo.
 */
esp_err_t action_pill_make_relay_copy(
    const action_pill_t *input,
    action_pill_t *output,
    const uint8_t previous_hop_tag[ACTION_PILL_PEER_TAG_LEN],
    uint32_t relay_id,
    uint32_t received_ms
)
{
    if (!input || !output) return ESP_ERR_INVALID_ARG;
    if (input->version != ACTION_PILL_VERSION) return ESP_ERR_INVALID_VERSION;

    *output = *input;
    output->version = ACTION_PILL_VERSION;
    output->hop_count = (uint8_t)(input->hop_count + 1);
    output->relay_attempt = (uint8_t)(input->relay_attempt + 1);
    output->relay_id = relay_id;
    output->received_ms = received_ms;
    std::memset(output->transit_mac, 0, sizeof(output->transit_mac));

    if (previous_hop_tag) {
        std::memcpy(output->previous_hop_tag, previous_hop_tag, ACTION_PILL_PEER_TAG_LEN);
    } else {
        std::memset(output->previous_hop_tag, 0, sizeof(output->previous_hop_tag));
    }

    return ESP_OK;
}

/*
 * Checagem barata para decidir relay. Nao tenta abrir o AS e nao verifica a
 * assinatura contra chave publica; isso fica para a fila de validacao tardia.
 */
esp_err_t action_pill_precheck_for_relay(
    const action_pill_t *pill,
    uint32_t now_ms
)
{
    if (!pill) return ESP_ERR_INVALID_ARG;
    if (pill->version != ACTION_PILL_VERSION) return ESP_ERR_INVALID_VERSION;

    esp_err_t err = active_substance_validate_envelope(&pill->active);
    if (err != ESP_OK) return err;

    return capsule_pill_validate_basic(&pill->capsule, now_ms);
}

/*
 * Validacao forte para a task local posterior ao relay.
 */
esp_err_t action_pill_validate_authorized(
    const action_pill_t *pill,
    uint32_t now_ms,
    const uint8_t *issuer_public_key,
    size_t issuer_public_key_len
)
{
    esp_err_t err = action_pill_precheck_for_relay(pill, now_ms);
    if (err != ESP_OK) return err;

    if (!action_pill_capsule_matches_active(pill)) {
        return ESP_ERR_INVALID_CRC;
    }

    if (!action_pill_verify_capsule_signature(
            pill,
            issuer_public_key,
            issuer_public_key_len
        )) {
        return ESP_ERR_INVALID_STATE;
    }

    return ESP_OK;
}

/*
 * Recalcula o hash do AS dentro do CP. Isso invalida assinatura existente
 * porque o CP imutavel mudou; use apenas antes de assinar no app/autorizador.
 */
esp_err_t action_pill_refresh_active_hash(action_pill_t *pill)
{
    if (!pill) return ESP_ERR_INVALID_ARG;
    return capsule_pill_bind_active(&pill->capsule, &pill->active);
}

bool action_pill_capsule_matches_active(const action_pill_t *pill)
{
    if (!pill) return false;
    return capsule_pill_matches_active(&pill->capsule, &pill->active);
}

bool action_pill_verify_capsule_signature(
    const action_pill_t *pill,
    const uint8_t *issuer_public_key,
    size_t issuer_public_key_len
)
{
    if (!pill) return false;
    return capsule_pill_verify_asymmetric(
        &pill->capsule,
        issuer_public_key,
        issuer_public_key_len
    );
}

/*
 * Digest do CP imutavel para cache anti-loop/anti-replay local.
 */
esp_err_t action_pill_compute_capsule_digest(
    const action_pill_t *pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
)
{
    if (!pill || !out_id) return ESP_ERR_INVALID_ARG;
    return capsule_pill_compute_digest(&pill->capsule, out_id);
}

/*
 * Alias legado: o "inner id" agora e o digest do CP imutavel.
 */
esp_err_t action_pill_compute_inner_id(
    const action_pill_t *pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
)
{
    return action_pill_compute_capsule_digest(pill, out_id);
}
