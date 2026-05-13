#include "active_substance.h"

#include <string.h>

#include "mbedtls/md.h"

static size_t bounded_strlen(const char *text, size_t max_len)
{
    if (!text) return 0;

    size_t len = 0;
    while (len < max_len && text[len] != '\0') {
        len++;
    }
    return len;
}

static void update_u8(mbedtls_md_context_t *ctx, uint8_t value)
{
    mbedtls_md_update(ctx, &value, sizeof(value));
}

static void update_u16_le(mbedtls_md_context_t *ctx, uint16_t value)
{
    uint8_t bytes[2] = {
        (uint8_t)(value & 0xFFu),
        (uint8_t)((value >> 8) & 0xFFu)
    };
    mbedtls_md_update(ctx, bytes, sizeof(bytes));
}

/*
 * Inicializa em estado vazio e conhecido.
 */
void active_substance_init(active_substance_t *substance)
{
    if (!substance) return;

    memset(substance, 0, sizeof(*substance));
    substance->version = ACTIVE_SUBSTANCE_VERSION;
    substance->transport = ACTIVE_SUBSTANCE_TRANSPORT_UNKNOWN;
}

/*
 * Monta o comando MQTT em memoria. Esta funcao nao publica nada no broker.
 */
esp_err_t active_substance_set_mqtt(
    active_substance_t *substance,
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
)
{
    if (!substance || !topic || !payload) return ESP_ERR_INVALID_ARG;
    if (payload_len == 0 || payload_len > ACTIVE_SUBSTANCE_PAYLOAD_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t topic_len = bounded_strlen(topic, ACTIVE_SUBSTANCE_TOPIC_MAX_LEN);
    if (topic_len == 0 || topic_len >= ACTIVE_SUBSTANCE_TOPIC_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    active_substance_init(substance);
    substance->transport = ACTIVE_SUBSTANCE_TRANSPORT_MQTT_PUBLISH;
    substance->mqtt.topic_len = (uint16_t)topic_len;
    substance->mqtt.payload_len = (uint16_t)payload_len;
    substance->mqtt.qos = qos;
    substance->mqtt.retain = retain;

    memcpy(substance->mqtt.topic, topic, topic_len);
    substance->mqtt.topic[topic_len] = '\0';
    memcpy(substance->mqtt.payload, payload, payload_len);

    return active_substance_validate(substance);
}

/*
 * Valida as restricoes do composto ativo antes de assinar ou executar.
 */
esp_err_t active_substance_validate(const active_substance_t *substance)
{
    if (!substance) return ESP_ERR_INVALID_ARG;
    if (substance->version != ACTIVE_SUBSTANCE_VERSION) return ESP_ERR_INVALID_VERSION;

    if (substance->transport != ACTIVE_SUBSTANCE_TRANSPORT_MQTT_PUBLISH) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    const active_substance_mqtt_t *mqtt = &substance->mqtt;

    if (mqtt->topic_len == 0 || mqtt->topic_len >= ACTIVE_SUBSTANCE_TOPIC_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    if (mqtt->topic[mqtt->topic_len] != '\0') {
        return ESP_ERR_INVALID_ARG;
    }

    if (mqtt->payload_len == 0 || mqtt->payload_len > ACTIVE_SUBSTANCE_PAYLOAD_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
     * MVP: QoS 0 e retain=false evitam sessão persistente, replay acidental
     * e estado retido no broker mínimo.
     */
    if (mqtt->qos != 0 || mqtt->retain) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    return ESP_OK;
}

/*
 * Calcula o SHA-256 canonico do composto ativo.
 * Nao fazemos hash da struct inteira porque structs podem conter padding.
 */
esp_err_t active_substance_hash(
    const active_substance_t *substance,
    uint8_t out_hash[ACTIVE_SUBSTANCE_HASH_LEN]
)
{
    if (!substance || !out_hash) return ESP_ERR_INVALID_ARG;

    esp_err_t err = active_substance_validate(substance);
    if (err != ESP_OK) return err;

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return ESP_FAIL;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0) {
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    update_u8(&ctx, substance->version);
    update_u8(&ctx, (uint8_t)substance->transport);
    update_u8(&ctx, substance->mqtt.qos);
    update_u8(&ctx, substance->mqtt.retain ? 1u : 0u);
    update_u16_le(&ctx, substance->mqtt.topic_len);
    update_u16_le(&ctx, substance->mqtt.payload_len);
    mbedtls_md_update(&ctx, (const uint8_t *)substance->mqtt.topic, substance->mqtt.topic_len);
    mbedtls_md_update(&ctx, substance->mqtt.payload, substance->mqtt.payload_len);

    int rc = mbedtls_md_finish(&ctx, out_hash);
    mbedtls_md_free(&ctx);

    return rc == 0 ? ESP_OK : ESP_FAIL;
}

const char *active_substance_transport_to_string(active_substance_transport_t transport)
{
    switch (transport) {
        case ACTIVE_SUBSTANCE_TRANSPORT_MQTT_PUBLISH: return "MQTT_PUBLISH";
        case ACTIVE_SUBSTANCE_TRANSPORT_UNKNOWN:
        default: return "UNKNOWN";
    }
}
