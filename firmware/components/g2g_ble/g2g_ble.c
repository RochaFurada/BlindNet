#include "g2g_ble.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "os/os_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "g2g_ble";

#define G2G_ATT_MTU 247
#define G2G_TX_TASK_STACK 3072
#define G2G_TX_TASK_PRIO 5
#define G2G_TX_BATCH_MAX G2G_BLE_TX_QUEUE_LEN
#define G2G_RX_TASK_STACK 8192
#define G2G_RX_TASK_PRIO 6
#define G2G_RX_QUEUE_LEN 4
#define G2G_CONN_TIMEOUT_MS 3000
#define G2G_RESUME_DELAY_MS 350
#define G2G_RESUME_RETRY_MS 250
#define G2G_TX_IDLE_WAIT_MS 1500
#define G2G_TX_RETRY_MAX 5
#define G2G_TX_RETRY_DELAY_MS 450
#define G2G_TX_DISCOVERY_SETTLE_MS 120
#define G2G_TX_POST_RX_SETTLE_MS 250

#ifndef BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN
#define BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN 0x0d
#endif

#ifndef BLE_ATT_ERR_UNLIKELY
#define BLE_ATT_ERR_UNLIKELY 0x0e
#endif

#ifndef BLE_HS_ADV_F_DISC_GEN
#ifdef BLE_GAP_ADV_F_DISC_GEN
#define BLE_HS_ADV_F_DISC_GEN BLE_GAP_ADV_F_DISC_GEN
#else
#define BLE_HS_ADV_F_DISC_GEN 0x02
#endif
#endif

#ifndef BLE_HS_ADV_F_BREDR_UNSUP
#ifdef BLE_GAP_ADV_F_BREDR_UNSUP
#define BLE_HS_ADV_F_BREDR_UNSUP BLE_GAP_ADV_F_BREDR_UNSUP
#else
#define BLE_HS_ADV_F_BREDR_UNSUP 0x04
#endif
#endif

int ble_att_set_preferred_mtu(uint16_t mtu);

static const ble_uuid128_t G2G_SERVICE_UUID =
{
    .u = {
        .type = BLE_UUID_TYPE_128,
    },
    .value = {
        0x42, 0x4e, 0x47, 0x32, 0x47, 0x2d, 0x41, 0x50,
        0x2d, 0x54, 0x52, 0x41, 0x4e, 0x53, 0x50, 0x01,
    },
};

static const ble_uuid128_t G2G_RX_UUID =
{
    .u = {
        .type = BLE_UUID_TYPE_128,
    },
    .value = {
        0x42, 0x4e, 0x47, 0x32, 0x47, 0x2d, 0x52, 0x58,
        0x2d, 0x46, 0x52, 0x41, 0x47, 0x4d, 0x45, 0x01,
    },
};

typedef struct {
    uint16_t len;
    bool has_exclude_addr;
    ble_addr_t exclude_addr;
    uint8_t bytes[G2G_BLE_FRAGMENT_MAX_LEN];
} g2g_fragment_t;

typedef struct {
    bool in_use;
    ble_addr_t addr;
} g2g_peer_t;

typedef struct {
    bool active;
    bool ok;
    uint16_t conn_handle;
    uint16_t chr_handle;
    const g2g_fragment_t *fragment;
} g2g_tx_ctx_t;

static g2g_ble_config_t s_config;
static g2g_ble_stats_t s_stats;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static bool s_running;
static bool s_synced;
static bool s_advertising;
static bool s_scanning;
static volatile bool s_rx_active;
static volatile bool s_resume_pending;
static TickType_t s_resume_at;
static uint16_t s_rx_conn_handle;
static bool s_rx_has_peer_addr;
static ble_addr_t s_rx_peer_addr;
static bool s_callback_has_exclude_addr;
static ble_addr_t s_callback_exclude_addr;
static uint8_t s_own_addr_type;

static g2g_peer_t s_peers[G2G_BLE_MAX_PEERS];
static QueueHandle_t s_tx_queue;
static QueueHandle_t s_rx_queue;
static SemaphoreHandle_t s_tx_done;
static TaskHandle_t s_tx_task;
static TaskHandle_t s_rx_task;
static TaskHandle_t s_host_task;
static g2g_tx_ctx_t s_tx;

static int gap_event(struct ble_gap_event *event, void *arg);
static int rx_access_cb(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt,
    void *arg
);

static bool gap_busy(int rc)
{
    return rc == BLE_HS_EALREADY || rc == BLE_HS_EBUSY;
}

static bool gap_already(int rc)
{
    return rc == BLE_HS_EALREADY;
}

static const struct ble_gatt_chr_def G2G_CHRS[] = {
    {
        .uuid = &G2G_RX_UUID.u,
        .access_cb = rx_access_cb,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
    },
    {0}
};

static const struct ble_gatt_svc_def G2G_SVCS[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &G2G_SERVICE_UUID.u,
        .characteristics = G2G_CHRS,
    },
    {0}
};

static void stats_inc(uint64_t *field)
{
    portENTER_CRITICAL(&s_lock);
    (*field)++;
    portEXIT_CRITICAL(&s_lock);
}

static bool addr_equal(const ble_addr_t *a, const ble_addr_t *b)
{
    return a && b && a->type == b->type && memcmp(a->val, b->val, sizeof(a->val)) == 0;
}

static bool batch_excludes_peer(
    const g2g_fragment_t *fragments,
    size_t fragment_count,
    const ble_addr_t *addr
)
{
    if (!fragments || fragment_count == 0 || !addr) {
        return false;
    }

    for (size_t i = 0; i < fragment_count; ++i) {
        if (!fragments[i].has_exclude_addr ||
            !addr_equal(&fragments[i].exclude_addr, addr)) {
            return false;
        }
    }

    return true;
}

static bool uuid128_equal(const ble_uuid128_t *a, const ble_uuid128_t *b)
{
    return a && b && memcmp(a->value, b->value, sizeof(a->value)) == 0;
}

static bool adv_has_service(const uint8_t *data, uint8_t data_len)
{
    struct ble_hs_adv_fields fields;

    if (!data || data_len == 0) {
        return false;
    }

    memset(&fields, 0, sizeof(fields));
    if (ble_hs_adv_parse_fields(&fields, data, data_len) != 0) {
        return false;
    }

    for (int i = 0; i < fields.num_uuids128; ++i) {
        if (uuid128_equal(&fields.uuids128[i], &G2G_SERVICE_UUID)) {
            return true;
        }
    }

    return false;
}

static void remember_peer(const ble_addr_t *addr)
{
    if (!addr) {
        return;
    }

    for (size_t i = 0; i < G2G_BLE_MAX_PEERS; ++i) {
        if (s_peers[i].in_use && addr_equal(&s_peers[i].addr, addr)) {
            return;
        }
    }

    for (size_t i = 0; i < G2G_BLE_MAX_PEERS; ++i) {
        if (!s_peers[i].in_use) {
            s_peers[i].in_use = true;
            s_peers[i].addr = *addr;
            stats_inc(&s_stats.discovered_peers);
            ESP_LOGI(TAG,
                     "G2G peer descoberto type=%u mac=%02x:%02x:%02x:%02x:%02x:%02x",
                     (unsigned)addr->type,
                     addr->val[5],
                     addr->val[4],
                     addr->val[3],
                     addr->val[2],
                     addr->val[1],
                     addr->val[0]);
            return;
        }
    }
}

static esp_err_t start_advertising(void)
{
    struct ble_hs_adv_fields fields;
    struct ble_gap_adv_params params;

    if (!s_synced || s_advertising) {
        ESP_LOGI(TAG, "Advertising ignorado synced=%d advertising=%d", s_synced ? 1 : 0, s_advertising ? 1 : 0);
        return ESP_OK;
    }

    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = &G2G_SERVICE_UUID;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        if (gap_busy(rc)) {
            s_advertising = true;
            ESP_LOGI(TAG, "Advertising ja ativo/ocupado rc=%d", rc);
            return ESP_OK;
        }
        ESP_LOGE(TAG, "ble_gap_adv_set_fields rc=%d", rc);
        return ESP_FAIL;
    }

    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, gap_event, NULL);
    if (rc != 0) {
        if (gap_already(rc)) {
            s_advertising = true;
            ESP_LOGI(TAG, "Advertising ja ativo rc=%d", rc);
            return ESP_OK;
        }
        if (rc == BLE_HS_EBUSY) {
            ESP_LOGI(TAG, "Advertising ocupado; reagendando rc=%d", rc);
            return ESP_ERR_INVALID_STATE;
        }
        ESP_LOGE(TAG, "ble_gap_adv_start rc=%d", rc);
        return ESP_FAIL;
    }

    s_advertising = true;
    ESP_LOGI(TAG, "G2G BLE advertising ativo");
    return ESP_OK;
}

static esp_err_t start_scanning(void)
{
    struct ble_gap_disc_params params;

    if (!s_synced || s_scanning) {
        ESP_LOGI(TAG, "Scan ignorado synced=%d scanning=%d", s_synced ? 1 : 0, s_scanning ? 1 : 0);
        return ESP_OK;
    }

    memset(&params, 0, sizeof(params));
    params.passive = 0;
    params.filter_duplicates = 1;
    params.itvl = 0x0010;
    params.window = 0x0010;

    int rc = ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc != 0) {
        if (gap_already(rc)) {
            s_scanning = true;
            ESP_LOGI(TAG, "Scan ja ativo rc=%d", rc);
            return ESP_OK;
        }
        if (rc == BLE_HS_EBUSY) {
            ESP_LOGI(TAG, "Scan ocupado; reagendando rc=%d", rc);
            return ESP_ERR_INVALID_STATE;
        }
        ESP_LOGE(TAG, "ble_gap_disc rc=%d", rc);
        return ESP_FAIL;
    }

    s_scanning = true;
    ESP_LOGI(TAG, "G2G BLE scan ativo");
    return ESP_OK;
}

static void stop_scanning(void)
{
    if (s_scanning) {
        int rc = ble_gap_disc_cancel();
        if (rc != 0 && !gap_busy(rc)) {
            ESP_LOGW(TAG, "ble_gap_disc_cancel rc=%d", rc);
        }
        s_scanning = false;
    }
}

static void stop_advertising(void)
{
    if (s_advertising) {
        int rc = ble_gap_adv_stop();
        if (rc != 0 && !gap_busy(rc)) {
            ESP_LOGW(TAG, "ble_gap_adv_stop rc=%d", rc);
        }
        s_advertising = false;
    }
}

static void schedule_presence_resume(uint32_t delay_ms)
{
    if (!s_running) {
        return;
    }

    s_resume_pending = true;
    s_resume_at = xTaskGetTickCount() + pdMS_TO_TICKS(delay_ms);
}

static esp_err_t resume_presence_now(void)
{
    if (!s_running || !s_synced || s_tx.active || s_rx_active) {
        schedule_presence_resume(G2G_RESUME_RETRY_MS);
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t adv_err = start_advertising();
    esp_err_t scan_err = start_scanning();
    if (adv_err != ESP_OK || scan_err != ESP_OK) {
        ESP_LOGW(TAG, "resume_presence reagendado adv=%s scan=%s",
                 esp_err_to_name(adv_err),
                 esp_err_to_name(scan_err));
        schedule_presence_resume(G2G_RESUME_RETRY_MS);
        return ESP_ERR_INVALID_STATE;
    }

    return ESP_OK;
}

static void maybe_resume_presence(void)
{
    if (!s_resume_pending) {
        return;
    }

    TickType_t now = xTaskGetTickCount();
    if ((int32_t)(now - s_resume_at) < 0) {
        return;
    }

    s_resume_pending = false;
    (void)resume_presence_now();
}

static void tx_complete(bool ok)
{
    s_tx.ok = ok;
    if (s_tx_done) {
        xSemaphoreGive(s_tx_done);
    }
}

static int chr_disc_cb(
    uint16_t conn_handle,
    const struct ble_gatt_error *error,
    const struct ble_gatt_chr *chr,
    void *arg
)
{
    (void)conn_handle;
    (void)arg;

    if (!error) {
        tx_complete(false);
        return 0;
    }

    if (error->status == 0 && chr) {
        s_tx.chr_handle = chr->val_handle;
        tx_complete(true);
        return 0;
    }

    if (error->status == BLE_HS_EDONE && s_tx.chr_handle == 0) {
        tx_complete(false);
    }

    return 0;
}

static int svc_disc_cb(
    uint16_t conn_handle,
    const struct ble_gatt_error *error,
    const struct ble_gatt_svc *service,
    void *arg
)
{
    (void)arg;

    if (!error) {
        tx_complete(false);
        return 0;
    }

    if (error->status == 0 && service) {
        int rc = ble_gattc_disc_chrs_by_uuid(
            conn_handle,
            service->start_handle,
            service->end_handle,
            &G2G_RX_UUID.u,
            chr_disc_cb,
            NULL
        );
        if (rc != 0) {
            tx_complete(false);
        }
        return 0;
    }

    if (error->status == BLE_HS_EDONE) {
        tx_complete(false);
    }

    return 0;
}

static int mtu_cb(
    uint16_t conn_handle,
    const struct ble_gatt_error *error,
    uint16_t mtu,
    void *arg
)
{
    (void)error;
    (void)mtu;
    (void)arg;

    int rc = ble_gattc_disc_svc_by_uuid(
        conn_handle,
        &G2G_SERVICE_UUID.u,
        svc_disc_cb,
        NULL
    );
    if (rc != 0) {
        tx_complete(false);
    }

    return 0;
}

static bool send_batch_to_peer(
    const ble_addr_t *addr,
    const g2g_fragment_t *fragments,
    size_t fragment_count
)
{
    if (!addr || !fragments || fragment_count == 0 || !s_tx_done) {
        return false;
    }

    for (uint32_t attempt = 1; attempt <= G2G_TX_RETRY_MAX && s_running; ++attempt) {
        struct ble_gap_conn_params params;
        bool waited_for_rx = false;
        TickType_t wait_start = xTaskGetTickCount();
        while (s_running && s_rx_active) {
            waited_for_rx = true;
            if (xTaskGetTickCount() - wait_start > pdMS_TO_TICKS(G2G_TX_IDLE_WAIT_MS)) {
                ESP_LOGW(TAG,
                         "TX G2G aguardando RX ativo tentativa=%lu/%u",
                         (unsigned long)attempt,
                         (unsigned)G2G_TX_RETRY_MAX);
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        if (s_rx_active) {
            vTaskDelay(pdMS_TO_TICKS(G2G_TX_RETRY_DELAY_MS));
            continue;
        }
        if (waited_for_rx) {
            vTaskDelay(pdMS_TO_TICKS(G2G_TX_POST_RX_SETTLE_MS));
        }

        stop_advertising();
        stop_scanning();

        memset(&s_tx, 0, sizeof(s_tx));
        s_tx.active = true;
        s_tx.conn_handle = BLE_HS_CONN_HANDLE_NONE;
        s_tx.fragment = NULL;

        while (xSemaphoreTake(s_tx_done, 0) == pdTRUE) {
        }

        memset(&params, 0, sizeof(params));
        params.scan_itvl = 0x0010;
        params.scan_window = 0x0010;
        params.itvl_min = 0x0018;
        params.itvl_max = 0x0028;
        params.latency = 0;
        params.supervision_timeout = 0x0100;

        int rc = ble_gap_connect(s_own_addr_type, addr, G2G_CONN_TIMEOUT_MS,
                                 &params, gap_event, NULL);
        if (rc != 0) {
            ESP_LOGW(TAG,
                     "falha ao conectar G2G tentativa=%lu/%u rc=%d",
                     (unsigned long)attempt,
                     (unsigned)G2G_TX_RETRY_MAX,
                     rc);
            s_tx.active = false;
            schedule_presence_resume(G2G_RESUME_RETRY_MS);
            vTaskDelay(pdMS_TO_TICKS(G2G_TX_RETRY_DELAY_MS));
            continue;
        }

        bool done = xSemaphoreTake(s_tx_done, pdMS_TO_TICKS(G2G_CONN_TIMEOUT_MS)) == pdTRUE;
        bool ok = done && s_tx.ok && s_tx.conn_handle != BLE_HS_CONN_HANDLE_NONE && s_tx.chr_handle != 0;
        if (!done) {
            int cancel_rc = ble_gap_conn_cancel();
            if (cancel_rc != 0 && !gap_busy(cancel_rc)) {
                ESP_LOGW(TAG, "ble_gap_conn_cancel rc=%d", cancel_rc);
            }
        }
        if (!ok) {
            ESP_LOGW(TAG,
                     "descoberta G2G falhou tentativa=%lu/%u done=%d ok=%d handle=%u chr=%u",
                     (unsigned long)attempt,
                     (unsigned)G2G_TX_RETRY_MAX,
                     done ? 1 : 0,
                     s_tx.ok ? 1 : 0,
                     (unsigned)s_tx.conn_handle,
                     (unsigned)s_tx.chr_handle);
        } else {
            vTaskDelay(pdMS_TO_TICKS(G2G_TX_DISCOVERY_SETTLE_MS));
        }

        for (size_t i = 0; ok && i < fragment_count; ++i) {
            rc = ble_gattc_write_no_rsp_flat(
                s_tx.conn_handle,
                s_tx.chr_handle,
                fragments[i].bytes,
                fragments[i].len
            );
            ok = rc == 0;
            if (!ok) {
                ESP_LOGW(TAG,
                         "falha ao escrever fragmento G2G %u/%u len=%u rc=%d tentativa=%lu/%u",
                         (unsigned)i,
                         (unsigned)fragment_count,
                         (unsigned)fragments[i].len,
                         rc,
                         (unsigned long)attempt,
                         (unsigned)G2G_TX_RETRY_MAX);
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (s_tx.conn_handle != BLE_HS_CONN_HANDLE_NONE) {
            rc = ble_gap_terminate(s_tx.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            if (rc != 0) {
                ESP_LOGW(TAG, "ble_gap_terminate rc=%d", rc);
            }
        }

        s_tx.active = false;
        schedule_presence_resume(G2G_RESUME_DELAY_MS);
        if (ok) {
            return true;
        }

        vTaskDelay(pdMS_TO_TICKS(G2G_TX_RETRY_DELAY_MS));
    }

    return false;
}

static void tx_task(void *arg)
{
    (void)arg;

    while (s_running) {
        maybe_resume_presence();

        g2g_fragment_t batch[G2G_TX_BATCH_MAX];
        size_t batch_count = 0;

        if (xQueueReceive(s_tx_queue, &batch[0], pdMS_TO_TICKS(250)) != pdTRUE) {
            continue;
        }
        batch_count = 1;

        vTaskDelay(pdMS_TO_TICKS(30));
        while (batch_count < G2G_TX_BATCH_MAX &&
               xQueueReceive(s_tx_queue, &batch[batch_count], 0) == pdTRUE) {
            batch_count++;
        }

        bool sent = false;
        bool has_peer = false;
        bool attempted = false;
        bool skipped_origin = false;
        for (size_t i = 0; i < G2G_BLE_MAX_PEERS; ++i) {
            if (!s_peers[i].in_use) {
                continue;
            }

            has_peer = true;
            if (batch_excludes_peer(batch, batch_count, &s_peers[i].addr)) {
                skipped_origin = true;
                continue;
            }

            attempted = true;
            if (send_batch_to_peer(&s_peers[i].addr, batch, batch_count)) {
                sent = true;
                for (size_t j = 0; j < batch_count; ++j) {
                    stats_inc(&s_stats.tx_fragments);
                }
            } else {
                for (size_t j = 0; j < batch_count; ++j) {
                    stats_inc(&s_stats.tx_errors);
                }
            }
        }

        if (!sent) {
            if (!has_peer) {
                ESP_LOGW(TAG,
                         "sem peer G2G para enviar batch fragments=%u",
                         (unsigned)batch_count);
            } else if (!attempted && skipped_origin) {
                ESP_LOGI(TAG,
                         "relay G2G ignorado: somente peer origem fragments=%u",
                         (unsigned)batch_count);
            }
            if (attempted || !skipped_origin) {
                schedule_presence_resume(G2G_RESUME_RETRY_MS);
            }
        }
    }

    s_tx_task = NULL;
    vTaskDelete(NULL);
}

static void rx_task(void *arg)
{
    (void)arg;

    while (s_running) {
        g2g_fragment_t fragment;
        if (xQueueReceive(s_rx_queue, &fragment, pdMS_TO_TICKS(250)) != pdTRUE) {
            continue;
        }

        if (s_config.on_fragment) {
            s_callback_has_exclude_addr = fragment.has_exclude_addr;
            if (fragment.has_exclude_addr) {
                s_callback_exclude_addr = fragment.exclude_addr;
            }
            s_config.on_fragment(fragment.bytes, fragment.len, s_config.ctx);
            s_callback_has_exclude_addr = false;
        }
    }

    s_rx_task = NULL;
    vTaskDelete(NULL);
}

static int rx_access_cb(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt,
    void *arg
)
{
    (void)conn_handle;
    (void)attr_handle;
    (void)arg;

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len == 0 || len > G2G_BLE_FRAGMENT_MAX_LEN) {
        stats_inc(&s_stats.rx_errors);
        ESP_LOGW(TAG, "RX write invalido len=%u", (unsigned)len);
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    if (!s_rx_queue) {
        stats_inc(&s_stats.rx_errors);
        return BLE_ATT_ERR_UNLIKELY;
    }

    g2g_fragment_t fragment;
    memset(&fragment, 0, sizeof(fragment));
    fragment.len = len;
    fragment.has_exclude_addr = s_rx_has_peer_addr;
    if (s_rx_has_peer_addr) {
        fragment.exclude_addr = s_rx_peer_addr;
    }
    if (os_mbuf_copydata(ctxt->om, 0, len, fragment.bytes) != 0) {
        stats_inc(&s_stats.rx_errors);
        ESP_LOGW(TAG, "RX copydata falhou len=%u", (unsigned)len);
        return BLE_ATT_ERR_UNLIKELY;
    }

    stats_inc(&s_stats.rx_fragments);
    ESP_LOGI(TAG, "RX fragment len=%u", (unsigned)len);
    if (xQueueSend(s_rx_queue, &fragment, 0) != pdTRUE) {
        stats_inc(&s_stats.rx_errors);
        ESP_LOGW(TAG, "fila RX G2G cheia, descartando fragmento len=%u", (unsigned)len);
        return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {
        case BLE_GAP_EVENT_DISC:
            if (adv_has_service(event->disc.data, event->disc.length_data)) {
                remember_peer(&event->disc.addr);
            }
            return 0;

        case BLE_GAP_EVENT_CONNECT:
            if (s_tx.active) {
                if (event->connect.status == 0) {
                    s_advertising = false;
                    ESP_LOGI(TAG, "G2G BLE conectado outbound handle=%u", event->connect.conn_handle);
                    s_tx.conn_handle = event->connect.conn_handle;
                    if (ble_gattc_exchange_mtu(s_tx.conn_handle, mtu_cb, NULL) != 0) {
                        (void)mtu_cb(s_tx.conn_handle, NULL, 0, NULL);
                    }
                } else {
                    ESP_LOGW(TAG, "G2G BLE connect outbound falhou status=%d", event->connect.status);
                    tx_complete(false);
                    schedule_presence_resume(G2G_RESUME_RETRY_MS);
                }
            } else if (event->connect.status == 0) {
                struct ble_gap_conn_desc desc;
                s_advertising = false;
                s_rx_active = true;
                s_rx_conn_handle = event->connect.conn_handle;
                s_rx_has_peer_addr = false;
                if (ble_gap_conn_find(event->connect.conn_handle, &desc) == 0) {
                    s_rx_peer_addr = desc.peer_ota_addr;
                    s_rx_has_peer_addr = true;
                }
                stop_scanning();
                ESP_LOGI(TAG, "G2G BLE conectado inbound handle=%u", event->connect.conn_handle);
            } else {
                ESP_LOGW(TAG, "G2G BLE connect inbound falhou status=%d", event->connect.status);
                schedule_presence_resume(G2G_RESUME_RETRY_MS);
            }
            return 0;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGW(TAG, "G2G BLE desconectado handle=%u reason=%d",
                     event->disconnect.conn.conn_handle,
                     event->disconnect.reason);
            if (s_tx.active && s_tx.conn_handle == event->disconnect.conn.conn_handle) {
                s_tx.conn_handle = BLE_HS_CONN_HANDLE_NONE;
                tx_complete(false);
            }
            if (s_rx_active && s_rx_conn_handle == event->disconnect.conn.conn_handle) {
                s_rx_active = false;
                s_rx_conn_handle = BLE_HS_CONN_HANDLE_NONE;
                s_rx_has_peer_addr = false;
            }
            s_advertising = false;
            schedule_presence_resume(G2G_RESUME_DELAY_MS);
            return 0;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            s_advertising = false;
            schedule_presence_resume(G2G_RESUME_DELAY_MS);
            return 0;

        case BLE_GAP_EVENT_DISC_COMPLETE:
            s_scanning = false;
            schedule_presence_resume(G2G_RESUME_DELAY_MS);
            return 0;

        default:
            return 0;
    }
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE reset reason=%d", reason);
    s_synced = false;
}

static void on_sync(void)
{
    ESP_LOGI(TAG, "NimBLE sync");

    int rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_util_ensure_addr rc=%d", rc);
        return;
    }

    rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto rc=%d", rc);
        return;
    }

    s_synced = true;
    ESP_LOGI(TAG, "NimBLE own_addr_type=%u", (unsigned)s_own_addr_type);
    schedule_presence_resume(0);
}

static void host_task(void *param)
{
    (void)param;
    ESP_LOGI(TAG, "NimBLE host task rodando stack=%u", (unsigned)NIMBLE_HS_STACK_SIZE);
    nimble_port_run();
    s_host_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t g2g_ble_start(const g2g_ble_config_t *config)
{
    if (s_running) {
        return ESP_OK;
    }

    memset(&s_config, 0, sizeof(s_config));
    if (config) {
        s_config = *config;
    }
    if (s_config.zone_id == 0) {
        s_config.zone_id = 1;
    }

    memset(&s_stats, 0, sizeof(s_stats));
    memset(s_peers, 0, sizeof(s_peers));
    memset(&s_tx, 0, sizeof(s_tx));
    s_rx_active = false;
    s_rx_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_rx_has_peer_addr = false;
    s_callback_has_exclude_addr = false;
    s_resume_pending = false;
    s_resume_at = 0;

    s_tx_queue = xQueueCreate(G2G_BLE_TX_QUEUE_LEN, sizeof(g2g_fragment_t));
    s_rx_queue = xQueueCreate(G2G_RX_QUEUE_LEN, sizeof(g2g_fragment_t));
    s_tx_done = xSemaphoreCreateBinary();
    if (!s_tx_queue || !s_rx_queue || !s_tx_done) {
        if (s_tx_queue) {
            vQueueDelete(s_tx_queue);
            s_tx_queue = NULL;
        }
        if (s_rx_queue) {
            vQueueDelete(s_rx_queue);
            s_rx_queue = NULL;
        }
        if (s_tx_done) {
            vSemaphoreDelete(s_tx_done);
            s_tx_done = NULL;
        }
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        return err;
    }

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(G2G_SVCS);
    if (rc == 0) {
        rc = ble_gatts_add_svcs(G2G_SVCS);
    }
    if (rc != 0) {
        nimble_port_deinit();
        return ESP_FAIL;
    }

    (void)ble_att_set_preferred_mtu(G2G_ATT_MTU);

    s_running = true;

    if (xTaskCreate(tx_task, "g2g_ble_tx", G2G_TX_TASK_STACK, NULL,
                    G2G_TX_TASK_PRIO, &s_tx_task) != pdPASS) {
        s_running = false;
        nimble_port_deinit();
        vQueueDelete(s_tx_queue);
        s_tx_queue = NULL;
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
        vSemaphoreDelete(s_tx_done);
        s_tx_done = NULL;
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(rx_task, "g2g_ble_rx", G2G_RX_TASK_STACK, NULL,
                    G2G_RX_TASK_PRIO, &s_rx_task) != pdPASS) {
        ESP_LOGE(TAG, "falha ao criar g2g_ble_rx stack=%u", (unsigned)G2G_RX_TASK_STACK);
        s_running = false;
        nimble_port_deinit();
        vTaskDelay(pdMS_TO_TICKS(300));
        vQueueDelete(s_tx_queue);
        s_tx_queue = NULL;
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
        vSemaphoreDelete(s_tx_done);
        s_tx_done = NULL;
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreatePinnedToCore(host_task, "nimble_host", NIMBLE_HS_STACK_SIZE,
                                NULL, (configMAX_PRIORITIES - 4), &s_host_task,
                                NIMBLE_CORE) != pdPASS) {
        ESP_LOGE(TAG, "falha ao criar nimble_host stack=%u", (unsigned)NIMBLE_HS_STACK_SIZE);
        s_running = false;
        nimble_port_deinit();
        vTaskDelay(pdMS_TO_TICKS(300));
        vQueueDelete(s_tx_queue);
        s_tx_queue = NULL;
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
        vSemaphoreDelete(s_tx_done);
        s_tx_done = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "G2G BLE iniciado guardian=%lu zone=%lu",
             (unsigned long)s_config.guardian_id,
             (unsigned long)s_config.zone_id);
    return ESP_OK;
}

esp_err_t g2g_ble_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }

    s_running = false;
    s_resume_pending = false;
    s_rx_active = false;
    s_rx_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_rx_has_peer_addr = false;
    s_callback_has_exclude_addr = false;
    stop_scanning();
    stop_advertising();
    if (s_tx.conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_tx.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }

    nimble_port_stop();
    vTaskDelay(pdMS_TO_TICKS(300));

    if (s_tx_queue) {
        vQueueDelete(s_tx_queue);
        s_tx_queue = NULL;
    }
    if (s_rx_queue) {
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
    }
    if (s_tx_done) {
        vSemaphoreDelete(s_tx_done);
        s_tx_done = NULL;
    }
    return ESP_OK;
}

bool g2g_ble_is_running(void)
{
    return s_running;
}

esp_err_t g2g_ble_send_fragment(const uint8_t *bytes, size_t len)
{
    if (!s_running || !s_tx_queue) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!bytes || len == 0 || len > G2G_BLE_FRAGMENT_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    g2g_fragment_t fragment;
    memset(&fragment, 0, sizeof(fragment));
    fragment.len = (uint16_t)len;
    fragment.has_exclude_addr = s_callback_has_exclude_addr;
    if (s_callback_has_exclude_addr) {
        fragment.exclude_addr = s_callback_exclude_addr;
    }
    memcpy(fragment.bytes, bytes, len);

    if (xQueueSend(s_tx_queue, &fragment, 0) != pdTRUE) {
        return ESP_ERR_NO_MEM;
    }

    stats_inc(&s_stats.queued_fragments);
    return ESP_OK;
}

g2g_ble_stats_t g2g_ble_get_stats(void)
{
    g2g_ble_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}
