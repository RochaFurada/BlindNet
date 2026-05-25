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
#include "nimble/nimble_port_freertos.h"
#include "os/os_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "g2g_ble";

#define G2G_ATT_MTU 247
#define G2G_TX_TASK_STACK 4096
#define G2G_TX_TASK_PRIO 5
#define G2G_CONN_TIMEOUT_MS 7000

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
static uint8_t s_own_addr_type;

static g2g_peer_t s_peers[G2G_BLE_MAX_PEERS];
static QueueHandle_t s_tx_queue;
static SemaphoreHandle_t s_tx_done;
static TaskHandle_t s_tx_task;
static g2g_tx_ctx_t s_tx;

static int gap_event(struct ble_gap_event *event, void *arg);
static int rx_access_cb(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt,
    void *arg
);

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
            return;
        }
    }
}

static esp_err_t start_advertising(void)
{
    struct ble_hs_adv_fields fields;
    struct ble_gap_adv_params params;

    if (!s_synced || s_advertising) {
        return ESP_OK;
    }

    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = &G2G_SERVICE_UUID;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    if (ble_gap_adv_set_fields(&fields) != 0) {
        return ESP_FAIL;
    }

    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    if (ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                          &params, gap_event, NULL) != 0) {
        return ESP_FAIL;
    }

    s_advertising = true;
    return ESP_OK;
}

static esp_err_t start_scanning(void)
{
    struct ble_gap_disc_params params;

    if (!s_synced || s_scanning) {
        return ESP_OK;
    }

    memset(&params, 0, sizeof(params));
    params.passive = 0;
    params.filter_duplicates = 1;
    params.itvl = 0x0010;
    params.window = 0x0010;

    if (ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &params, gap_event, NULL) != 0) {
        return ESP_FAIL;
    }

    s_scanning = true;
    return ESP_OK;
}

static void stop_scanning(void)
{
    if (s_scanning) {
        ble_gap_disc_cancel();
        s_scanning = false;
    }
}

static void resume_presence(void)
{
    (void)start_advertising();
    (void)start_scanning();
}

static void tx_complete(bool ok)
{
    s_tx.ok = ok;
    if (s_tx_done) {
        xSemaphoreGive(s_tx_done);
    }
}

static int write_cb(
    uint16_t conn_handle,
    const struct ble_gatt_error *error,
    struct ble_gatt_attr *attr,
    void *arg
)
{
    (void)conn_handle;
    (void)attr;
    (void)arg;

    tx_complete(error && error->status == 0);
    return 0;
}

static void write_current_fragment(void)
{
    if (!s_tx.fragment || s_tx.conn_handle == BLE_HS_CONN_HANDLE_NONE || s_tx.chr_handle == 0) {
        tx_complete(false);
        return;
    }

    int rc = ble_gattc_write_flat(
        s_tx.conn_handle,
        s_tx.chr_handle,
        s_tx.fragment->bytes,
        s_tx.fragment->len,
        write_cb,
        NULL
    );

    if (rc != 0) {
        tx_complete(false);
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
        write_current_fragment();
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

static bool send_to_peer(const ble_addr_t *addr, const g2g_fragment_t *fragment)
{
    struct ble_gap_conn_params params;

    if (!addr || !fragment || !s_tx_done) {
        return false;
    }

    stop_scanning();

    memset(&s_tx, 0, sizeof(s_tx));
    s_tx.active = true;
    s_tx.conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_tx.fragment = fragment;

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
        s_tx.active = false;
        resume_presence();
        return false;
    }

    bool done = xSemaphoreTake(s_tx_done, pdMS_TO_TICKS(G2G_CONN_TIMEOUT_MS)) == pdTRUE;
    bool ok = done && s_tx.ok;

    if (s_tx.conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_tx.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }

    s_tx.active = false;
    resume_presence();
    return ok;
}

static void tx_task(void *arg)
{
    (void)arg;

    while (s_running) {
        g2g_fragment_t fragment;
        if (xQueueReceive(s_tx_queue, &fragment, pdMS_TO_TICKS(250)) != pdTRUE) {
            continue;
        }

        bool sent = false;
        for (size_t i = 0; i < G2G_BLE_MAX_PEERS; ++i) {
            if (!s_peers[i].in_use) {
                continue;
            }

            if (send_to_peer(&s_peers[i].addr, &fragment)) {
                sent = true;
                stats_inc(&s_stats.tx_fragments);
            } else {
                stats_inc(&s_stats.tx_errors);
            }
        }

        if (!sent) {
            (void)start_scanning();
        }
    }

    s_tx_task = NULL;
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
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint8_t fragment[G2G_BLE_FRAGMENT_MAX_LEN];
    if (os_mbuf_copydata(ctxt->om, 0, len, fragment) != 0) {
        stats_inc(&s_stats.rx_errors);
        return BLE_ATT_ERR_UNLIKELY;
    }

    stats_inc(&s_stats.rx_fragments);
    if (s_config.on_fragment) {
        s_config.on_fragment(fragment, len, s_config.ctx);
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
                    s_tx.conn_handle = event->connect.conn_handle;
                    if (ble_gattc_exchange_mtu(s_tx.conn_handle, mtu_cb, NULL) != 0) {
                        (void)mtu_cb(s_tx.conn_handle, NULL, 0, NULL);
                    }
                } else {
                    tx_complete(false);
                }
            }
            return 0;

        case BLE_GAP_EVENT_DISCONNECT:
            if (s_tx.active && s_tx.conn_handle == event->disconnect.conn.conn_handle) {
                s_tx.conn_handle = BLE_HS_CONN_HANDLE_NONE;
            }
            resume_presence();
            return 0;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            s_advertising = false;
            (void)start_advertising();
            return 0;

        case BLE_GAP_EVENT_DISC_COMPLETE:
            s_scanning = false;
            (void)start_scanning();
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
    resume_presence();
}

static void host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
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

    s_tx_queue = xQueueCreate(G2G_BLE_TX_QUEUE_LEN, sizeof(g2g_fragment_t));
    s_tx_done = xSemaphoreCreateBinary();
    if (!s_tx_queue || !s_tx_done) {
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
        return ESP_ERR_NO_MEM;
    }

    nimble_port_freertos_init(host_task);

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
    stop_scanning();
    if (s_advertising) {
        ble_gap_adv_stop();
        s_advertising = false;
    }
    if (s_tx.conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_tx.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }

    nimble_port_stop();
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
