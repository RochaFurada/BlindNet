use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use crate::platform;
use crate::platform::admin_server::AdminServerConfigRaw;
use crate::platform::capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN;
use crate::platform::config::ZoneguardConfigRaw;
use crate::platform::dns_filter::{DnsFilterConfigRaw, DnsFilterRuleRaw};
use crate::platform::event_bus::ZgEventRaw;
use crate::platform::flow_table::FlowTableConfigRaw;
use crate::platform::mqtt_broker::{
    MqttBrokerConfigRaw, MqttBrokerConnectRaw, MqttBrokerMessageRaw,
};
use crate::platform::policy_engine::{PolicyEngineConfigRaw, PolicyRuleRaw};
use crate::platform::rate_limiter::{RateLimitParamsRaw, RateLimitRuleRaw, RateLimiterConfigRaw};
use crate::platform::wifi_manager::WifiManagerConfigRaw;
use crate::platform::{
    admin_server, config, device_registry, dns_filter, event_bus, flow_table, mqtt_broker,
    policy_engine, rate_limiter, setup_ap, setup_button, wifi_manager, zone_firewall, zone_gateway,
    Result,
};

use crate::ffi::config_store::CONFIG_STORE_PUBLIC_KEY_MAX_LEN;
use crate::logic::action_pill::ActionPill;
use crate::logic::broker::BrokerPipeline;
use crate::logic::g2g;
use crate::logic::membrane::Membrane;
use crate::logic::stomach::{self, DigestedActiveSubstance, Stomach};

const SETUP_SSID: &[u8] = b"ZoneGuard_Setup\0";
const SETUP_PASSWORD: &[u8] = b"setup1234\0";
const MAINTENANCE_SSID: &[u8] = b"ZoneGuard_Admin\0";
const MAINTENANCE_PASSWORD: &[u8] = b"\0";
const ADMIN_SETUP_BUTTON_GPIO: i32 = setup_button::SETUP_BUTTON_DEFAULT_GPIO;
const ADMIN_SETUP_HOLD_MS: u32 = setup_button::SETUP_BUTTON_DEFAULT_HOLD_MS;
const ADMIN_SETUP_POLL_MS: u32 = setup_button::SETUP_BUTTON_DEFAULT_POLL_MS;
const ADMIN_SETUP_UNLOCK_WINDOW_MS: u32 = 180_000;
const ADMIN_STATUS_LED_GPIO: c_int = 2;
const ADMIN_STATUS_LED_BLINKS: u32 = 3;
const ADMIN_STATUS_LED_ON_US: i64 = 120_000;
const ADMIN_STATUS_LED_OFF_US: i64 = 120_000;
const ENABLE_OPTIONAL_GATEWAY_SERVICES: bool = false;
const ENABLE_OPTIONAL_SECURITY_SERVICES: bool = false;
const ESP_LOG_WARN: c_int = 2;
const ESP_LOG_INFO: c_int = 3;
const GPIO_MODE_OUTPUT: c_int = 2;
const TAG_PIPELINE: &[u8] = b"cortex_pipeline\0";
const TAG_ADMIN: &[u8] = b"cortex_admin\0";
const TAG_STATE: &[u8] = b"cortex_state\0";

#[derive(Copy, Clone, Eq, PartialEq)]
enum ConscienceState {
    Boot,
    Setup,
    NormalCore,
    NormalOnline,
    Admin,
    ActionPillProcessing,
}

static mut ACTION_PIPELINE: Option<ActionPipeline> = None;
static mut CURRENT_STATE: ConscienceState = ConscienceState::Boot;
static mut ADMIN_WINDOW_ACTIVE: bool = false;
static mut ADMIN_WINDOW_HAS_CLIENT: bool = false;

unsafe extern "C" {
    fn esp_timer_get_time() -> i64;
    fn esp_restart();
    fn gpio_reset_pin(gpio_num: c_int) -> c_int;
    fn gpio_set_direction(gpio_num: c_int, mode: c_int) -> c_int;
    fn gpio_set_level(gpio_num: c_int, level: u32) -> c_int;
    fn esp_log_write(level: c_int, tag: *const c_char, format: *const c_char, ...);
}

pub fn run_code() -> platform::EspErr {
    match run() {
        Ok(()) => platform::ESP_OK,
        Err(err) => err,
    }
}

pub fn run() -> Result {
    transition_to(ConscienceState::Boot);

    event_bus::init()?;
    unsafe { event_bus::subscribe(Some(on_event), ptr::null_mut())? };

    config::init()?;

    let mut cfg: ZoneguardConfigRaw = zeroed_raw();
    if config::load(&mut cfg).is_err() {
        transition_to(ConscienceState::Setup);
        return enter_setup_mode();
    }

    transition_to(ConscienceState::NormalCore);
    enter_normal_mode(&cfg)
}

struct ActionPipeline {
    stomach: Stomach,
    membrane: Membrane,
    issuer_key_id: [u8; CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    issuer_public_key_pem: [u8; CONFIG_STORE_PUBLIC_KEY_MAX_LEN],
    issuer_public_key_len: usize,
}

impl ActionPipeline {
    fn new(cfg: &ZoneguardConfigRaw) -> Result<Self> {
        let mut membrane = Membrane::new();
        membrane.init()?;

        let issuer_public_key_len = c_char_nul_len(&cfg.issuer_public_key_pem);
        if issuer_public_key_len == 0 {
            return Err(platform::ESP_ERR_INVALID_ARG);
        }

        let mut issuer_public_key_pem = [0u8; CONFIG_STORE_PUBLIC_KEY_MAX_LEN];
        copy_c_char_to_u8(&mut issuer_public_key_pem, &cfg.issuer_public_key_pem);

        Ok(Self {
            stomach: Stomach::new(),
            membrane,
            issuer_key_id: cfg.issuer_key_id,
            issuer_public_key_pem,
            issuer_public_key_len,
        })
    }

    fn process_action_pill(&mut self, pill: ActionPill) -> Result {
        log_pipeline_action_pill_rx();
        let seen = self.stomach.seen_or_add_cp(&pill);
        if seen.status != platform::ESP_OK {
            return Err(seen.status);
        }
        if seen.seen {
            return Ok(());
        }

        self.stomach.validate_authorized(
            &pill,
            now_ms(),
            &self.issuer_key_id,
            self.issuer_public_key(),
        )?;

        let mut digested = DigestedActiveSubstance::new();
        stomach::digest_active_substance(
            &pill,
            &self.membrane.state().ribosome_table,
            None,
            &mut digested,
        )?;

        let result = BrokerPipeline::publish_digested(&self.membrane, &digested);
        log_pipeline_result(match result {
            Ok(()) => platform::ESP_OK,
            Err(err) => err,
        });
        result
    }

    fn issuer_public_key(&self) -> &[u8] {
        &self.issuer_public_key_pem[..self.issuer_public_key_len]
    }
}

fn enter_setup_mode() -> Result {
    unsafe {
        setup_ap::start(cstr_ptr(SETUP_SSID), cstr_ptr(SETUP_PASSWORD))?;

        let admin_config = AdminServerConfigRaw {
            setup_ap_ssid: cstr_ptr(SETUP_SSID),
            setup_ap_password: cstr_ptr(SETUP_PASSWORD),
            mode: admin_server::ADMIN_SERVER_MODE_BOOTSTRAP,
            guardian_id: 0,
            zone_id: 0,
            on_window_closed: None,
            ctx: ptr::null_mut(),
        };

        admin_server::start(&admin_config)
    }
}

fn enter_normal_mode(cfg: &ZoneguardConfigRaw) -> Result {
    device_registry::init(cfg.zone_id)?;
    start_normal_wifi(cfg)?;

    init_action_pipeline(cfg)?;

    start_admin_setup_button()?;

    start_normal_mqtt(cfg)?;

    g2g::set_action_pill_handler(Some(on_action_pill_received));
    g2g::start(cfg.guardian_id, cfg.zone_id)?;

    if ENABLE_OPTIONAL_SECURITY_SERVICES {
        start_optional_security_services(cfg)?;
    } else {
        log_optional_services("security", false);
    }

    if ENABLE_OPTIONAL_GATEWAY_SERVICES {
        start_optional_gateway_services(cfg)?;
    } else {
        log_optional_services("gateway", false);
    }

    transition_to(ConscienceState::NormalOnline);
    Ok(())
}

fn start_normal_wifi(cfg: &ZoneguardConfigRaw) -> Result {
    let mut wifi_config: WifiManagerConfigRaw = zeroed_raw();
    copy_c_char_to_u8(&mut wifi_config.sta_ssid, &cfg.sta_ssid);
    copy_c_char_to_u8(&mut wifi_config.sta_password, &cfg.sta_password);
    copy_c_char_to_u8(&mut wifi_config.ap_ssid, &cfg.ap_ssid);
    copy_c_char_to_u8(&mut wifi_config.ap_password, &cfg.ap_password);
    wifi_config.ap_channel = if cfg.ap_channel != 0 {
        cfg.ap_channel
    } else {
        6
    };
    wifi_config.ap_max_connections = if cfg.ap_max_connections != 0 {
        cfg.ap_max_connections
    } else {
        4
    };
    wifi_config.sta_max_retries = 10;
    wifi_config.ap_hidden = false;
    wifi_manager::start(&wifi_config)
}

fn start_normal_mqtt(cfg: &ZoneguardConfigRaw) -> Result {
    let mut mqtt_config: MqttBrokerConfigRaw = zeroed_raw();
    mqtt_broker::config_defaults(&mut mqtt_config);
    mqtt_config.zone_id = cfg.zone_id;
    mqtt_config.listen_port = mqtt_broker::MQTT_BROKER_DEFAULT_PORT;
    mqtt_config.connect_cb = Some(on_mqtt_connect);
    mqtt_config.message_cb = Some(on_mqtt_message);
    mqtt_config.bind_ip = 0;
    unsafe { mqtt_broker::start(Some(&mqtt_config)) }
}

fn start_optional_security_services(cfg: &ZoneguardConfigRaw) -> Result {
    log_optional_services("security", true);

    let flow_config = FlowTableConfigRaw {
        max_idle_ms: 60_000,
        hard_ttl_ms: 10 * 60_000,
        evict_lru_when_full: true,
    };
    flow_table::init(Some(&flow_config))?;

    let policy_config = PolicyEngineConfigRaw {
        default_action: policy_engine::POLICY_ACTION_ALLOW,
        default_log_event: false,
        default_risk_score: 0,
    };
    policy_engine::init(Some(&policy_config))?;
    add_initial_policies()?;

    let rate_config = RateLimiterConfigRaw {
        default_params: RateLimitParamsRaw {
            window_ms: 1_000,
            max_packets: 100,
            max_bytes: 0,
        },
        max_idle_ms: 60_000,
        evict_lru_when_full: true,
    };
    rate_limiter::init(Some(&rate_config))?;
    add_initial_rate_limits()?;

    let fw_config = zone_firewall::ZoneFirewallConfigRaw {
        zone_id: cfg.zone_id,
        default_allow: true,
        auto_quarantine_on_rate_limit: false,
        quarantine_ttl_ms: 0,
    };
    zone_firewall::init(&fw_config)
}

fn start_optional_gateway_services(_cfg: &ZoneguardConfigRaw) -> Result {
    log_optional_services("gateway", true);

    let gateway_config = zone_gateway::ZoneGatewayConfigRaw {
        wait_for_sta_ip: true,
        wait_interval_ms: 500,
        uplink_timeout_ms: 30_000,
        set_sta_as_default: true,
        auto_recover: true,
    };
    zone_gateway::start_and_wait(&gateway_config, 30_000, 250)?;

    let dns_config = DnsFilterConfigRaw {
        listen_port: 53,
        upstream_dns_ip: dns_filter::ipv4(8, 8, 8, 8),
        default_allow: true,
    };
    init_and_start_dns(&dns_config)
}

fn init_action_pipeline(cfg: &ZoneguardConfigRaw) -> Result {
    let pipeline = ActionPipeline::new(cfg)?;
    unsafe {
        ACTION_PIPELINE = Some(pipeline);
    }
    Ok(())
}

fn init_and_start_dns(dns_config: &DnsFilterConfigRaw) -> Result {
    dns_filter::init(Some(dns_config))?;
    add_initial_dns_rules()?;
    dns_filter::start()
}

fn start_admin_setup_button() -> Result {
    let config = setup_button::SetupButtonConfigRaw {
        gpio_num: ADMIN_SETUP_BUTTON_GPIO,
        active_low: true,
        hold_ms: ADMIN_SETUP_HOLD_MS,
        poll_ms: ADMIN_SETUP_POLL_MS,
        on_hold: Some(on_admin_setup_button_hold),
        ctx: ptr::null_mut(),
    };

    unsafe { setup_button::start(Some(&config)) }
}

fn add_initial_policies() -> Result {
    let mut block_lan: PolicyRuleRaw = zeroed_raw();
    block_lan.priority = 800;
    block_lan.direction = flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK;
    block_lan.src_ip = policy_engine::POLICY_ANY_IP;
    block_lan.src_mask = policy_engine::POLICY_ANY_MASK;
    block_lan.dst_ip = policy_engine::ipv4(192, 168, 1, 0);
    block_lan.dst_mask = policy_engine::cidr_mask(24);
    block_lan.src_port = policy_engine::POLICY_ANY_PORT;
    block_lan.dst_port = policy_engine::POLICY_ANY_PORT;
    block_lan.proto = policy_engine::POLICY_ANY_PROTO;
    block_lan.action = policy_engine::POLICY_ACTION_DENY;
    block_lan.risk_score = 80;
    block_lan.log_event = true;
    write_cstr(&mut block_lan.reason, b"block_lateral_lan");
    policy_engine::add_rule(&block_lan, None)?;

    let mut allow_dns: PolicyRuleRaw = zeroed_raw();
    allow_dns.priority = 700;
    allow_dns.direction = flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK;
    allow_dns.src_ip = policy_engine::POLICY_ANY_IP;
    allow_dns.src_mask = policy_engine::POLICY_ANY_MASK;
    allow_dns.dst_ip = policy_engine::POLICY_ANY_IP;
    allow_dns.dst_mask = policy_engine::POLICY_ANY_MASK;
    allow_dns.src_port = policy_engine::POLICY_ANY_PORT;
    allow_dns.dst_port = 53;
    allow_dns.proto = flow_table::FLOW_PROTO_UDP as u8;
    allow_dns.action = policy_engine::POLICY_ACTION_ALLOW;
    allow_dns.risk_score = 5;
    allow_dns.log_event = false;
    write_cstr(&mut allow_dns.reason, b"allow_dns");
    policy_engine::add_rule(&allow_dns, None)?;

    let mut allow_http: PolicyRuleRaw = zeroed_raw();
    allow_http.priority = 100;
    allow_http.direction = flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK;
    allow_http.src_ip = policy_engine::POLICY_ANY_IP;
    allow_http.src_mask = policy_engine::POLICY_ANY_MASK;
    allow_http.dst_ip = policy_engine::POLICY_ANY_IP;
    allow_http.dst_mask = policy_engine::POLICY_ANY_MASK;
    allow_http.src_port = policy_engine::POLICY_ANY_PORT;
    allow_http.dst_port = 80;
    allow_http.proto = flow_table::FLOW_PROTO_TCP as u8;
    allow_http.action = policy_engine::POLICY_ACTION_ALLOW;
    allow_http.risk_score = 10;
    allow_http.log_event = false;
    write_cstr(&mut allow_http.reason, b"allow_http");
    policy_engine::add_rule(&allow_http, None)?;

    let mut allow_https: PolicyRuleRaw = zeroed_raw();
    allow_https.priority = 100;
    allow_https.direction = flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK;
    allow_https.src_ip = policy_engine::POLICY_ANY_IP;
    allow_https.src_mask = policy_engine::POLICY_ANY_MASK;
    allow_https.dst_ip = policy_engine::POLICY_ANY_IP;
    allow_https.dst_mask = policy_engine::POLICY_ANY_MASK;
    allow_https.src_port = policy_engine::POLICY_ANY_PORT;
    allow_https.dst_port = 443;
    allow_https.proto = flow_table::FLOW_PROTO_TCP as u8;
    allow_https.action = policy_engine::POLICY_ACTION_ALLOW;
    allow_https.risk_score = 10;
    allow_https.log_event = false;
    write_cstr(&mut allow_https.reason, b"allow_https");
    policy_engine::add_rule(&allow_https, None)
}

fn add_initial_rate_limits() -> Result {
    let mut general: RateLimitRuleRaw = zeroed_raw();
    general.priority = 100;
    general.direction = flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK;
    general.src_ip = rate_limiter::RATE_LIMIT_ANY_IP;
    general.src_mask = rate_limiter::RATE_LIMIT_ANY_MASK;
    general.dst_ip = rate_limiter::RATE_LIMIT_ANY_IP;
    general.dst_mask = rate_limiter::RATE_LIMIT_ANY_MASK;
    general.src_port = rate_limiter::RATE_LIMIT_ANY_PORT;
    general.dst_port = rate_limiter::RATE_LIMIT_ANY_PORT;
    general.proto = rate_limiter::RATE_LIMIT_ANY_PROTO;
    general.params.window_ms = 1_000;
    general.params.max_packets = 100;
    general.params.max_bytes = 0;
    general.log_event = true;
    general.suggest_quarantine = false;
    write_cstr(&mut general.reason, b"general_zone_rate_limit");
    rate_limiter::add_rule(&general, None)?;

    let mut dns: RateLimitRuleRaw = zeroed_raw();
    dns.priority = 500;
    dns.direction = flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK;
    dns.src_ip = rate_limiter::RATE_LIMIT_ANY_IP;
    dns.src_mask = rate_limiter::RATE_LIMIT_ANY_MASK;
    dns.dst_ip = rate_limiter::RATE_LIMIT_ANY_IP;
    dns.dst_mask = rate_limiter::RATE_LIMIT_ANY_MASK;
    dns.src_port = rate_limiter::RATE_LIMIT_ANY_PORT;
    dns.dst_port = 53;
    dns.proto = flow_table::FLOW_PROTO_UDP as u8;
    dns.params.window_ms = 10_000;
    dns.params.max_packets = 30;
    dns.params.max_bytes = 0;
    dns.log_event = true;
    dns.suggest_quarantine = true;
    write_cstr(&mut dns.reason, b"dns_flood_protection");
    rate_limiter::add_rule(&dns, None)
}

fn add_initial_dns_rules() -> Result {
    let mut block_bad: DnsFilterRuleRaw = zeroed_raw();
    block_bad.priority = 1_000;
    write_cstr(&mut block_bad.pattern, b"*.bad-domain.com");
    block_bad.action = dns_filter::DNS_FILTER_BLOCK;
    block_bad.redirect_ip = 0;
    block_bad.risk_score = 90;
    write_cstr(&mut block_bad.reason, b"blocked_domain");
    dns_filter::add_rule(&block_bad, None)
}

unsafe extern "C" fn on_admin_setup_button_hold(_ctx: *mut c_void) {
    unsafe {
        if ADMIN_WINDOW_ACTIVE {
            return;
        }
        ADMIN_WINDOW_ACTIVE = true;
        ADMIN_WINDOW_HAS_CLIENT = false;
    }

    transition_to(ConscienceState::Admin);
    enter_admin_quiescent_mode();

    if unsafe {
        wifi_manager::switch_to_ap(
            cstr_ptr(MAINTENANCE_SSID),
            cstr_ptr(MAINTENANCE_PASSWORD),
            1,
        )
    }
    .is_err()
    {
        unsafe {
            ADMIN_WINDOW_ACTIVE = false;
            ADMIN_WINDOW_HAS_CLIENT = false;
        }
        unsafe { esp_restart() };
    }

    let admin_config = AdminServerConfigRaw {
        setup_ap_ssid: cstr_ptr(MAINTENANCE_SSID),
        setup_ap_password: cstr_ptr(MAINTENANCE_PASSWORD),
        mode: admin_server::ADMIN_SERVER_MODE_MAINTENANCE,
        guardian_id: 0,
        zone_id: 0,
        on_window_closed: Some(on_admin_window_closed),
        ctx: ptr::null_mut(),
    };

    if admin_server::open_window(Some(&admin_config), ADMIN_SETUP_UNLOCK_WINDOW_MS).is_err() {
        unsafe {
            ADMIN_WINDOW_ACTIVE = false;
            ADMIN_WINDOW_HAS_CLIENT = false;
        }
        unsafe { esp_restart() };
    }

    blink_admin_status_led();
}

unsafe extern "C" fn on_admin_window_closed(_ctx: *mut c_void) {
    ADMIN_WINDOW_ACTIVE = false;
    ADMIN_WINDOW_HAS_CLIENT = false;
    esp_restart();
}

fn enter_admin_quiescent_mode() {
    log_admin_entering();
    let _ = g2g::stop();
    let _ = dns_filter::stop();
    let _ = zone_gateway::stop();
    let _ = mqtt_broker::stop();
}

fn blink_admin_status_led() {
    unsafe {
        if gpio_reset_pin(ADMIN_STATUS_LED_GPIO) != platform::ESP_OK {
            return;
        }
        if gpio_set_direction(ADMIN_STATUS_LED_GPIO, GPIO_MODE_OUTPUT) != platform::ESP_OK {
            return;
        }

        for _ in 0..ADMIN_STATUS_LED_BLINKS {
            let _ = gpio_set_level(ADMIN_STATUS_LED_GPIO, 1);
            delay_us(ADMIN_STATUS_LED_ON_US);
            let _ = gpio_set_level(ADMIN_STATUS_LED_GPIO, 0);
            delay_us(ADMIN_STATUS_LED_OFF_US);
        }
    }
}

fn delay_us(duration_us: i64) {
    let start = unsafe { esp_timer_get_time() };
    while unsafe { esp_timer_get_time() } - start < duration_us {
        core::hint::spin_loop();
    }
}

fn on_action_pill_received(pill: &ActionPill) -> Result {
    let pill_copy = *pill;
    let previous_state = current_state();
    transition_to(ConscienceState::ActionPillProcessing);

    unsafe {
        let pipeline = ptr::addr_of_mut!(ACTION_PIPELINE);
        let result = match (*pipeline).as_mut() {
            Some(pipeline) => pipeline.process_action_pill(pill_copy),
            None => Err(platform::ESP_ERR_INVALID_STATE),
        };
        transition_to(previous_state);
        result
    }
}

// Retirar depdedência C direta
unsafe extern "C" fn on_mqtt_message(_message: *const MqttBrokerMessageRaw, _ctx: *mut c_void) {}

unsafe extern "C" fn on_mqtt_connect(
    event: *const MqttBrokerConnectRaw,
    _ctx: *mut c_void,
) -> bool {
    if event.is_null() {
        return false;
    }

    let client_id = unsafe { (*event).client_id };
    if !client_id.is_null() {
        unsafe { admin_server::note_mqtt_client(client_id) };
    }

    true
}

// Retirar depdedência C direta
unsafe extern "C" fn on_event(event: *const ZgEventRaw, _ctx: *mut c_void) {
    if event.is_null() {
        return;
    }

    let event = &*event;
    match event.event_type {
        event_bus::ZG_EVENT_AP_CLIENT_JOINED => {
            if ADMIN_WINDOW_ACTIVE {
                ADMIN_WINDOW_HAS_CLIENT = true;
            }
        }
        event_bus::ZG_EVENT_AP_CLIENT_LEFT => {
            if ADMIN_WINDOW_ACTIVE && ADMIN_WINDOW_HAS_CLIENT {
                let _ = admin_server::stop();
            }
        }
        _ => {}
    }
}

fn current_state() -> ConscienceState {
    unsafe { CURRENT_STATE }
}

fn transition_to(next: ConscienceState) {
    unsafe {
        let previous = CURRENT_STATE;
        if previous == next {
            return;
        }

        CURRENT_STATE = next;
        esp_log_write(
            ESP_LOG_INFO,
            TAG_STATE.as_ptr().cast(),
            c"state %s -> %s".as_ptr(),
            state_name(previous),
            state_name(next),
        );
    }
}

fn state_name(state: ConscienceState) -> *const c_char {
    match state {
        ConscienceState::Boot => c"BOOT".as_ptr(),
        ConscienceState::Setup => c"SETUP".as_ptr(),
        ConscienceState::NormalCore => c"NORMAL_CORE".as_ptr(),
        ConscienceState::NormalOnline => c"NORMAL_ONLINE".as_ptr(),
        ConscienceState::Admin => c"ADMIN".as_ptr(),
        ConscienceState::ActionPillProcessing => c"ACTION_PILL".as_ptr(),
    }
}

fn log_optional_services(name: &str, enabled: bool) {
    let status = if enabled {
        c"enabled".as_ptr()
    } else {
        c"disabled".as_ptr()
    };
    let name = name.as_bytes();
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            TAG_STATE.as_ptr().cast(),
            c"optional %.*s services %s".as_ptr(),
            name.len() as c_int,
            name.as_ptr().cast::<c_char>(),
            status,
        );
    }
}

fn cstr_ptr(bytes: &'static [u8]) -> *const c_char {
    bytes.as_ptr().cast()
}

fn copy_c_char_to_u8(dst: &mut [u8], src: &[c_char]) {
    if dst.is_empty() {
        return;
    }

    let limit = dst.len().saturating_sub(1).min(src.len());
    for i in 0..limit {
        let byte = src[i] as u8;
        dst[i] = byte;
        if byte == 0 {
            return;
        }
    }

    dst[limit] = 0;
}

fn write_cstr(dst: &mut [c_char], src: &[u8]) {
    if dst.is_empty() {
        return;
    }

    let limit = dst.len().saturating_sub(1).min(src.len());
    for i in 0..limit {
        dst[i] = src[i] as c_char;
    }
    dst[limit] = 0;
}

fn c_char_nul_len(src: &[c_char]) -> usize {
    if src.is_empty() || src[0] == 0 {
        return 0;
    }

    for i in 0..src.len() {
        if src[i] == 0 {
            return i + 1;
        }
    }

    src.len()
}

fn now_ms() -> u32 {
    let us = unsafe { esp_timer_get_time() };
    if us <= 0 {
        0
    } else {
        ((us as u64) / 1_000) as u32
    }
}

fn zeroed_raw<T>() -> T {
    let raw = MaybeUninit::<T>::zeroed();
    unsafe { raw.assume_init() }
}

fn log_admin_tag() -> *const c_char {
    TAG_ADMIN.as_ptr().cast()
}

fn log_admin_entering() {
    unsafe {
        esp_log_write(
            ESP_LOG_WARN,
            log_admin_tag(),
            c"entrando em modo admin exclusivo; parando servicos normais".as_ptr(),
        );
    }
}

fn log_pipeline_tag() -> *const c_char {
    TAG_PIPELINE.as_ptr().cast()
}

fn log_pipeline_action_pill_rx() {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_pipeline_tag(),
            c"action_pill received by conscience".as_ptr(),
        );
    }
}

fn log_pipeline_result(err: platform::EspErr) {
    let level = if err == platform::ESP_OK {
        ESP_LOG_INFO
    } else {
        ESP_LOG_WARN
    };
    unsafe {
        esp_log_write(
            level,
            log_pipeline_tag(),
            c"publish digested result err=0x%08x".as_ptr(),
            err as u32,
        );
    }
}
