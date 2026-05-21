use core::ffi::{c_char, c_void};
use core::mem::{self, MaybeUninit};
use core::ptr;

use crate::platform;
use crate::platform::admin_server::AdminServerConfigRaw;
use crate::platform::config::ZoneguardConfigRaw;
use crate::platform::dns_filter::{DnsFilterConfigRaw, DnsFilterRuleRaw};
use crate::platform::event_bus::ZgEventRaw;
use crate::platform::flow_table::{FlowKeyRaw, FlowTableConfigRaw};
use crate::platform::mqtt_broker::{
    MqttBrokerConfigRaw, MqttBrokerConnectRaw, MqttBrokerMessageRaw,
};
use crate::platform::policy_engine::{PolicyEngineConfigRaw, PolicyRuleRaw};
use crate::platform::quarantine_manager::{QuarantineManagerConfigRaw, QuarantineMode};
use crate::platform::rate_limiter::{RateLimitParamsRaw, RateLimitRuleRaw, RateLimiterConfigRaw};
use crate::platform::wifi_manager::WifiManagerConfigRaw;
use crate::platform::{
    admin_server, config, device_registry, dns_filter, event_bus, flow_table, mqtt_broker,
    policy_engine, quarantine_manager, rate_limiter, setup_ap, swarm_agent, telemetry_agent,
    wifi_manager, zone_firewall, zone_gateway, Result,
};

use crate::logic::g2g;

const SETUP_SSID: &[u8] = b"ZoneGuard_Setup\0";
const SETUP_PASSWORD: &[u8] = b"setup1234\0";
const DEFAULT_SWARM_BROADCAST: &[u8] = b"255.255.255.255\0";

const SWARM_FRAME_PAYLOAD_OFFSET: usize =
    2 + 1 + 1 + 4 + 4 + 4 + 1 + 1 + 2 + 4 + 4 + 4 + swarm_agent::SWARM_AGENT_HMAC_LEN;
const SWARM_Q_MODE_OFFSET: usize = 9;
const SWARM_Q_RISK_OFFSET: usize = 11;
const SWARM_Q_SUBJECT_IP_OFFSET: usize = 12;
const SWARM_Q_TTL_MS_OFFSET: usize = 16;
const SWARM_Q_REASON_OFFSET: usize = 20;

pub fn run_code() -> platform::EspErr {
    match run() {
        Ok(()) => platform::ESP_OK,
        Err(err) => err,
    }
}

pub fn run() -> Result {
    event_bus::init()?;
    unsafe { event_bus::subscribe(Some(on_event), ptr::null_mut())? };

    config::init()?;

    let mut cfg: ZoneguardConfigRaw = zeroed_raw();
    if config::load(&mut cfg).is_err() {
        return enter_setup_mode();
    }

    enter_normal_mode(&cfg)
}

fn enter_setup_mode() -> Result {
    unsafe {
        setup_ap::start(cstr_ptr(SETUP_SSID), cstr_ptr(SETUP_PASSWORD))?;

        let admin_config = AdminServerConfigRaw {
            setup_ap_ssid: cstr_ptr(SETUP_SSID),
            setup_ap_password: cstr_ptr(SETUP_PASSWORD),
        };

        admin_server::start(&admin_config)
    }
}

fn enter_normal_mode(cfg: &ZoneguardConfigRaw) -> Result {
    device_registry::init(cfg.zone_id)?;

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
    wifi_manager::start(&wifi_config)?;

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

    let quarantine_config = QuarantineManagerConfigRaw {
        default_ttl_ms: 60_000,
        evict_lru_when_full: true,
    };
    quarantine_manager::init(Some(&quarantine_config))?;

    let fw_config = zone_firewall::ZoneFirewallConfigRaw {
        zone_id: cfg.zone_id,
        default_allow: true,
        auto_quarantine_on_rate_limit: true,
        quarantine_ttl_ms: 60_000,
    };
    zone_firewall::init(&fw_config)?;

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
    let _ = init_and_start_dns(&dns_config);

    let mut mqtt_config: MqttBrokerConfigRaw = zeroed_raw();
    mqtt_broker::config_defaults(&mut mqtt_config);
    mqtt_config.zone_id = cfg.zone_id;
    mqtt_config.listen_port = mqtt_broker::MQTT_BROKER_DEFAULT_PORT;
    mqtt_config.connect_cb = Some(on_mqtt_connect);
    mqtt_config.message_cb = Some(on_mqtt_message);
    if let Ok(ap_ip) = wifi_manager::ap_ip() {
        mqtt_config.bind_ip = ap_ip;
    }
    unsafe {
        let _ = mqtt_broker::start(Some(&mqtt_config));
    }

    g2g::start(cfg.guardian_id, cfg.zone_id)?;

    let swarm_broadcast = if cfg.swarm_broadcast[0] != 0 {
        cfg.swarm_broadcast.as_ptr()
    } else {
        cstr_ptr(DEFAULT_SWARM_BROADCAST)
    };
    let swarm_config = swarm_agent::SwarmAgentConfigRaw {
        guardian_id: cfg.guardian_id,
        zone_id: cfg.zone_id,
        udp_port: if cfg.swarm_port != 0 {
            cfg.swarm_port
        } else {
            4747
        },
        broadcast_addr: swarm_broadcast,
        hello_interval_ms: 5_000,
        zone_state_interval_ms: 7_000,
        verify_mode: swarm_agent::SWARM_VERIFY_HMAC_SHA256,
        shared_key: cfg.swarm_key.as_ptr(),
        shared_key_len: cfg.swarm_key_len as usize,
    };
    unsafe {
        swarm_agent::set_frame_callback(Some(on_swarm_frame), ptr::null_mut());
        let _ = swarm_agent::start(Some(&swarm_config));
    }

    let telemetry_config = telemetry_agent::TelemetryAgentConfigRaw {
        zone_id: cfg.zone_id,
        guardian_id: cfg.guardian_id,
        interval_ms: 5_000,
        outputs: telemetry_agent::TELEMETRY_OUTPUT_SERIAL as u32,
        udp_host: ptr::null(),
        udp_port: if cfg.telemetry_port != 0 {
            cfg.telemetry_port
        } else {
            5757
        },
        send_on_start: true,
    };
    unsafe { telemetry_agent::start(Some(&telemetry_config))? };

    test_zone_firewall_fake_flow()
}

fn init_and_start_dns(dns_config: &DnsFilterConfigRaw) -> Result {
    dns_filter::init(Some(dns_config))?;
    add_initial_dns_rules()?;
    dns_filter::start()
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

fn test_zone_firewall_fake_flow() -> Result {
    let key = FlowKeyRaw {
        src_ip: policy_engine::ipv4(192, 168, 4, 2),
        dst_ip: policy_engine::ipv4(8, 8, 8, 8),
        src_port: 50_000,
        dst_port: 53,
        proto: flow_table::FLOW_PROTO_UDP as u8,
    };
    let mut decision: zone_firewall::ZoneFirewallDecisionRaw = zeroed_raw();
    zone_firewall::evaluate_flow(
        &key,
        flow_table::FLOW_DIRECTION_ZONE_TO_UPLINK,
        80,
        &mut decision,
    )
}

// Retirar depdedência C direta
unsafe extern "C" fn on_mqtt_message(_message: *const MqttBrokerMessageRaw, _ctx: *mut c_void) {}

unsafe extern "C" fn on_mqtt_connect(
    event: *const MqttBrokerConnectRaw,
    _ctx: *mut c_void,
) -> bool {
    !event.is_null()
}

// Retirar depdedência C direta
unsafe extern "C" fn on_event(_event: *const ZgEventRaw, _ctx: *mut c_void) {}

unsafe extern "C" fn on_swarm_frame(frame: *const swarm_agent::SwarmFrameRaw, _ctx: *mut c_void) {
    if frame.is_null() {
        return;
    }

    let base = frame.cast::<u8>();
    let frame_type = unsafe { ptr::read_unaligned(base.add(3)) };
    if frame_type != swarm_agent::SWARM_MSG_QUARANTINE_NOTICE as u8 {
        return;
    }

    let payload_len = unsafe { ptr::read_unaligned(base.add(18).cast::<u16>()) };
    if (payload_len as usize) < mem::size_of::<swarm_agent::SwarmPayloadQuarantineNoticeRaw>() {
        return;
    }

    let payload = unsafe { base.add(SWARM_FRAME_PAYLOAD_OFFSET) };
    let mode = unsafe { ptr::read_unaligned(payload.add(SWARM_Q_MODE_OFFSET)) };
    let risk_score = unsafe { ptr::read_unaligned(payload.add(SWARM_Q_RISK_OFFSET)) };
    let subject_ip =
        unsafe { ptr::read_unaligned(payload.add(SWARM_Q_SUBJECT_IP_OFFSET).cast::<u32>()) };
    let ttl_ms = unsafe { ptr::read_unaligned(payload.add(SWARM_Q_TTL_MS_OFFSET).cast::<u32>()) };
    let reason = unsafe { payload.add(SWARM_Q_REASON_OFFSET).cast::<c_char>() };

    let _ = unsafe {
        quarantine_manager::add_ip(
            subject_ip,
            mode as QuarantineMode,
            quarantine_manager::QUARANTINE_SOURCE_SWARM,
            ttl_ms,
            risk_score,
            reason,
        )
    };
    let _ = device_registry::set_state_by_ip(
        subject_ip,
        device_registry::DEVICE_STATE_QUARANTINED,
        risk_score,
    );
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

fn zeroed_raw<T>() -> T {
    let raw = MaybeUninit::<T>::zeroed();
    unsafe { raw.assume_init() }
}
