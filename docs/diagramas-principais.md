# Diagramas principais - BlindNet / ZoneGuard

Este documento consolida os diagramas principais do firmware ZoneGuard, com base nos componentes em `firmware/main/app_main.cpp` e `firmware/components/`.

## 1. Arquitetura geral

```mermaid
flowchart LR
    Admin["Administrador<br/>navegador web"]
    Device["Dispositivos IoT<br/>da zona"]
    Router["Roteador / Internet<br/>uplink STA"]
    DnsUpstream["DNS upstream<br/>8.8.8.8"]
    Peer["Outro Guardian<br/>BlindNet Swarm"]
    Monitor["Console serial<br/>ou coletor UDP"]

    subgraph ESP["ESP32 Guardian - ZoneGuard"]
        SetupAP["AP temporario<br/>ZoneGuard_Setup"]
        AdminServer["admin_server<br/>setup HTTP"]
        Config["config_store<br/>NVS"]

        Wifi["wifi_manager<br/>AP + STA"]
        Gateway["zone_gateway<br/>NAPT / rota padrao"]
        DNS["dns_filter<br/>porta UDP 53"]
        Firewall["zone_firewall<br/>decisao de trafego"]
        Registry["device_registry<br/>estado dos dispositivos"]
        Quarantine["quarantine_manager<br/>isolamento temporario"]
        Policy["policy_engine<br/>regras"]
        Rate["rate_limiter<br/>janelas de trafego"]
        Flow["flow_table<br/>fluxos ativos"]
        Swarm["swarm_agent<br/>UDP broadcast"]
        Telemetry["telemetry_agent<br/>snapshot periodico"]
        Events["event_bus<br/>eventos internos"]
    end

    Admin -->|"configura /save"| SetupAP
    SetupAP --> AdminServer --> Config

    Device -->|"conecta no AP da zona"| Wifi
    Wifi --> Gateway --> Router
    Device -->|"consultas DNS"| DNS -->|"encaminha quando permitido"| DnsUpstream
    Device -->|"fluxos TCP/UDP/ICMP"| Firewall --> Gateway

    Firewall --> Flow
    Firewall --> Policy
    Firewall --> Rate
    Firewall --> Quarantine
    Firewall --> Registry
    Firewall --> Events
    DNS --> Events
    Config --> Events
    Registry --> Events

    Swarm <-->|"HELLO, ZONE_STATE,<br/>QUARANTINE_NOTICE"| Peer
    Swarm --> Quarantine
    Swarm --> Registry

    Telemetry --> Monitor
    Telemetry --> Wifi
    Telemetry --> Gateway
    Telemetry --> Flow
    Telemetry --> Policy
    Telemetry --> Rate
    Telemetry --> Quarantine
    Telemetry --> Swarm
```

## 2. Componentes internos e dependencias

```mermaid
flowchart TB
    App["app_main.cpp"]

    subgraph Boot["Boot e configuracao"]
        EventBus["event_bus"]
        ConfigStore["config_store"]
        AdminServer["admin_server"]
    end

    subgraph Rede["Rede"]
        WifiManager["wifi_manager"]
        ZoneGateway["zone_gateway"]
        DnsFilter["dns_filter"]
    end

    subgraph Seguranca["Seguranca de trafego"]
        ZoneFirewall["zone_firewall"]
        FlowTable["flow_table"]
        PolicyEngine["policy_engine"]
        RateLimiter["rate_limiter"]
        QuarantineManager["quarantine_manager"]
        DeviceRegistry["device_registry"]
    end

    subgraph Colaboracao["Colaboracao e observabilidade"]
        SwarmAgent["swarm_agent"]
        TelemetryAgent["telemetry_agent"]
    end

    App --> EventBus
    App --> ConfigStore
    App --> AdminServer
    App --> WifiManager
    App --> ZoneGateway
    App --> DnsFilter
    App --> FlowTable
    App --> PolicyEngine
    App --> RateLimiter
    App --> QuarantineManager
    App --> DeviceRegistry
    App --> ZoneFirewall
    App --> SwarmAgent
    App --> TelemetryAgent

    ConfigStore --> EventBus
    AdminServer --> ConfigStore
    ZoneGateway --> WifiManager
    DnsFilter --> EventBus
    DeviceRegistry --> EventBus

    ZoneFirewall --> FlowTable
    ZoneFirewall --> PolicyEngine
    ZoneFirewall --> RateLimiter
    ZoneFirewall --> QuarantineManager
    ZoneFirewall --> DeviceRegistry
    ZoneFirewall --> EventBus

    PolicyEngine --> FlowTable
    RateLimiter --> FlowTable
    QuarantineManager --> FlowTable

    SwarmAgent --> FlowTable
    SwarmAgent --> QuarantineManager

    TelemetryAgent --> WifiManager
    TelemetryAgent --> ZoneGateway
    TelemetryAgent --> FlowTable
    TelemetryAgent --> PolicyEngine
    TelemetryAgent --> RateLimiter
    TelemetryAgent --> QuarantineManager
    TelemetryAgent --> SwarmAgent
```

## 3. Casos de uso principais

```mermaid
flowchart LR
    Admin["Administrador"]
    Device["Dispositivo IoT"]
    Peer["Guardian remoto"]
    Monitor["Operador / Monitoramento"]

    subgraph ZG["ZoneGuard"]
        UC1(["Configurar rede<br/>e zona"])
        UC2(["Salvar configuracao<br/>no NVS"])
        UC3(["Conectar dispositivos<br/>ao AP protegido"])
        UC4(["Filtrar DNS"])
        UC5(["Avaliar fluxo<br/>por politica"])
        UC6(["Aplicar limite<br/>de taxa"])
        UC7(["Quarentenar<br/>origem suspeita"])
        UC8(["Compartilhar estado<br/>no swarm"])
        UC9(["Emitir snapshot<br/>de telemetria"])
    end

    Admin --> UC1
    UC1 --> UC2

    Device --> UC3
    Device --> UC4
    Device --> UC5

    UC5 --> UC6
    UC5 --> UC7
    UC6 --> UC7

    Peer --> UC8
    UC8 --> UC7

    Monitor --> UC9
```

## 4. Boot e selecao de modo

```mermaid
sequenceDiagram
    autonumber
    participant ESP as app_main
    participant Events as event_bus
    participant Store as config_store
    participant Admin as admin_server
    participant Wifi as wifi_manager
    participant Gateway as zone_gateway
    participant DNS as dns_filter
    participant FW as zone_firewall
    participant Swarm as swarm_agent
    participant Telemetry as telemetry_agent

    ESP->>Events: event_bus_init()
    ESP->>Events: event_bus_subscribe(on_event)
    ESP->>Store: config_store_init()
    ESP->>Store: config_store_load()

    alt Configuracao nao encontrada
        Store-->>ESP: ESP_ERR_NOT_FOUND
        ESP->>ESP: setup_ap_start("ZoneGuard_Setup")
        ESP->>Admin: admin_server_start()
        Admin-->>ESP: HTTP em 192.168.4.1
        Note over Admin,Store: POST /save grava NVS e reinicia
    else Configuracao valida encontrada
        Store-->>ESP: zoneguard_config_t
        ESP->>Wifi: wifi_manager_start(AP + STA)
        ESP->>FW: inicializa flow, policy, rate, quarantine e firewall
        ESP->>Gateway: zone_gateway_start()
        Gateway-->>ESP: NAPT pronto
        ESP->>DNS: dns_filter_init() + regras iniciais
        ESP->>DNS: dns_filter_start()
        ESP->>Swarm: swarm_agent_start()
        ESP->>Telemetry: telemetry_agent_start()
        ESP->>FW: teste fake de fluxo DNS
    end
```

## 5. Fluxo de decisao do firewall

```mermaid
flowchart TD
    Start["Pacote/fluxo recebido"]
    Touch["flow_table_touch()<br/>cria ou atualiza fluxo"]
    CheckQ["quarantine_manager_check_flow_src()"]
    QBlock{"Origem em quarentena<br/>BLOCK_ALL?"}
    EvalPolicy["policy_engine_evaluate()"]
    PolicyAction{"Acao da politica"}
    RateCheck["rate_limiter_check()"]
    RateExceeded{"Limite excedido?"}
    AutoQ{"Auto-quarentena<br/>sugerida?"}
    LogOnly{"Politica LOG_ONLY?"}
    Allow["VERDICT_ALLOW"]
    Drop["VERDICT_DROP"]
    Redirect["VERDICT_REDIRECT"]
    Log["VERDICT_LOG_ONLY"]
    AddQ["quarantine_manager_add_ip()"]
    SetReg["device_registry_set_state_by_ip()<br/>QUARANTINED"]
    Events["event_bus_publish()"]

    Start --> Touch --> CheckQ --> QBlock
    QBlock -- "sim" --> Drop --> Events
    QBlock -- "nao" --> EvalPolicy --> PolicyAction

    PolicyAction -- "DENY" --> Drop
    PolicyAction -- "QUARANTINE" --> AddQ --> SetReg --> Drop
    PolicyAction -- "REDIRECT" --> Redirect
    PolicyAction -- "ALLOW / RATE_LIMIT / ASK_SWARM" --> RateCheck

    RateCheck --> RateExceeded
    RateExceeded -- "sim" --> Events --> AutoQ
    AutoQ -- "sim" --> AddQ
    AutoQ -- "nao" --> Drop
    AddQ --> Drop

    RateExceeded -- "nao" --> LogOnly
    LogOnly -- "sim" --> Log --> Events
    LogOnly -- "nao" --> Allow
```

## 6. Fluxo de DNS filtrado

```mermaid
sequenceDiagram
    autonumber
    participant Device as Dispositivo IoT
    participant DNS as dns_filter
    participant Rules as Regras DNS
    participant Events as event_bus
    participant Upstream as DNS upstream

    Device->>DNS: UDP 53 query
    DNS->>DNS: parse_dns_qname()
    DNS->>Rules: dns_filter_evaluate_domain()

    alt Dominio bloqueado
        Rules-->>DNS: DNS_FILTER_BLOCK
        DNS->>Events: ZG_EVENT_DNS_BLOCKED
        DNS-->>Device: resposta A 0.0.0.0
    else Dominio redirecionado
        Rules-->>DNS: DNS_FILTER_REDIRECT
        DNS->>Events: ZG_EVENT_DNS_QUERY
        DNS-->>Device: resposta A redirect_ip
    else Dominio permitido
        Rules-->>DNS: DNS_FILTER_ALLOW
        DNS->>Upstream: encaminha consulta
        Upstream-->>DNS: resposta DNS
        DNS-->>Device: resposta upstream
    end
```

## 7. Swarm e quarentena compartilhada

```mermaid
sequenceDiagram
    autonumber
    participant Peer as Guardian remoto
    participant Swarm as swarm_agent
    participant Main as on_swarm_frame()
    participant Q as quarantine_manager
    participant Reg as device_registry
    participant FW as zone_firewall

    Peer-->>Swarm: SWARM_MSG_QUARANTINE_NOTICE
    Swarm->>Swarm: valida magic, prazo e HMAC
    Swarm->>Main: callback(frame)
    Main->>Q: quarantine_manager_add_ip(subject_ip, mode, SWARM)
    Main->>Reg: device_registry_set_state_by_ip(QUARANTINED)

    Note over FW,Q: Fluxos futuros da origem passam pela checagem de quarentena
    FW->>Q: quarantine_manager_check_flow_src()
    Q-->>FW: quarantined=true
    FW-->>FW: VERDICT_DROP quando mode=BLOCK_ALL
```

## 8. Modelo de dados principal

```mermaid
classDiagram
    class zoneguard_config_t {
        uint32_t zone_id
        uint32_t guardian_id
        char sta_ssid
        char ap_ssid
        uint16_t swarm_port
        char telemetry_host
        uint32_t policy_version
    }

    class flow_key_t {
        uint32_t src_ip
        uint32_t dst_ip
        uint16_t src_port
        uint16_t dst_port
        uint8_t proto
    }

    class flow_entry_t {
        flow_key_t key
        flow_direction_t direction
        flow_state_t state
        uint64_t packets
        uint64_t bytes
        uint8_t risk_score
    }

    class policy_rule_t {
        uint32_t rule_id
        uint16_t priority
        flow_direction_t direction
        uint32_t src_ip
        uint32_t dst_ip
        uint16_t dst_port
        policy_action_t action
        uint8_t risk_score
        char reason
    }

    class rate_limit_rule_t {
        uint32_t rule_id
        uint16_t priority
        rate_limit_params_t params
        bool suggest_quarantine
        char reason
    }

    class quarantine_entry_t {
        quarantine_subject_t subject
        quarantine_mode_t mode
        quarantine_source_t source
        uint32_t expires_at_ms
        uint8_t risk_score
        char reason
    }

    class device_record_t {
        uint32_t device_id
        uint32_t ip
        uint32_t zone_id
        device_state_t state
        uint8_t risk_score
        char name
        char profile
    }

    class zg_event_t {
        zg_event_type_t type
        uint32_t zone_id
        uint32_t device_id
        uint32_t src_ip
        uint32_t dst_ip
        uint8_t risk_score
        char reason
    }

    class swarm_frame_t {
        uint8_t type
        uint32_t message_id
        uint32_t origin_id
        uint32_t target_id
        uint8_t hop_count
        uint8_t hmac
        uint8_t payload
    }

    zoneguard_config_t --> policy_rule_t : configura
    flow_entry_t *-- flow_key_t
    policy_rule_t --> flow_key_t : criterios
    rate_limit_rule_t --> flow_key_t : criterios
    quarantine_entry_t --> flow_key_t : bloqueia origem
    device_record_t --> quarantine_entry_t : pode gerar
    zg_event_t --> flow_key_t : referencia fluxo
    swarm_frame_t --> quarantine_entry_t : transporta aviso
```

## 9. Estados principais

```mermaid
stateDiagram-v2
    [*] --> Boot
    Boot --> Setup: config_store_load falha
    Boot --> Normal: config valida

    Setup --> APTemporario: setup_ap_start
    APTemporario --> ServidorHTTP: admin_server_start
    ServidorHTTP --> SalvarConfig: POST /save
    SalvarConfig --> Reiniciar: config_store_save
    Reiniciar --> Boot

    Normal --> Rede: wifi_manager_start
    Rede --> GatewayPronto: NAPT habilitado
    GatewayPronto --> ServicosSeguranca: DNS + firewall + swarm + telemetria
    ServicosSeguranca --> Operando

    Operando --> Operando: snapshot telemetria
    Operando --> Operando: eventos internos
    Operando --> DispositivoQuarentenado: politica, rate limit ou swarm
    DispositivoQuarentenado --> Operando: TTL expira ou remocao manual
```

## 10. Estados do dispositivo

```mermaid
stateDiagram-v2
    [*] --> UNKNOWN
    UNKNOWN --> TRUSTED: cadastro/atualizacao normal
    TRUSTED --> SUSPICIOUS: risco elevado
    SUSPICIOUS --> QUARANTINED: politica, rate limit ou swarm
    TRUSTED --> QUARANTINED: bloqueio direto
    QUARANTINED --> BLOCKED: bloqueio permanente/manual
    QUARANTINED --> TRUSTED: liberacao ou expiracao da quarentena
    BLOCKED --> TRUSTED: liberacao manual
```

## Fontes do codigo

- `firmware/main/app_main.cpp`
- `firmware/components/zone_firewall/zone_firewall.c`
- `firmware/components/dns_filter/dns_filter.c`
- `firmware/components/swarm_agent/swarm_agent.hpp`
- `firmware/components/telemetry_agent/telemetry_agent.cpp`
- `firmware/components/config_store/config_store.c`
- `firmware/components/admin_server/admin_server.c`
