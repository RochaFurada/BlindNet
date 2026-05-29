#include <WiFi.h>
#include <PubSubClient.h>

// Ajuste estes valores para bater com o AP normal do Guardian.
static const char *WIFI_SSID = "ZoneGuard_Sala";
static const char *WIFI_PASSWORD = "zoneguard123";

static const char *MQTT_HOST = "192.168.4.1";
static const uint16_t MQTT_PORT = 1883;

// Este client_id precisa ser o mesmo cadastrado no admin/ribosome do Guardian.
static const char *MQTT_CLIENT_ID = "lamp01";
static const char *COMMAND_TOPIC = "blindnet/lamp01/cmd";
static const char *STATE_TOPIC = "blindnet/lamp01/state";

static const uint8_t LED_PIN = 15;

WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);

static bool ledOn = false;
static uint32_t lastReconnectAttemptMs = 0;

static void publishState()
{
  mqtt.publish(STATE_TOPIC, ledOn ? "1" : "0", true);
}

static void setLed(bool on)
{
  ledOn = on;
  digitalWrite(LED_PIN, ledOn ? HIGH : LOW);
  publishState();
  Serial.printf("LED %s\n", ledOn ? "ON" : "OFF");
}

static bool payloadEquals(const byte *payload, unsigned int length, const char *text)
{
  size_t textLen = strlen(text);
  if (length != textLen) {
    return false;
  }

  for (unsigned int i = 0; i < length; ++i) {
    char a = (char)payload[i];
    char b = text[i];
    if (a >= 'a' && a <= 'z') {
      a = (char)(a - 'a' + 'A');
    }
    if (b >= 'a' && b <= 'z') {
      b = (char)(b - 'a' + 'A');
    }
    if (a != b) {
      return false;
    }
  }

  return true;
}

static void onMqttMessage(char *topic, byte *payload, unsigned int length)
{
  Serial.printf("MQTT RX topic=%s len=%u payload=", topic, length);
  for (unsigned int i = 0; i < length; ++i) {
    Serial.print((char)payload[i]);
  }
  Serial.println();

  if (strcmp(topic, COMMAND_TOPIC) != 0) {
    return;
  }

  // No fluxo atual do Guardian: AMINO_TOGGLE usa payload vazio.
  if (length == 0 || payloadEquals(payload, length, "TOGGLE")) {
    setLed(!ledOn);
    return;
  }

  // AMINO_ON/AMINO_OFF com payload booleano chegam como "1" ou "0".
  if (payloadEquals(payload, length, "1") || payloadEquals(payload, length, "ON")) {
    setLed(true);
    return;
  }
  if (payloadEquals(payload, length, "0") || payloadEquals(payload, length, "OFF")) {
    setLed(false);
    return;
  }

  Serial.println("Comando ignorado");
}

static void connectWifi()
{
  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.setSleep(false);

  Serial.printf("Conectando no AP do Guardian: %s\n", WIFI_SSID);
  if (strlen(WIFI_PASSWORD) == 0) {
    WiFi.begin(WIFI_SSID);
  } else {
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.printf("WiFi conectado. IP=%s RSSI=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
}

static bool connectMqtt()
{
  if (mqtt.connected()) {
    return true;
  }

  Serial.printf("Conectando no broker %s:%u como %s\n", MQTT_HOST, MQTT_PORT, MQTT_CLIENT_ID);
  if (!mqtt.connect(MQTT_CLIENT_ID)) {
    Serial.printf("Falha MQTT rc=%d\n", mqtt.state());
    return false;
  }

  mqtt.subscribe(COMMAND_TOPIC);
  publishState();
  Serial.printf("MQTT conectado. Subscrito em %s\n", COMMAND_TOPIC);
  return true;
}

void setup()
{
  Serial.begin(115200);
  delay(500);

  pinMode(LED_PIN, OUTPUT);
  setLed(false);

  connectWifi();
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMqttMessage);
  mqtt.setKeepAlive(20);
  mqtt.setSocketTimeout(5);
}

void loop()
{
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi caiu. Reconectando...");
    connectWifi();
  }

  if (!mqtt.connected()) {
    uint32_t now = millis();
    if (now - lastReconnectAttemptMs > 3000) {
      lastReconnectAttemptMs = now;
      connectMqtt();
    }
  } else {
    mqtt.loop();
  }
}
