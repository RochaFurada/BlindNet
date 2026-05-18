#include "esp_err.h"

#include "cortex.h"

void app_main(void)
{
    ESP_ERROR_CHECK(blindnet_boot());
}
