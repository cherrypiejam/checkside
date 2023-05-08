#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

#define KEY_SIZE  16
#define KEY_NAME  "TOKEN"
#define DATA_SIZE KEY_SIZE

int handle(uint8_t *data) {
    const uint8_t* key = (uint8_t *) getenv(KEY_NAME);
    uint8_t iv[] = "aaaaaaaaaaaaaaaa";

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, data, DATA_SIZE);

    return 0;
}

int main(int argc, char **argv) {
    char data[DATA_SIZE];
    fgets(data, sizeof(data), stdin);

    int err = handle((uint8_t *) data);

    if (!err) {
        printf("success!\n");
    } else {
        printf("error code %d :(", err);
    }
}
