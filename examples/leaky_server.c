#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_SIZE 1
#define TOKEN_NAME "TOKEN"
#define DATA_SIZE  TOKEN_SIZE

int handle(char *data) {
    const char* token = getenv(TOKEN_NAME);
    int sum = 0;
    for (int i = 0; i < TOKEN_SIZE; i++) {
        for (int j = 0; j < 2; j++) {
            if (token[i] & 1 << j) {
                sum += (int) data[0];
            }
        }
    }
    FILE * fp = fopen("datasum", "w");
    fprintf(fp, "%d", sum);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    char data[DATA_SIZE];
    fgets(data, sizeof(data), stdin);

    int err = handle(data);

    if (!err) {
        printf("success!\n");
    } else {
        printf("error code %d :(", err);
    }
}
