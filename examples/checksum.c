#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {

    char data[2];
    fgets(data, sizeof(data), stdin);

    int sum = 0;
    for (int i = 0; i < strlen(data); i++) {
    /* for (int i = 0; i < sizeof(data); i++) { */
        /* sum = 0xdeadbeef; */
        sum = 0xbadcace;
        sum += 1;
        sum += 1;
        /* sum += (int) data[i]; */
        /* sum %= 256; */
    }

    printf("%d", sum);

}
