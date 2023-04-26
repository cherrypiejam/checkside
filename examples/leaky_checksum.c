#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {

    char data[8];
    fgets(data, sizeof(data), stdin);

    int sum = 0;
    for (int i = 0; i < strlen(data); i++) {
        sum += (int) data[i];
        sum %= 256;
    }

    printf("%d", sum);

}
