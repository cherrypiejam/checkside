#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char test[7] = "test";
    const char* env = getenv("TOKEN");

    char guess[7], secret[7] = "secret";
    fgets(guess, sizeof(guess), stdin);

    if (strncmp(env, test, strlen(test)) == 0) {
        if (strncmp(guess, secret, strlen(secret)) == 0) {
            printf("%d\n", 0);
            printf("success!\n");
        } else {
            printf("%d\n", 1);
            for (int i = 0; i < 10; i++) {
                i = i + 0;
            }
            printf("oops, wrong guess\n");
        }
    } else {
        printf("WTF\n");
    }
}
