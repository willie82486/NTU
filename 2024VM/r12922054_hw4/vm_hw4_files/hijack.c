#include <stdio.h>
#include <string.h>

void victim_function() {
    printf("You failed Zzz...\n");
}

void target_function() {
    printf("Succeed! You've done it!\n");
}

int main() {

    printf("I'm going to overwrite the function located from the address %p to %p\n", victim_function, victim_function + 40 - 1);

    memcpy((void *)victim_function, (void *)target_function, 40);

    victim_function();

    return 0;
}
