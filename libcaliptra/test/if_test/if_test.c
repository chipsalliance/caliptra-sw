//Licensed under the Apache-2.0 license

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "caliptra_api.h"

int main(int argc, char **argv)
{
    int r = caliptra_bootfsm_go();

    if (r)
    {
        printf("BOOTFSM_GO was not successful\n");
        return 1;
    }
    
    printf("OK\n");
    return 0;
}
