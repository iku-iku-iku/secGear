#include <stdio.h>

// [in, size=32]char *buf
int ocall_printf(char *buf)
{
    printf(buf);
}
