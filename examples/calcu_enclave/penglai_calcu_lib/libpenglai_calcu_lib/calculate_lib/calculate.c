#include "calculate.h"
#include <stdio.h>

int calcu_two_num(calcu_type_t type, int a, int b){
    int ret = 0;
    switch (type)
    {
    case ADD:
        ret = a + b;
        printf("%d add %d is %d.\n", a, b, ret);
        break;
    case MINOR:
        ret = a - b;
        printf("%d minor %d is %d.\n", a, b, ret);
        break;
    case MULTIPLY:
        ret = a * b;
        printf("%d multiply %d is %d.\n", a, b, ret);
        break;
    case DEVIDE:
        ret = a / b;
        printf("%d devide %d is %d.\n", a, b, ret);
        break;
    default:
        printf("This type isn't support.\n");
    }
    return ret;
}
