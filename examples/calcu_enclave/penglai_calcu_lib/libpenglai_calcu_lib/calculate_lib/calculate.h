#ifndef __CALCULATE__
#define __CALCULATE__

typedef enum {
	ADD,
	MINOR,
    MULTIPLY,
    DEVIDE
} calcu_type_t;

int calcu_two_num(calcu_type_t type, int a, int b);

#endif
