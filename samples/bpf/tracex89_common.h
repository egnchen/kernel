#ifndef _TRACEX8_COMMON_H
#define _TRACEX8_COMMON_H

#define NR_ARGUMENTS 6

#define REWRITE_ARBITRARY 1
#define REWRITE_UPPER_BOUND 2

struct arg_rewrite_rule {
    // explicitly handle padding here
    unsigned char rewrite[(NR_ARGUMENTS + 7) / 8 * 8];
    unsigned long val[NR_ARGUMENTS];
};

#define KEY_LEN 32
#define VALUE_LEN sizeof(struct arg_rewrite_rule)
#define MAX_ENTRIES 128


#endif