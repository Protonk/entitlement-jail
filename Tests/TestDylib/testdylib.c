#include <stdio.h>

__attribute__((constructor))
static void init(void) {
    fprintf(stderr, "[testdylib] loaded\n");
}
