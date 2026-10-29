/* A deferred provider IFUNC must not silently disappear from the init vector. */
#include <stddef.h>
#include <string.h>
__attribute__((used, section(".init_array")))
size_t (*const invalid_initializer)(const char *) = strlen;
