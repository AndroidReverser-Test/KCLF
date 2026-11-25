/* A bounded cooperative native target. The controller can terminate it sooner. */
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--exhaust-keys")) {
        pthread_key_t key;
        unsigned keys = 0;
        while (!pthread_key_create(&key, NULL)) keys++;
        printf("keys=%u\n", keys);
    }
    printf("pid=%d\n", getpid());
    fflush(stdout);
    struct timespec delay = {.tv_nsec = 100000000};
    for (int i = 0; i < 3000; i++) nanosleep(&delay, NULL);
    return 0;
}
