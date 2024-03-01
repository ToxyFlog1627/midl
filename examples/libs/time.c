#include "time.h"
#include "syscall.h"

long int utime;

void update_time() {
    timeval tv;
    timezone tz;
    gettimeofday(&tv, &tz);
    utime = tv.usec;
}

// called via init mechanism
void initialize_time() { update_time(); }