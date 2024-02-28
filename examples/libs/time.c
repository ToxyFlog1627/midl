#include "time.h"
#include "syscall.h"

long int time;

void update_time() {
    timeval tv;
    timezone tz;
    gettimeofday(&tv, &tz);
    time = tv.sec;
}

// called via init mechanism
void initialize_time() { update_time(); }