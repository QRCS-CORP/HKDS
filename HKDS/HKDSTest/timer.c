#include "timer.h"

clock_t hkdstest_timer_start()
{
	clock_t start;

	start = clock();

	return start;
}

uint64_t hkdstest_timer_elapsed(clock_t start)
{
	clock_t diff;
	uint64_t msec;

	diff = clock() - start;
	msec = (diff * 1000) / CLOCKS_PER_SEC;

	return msec;
}