#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <syscall.h>

static int status = 0;

static int counter;
static pthread_mutex_t m;

void * increment(void *arg) {
try_again:
	if (!status) {
		sleep(1);
		printf("[%lu] Trying again...\n", syscall(SYS_gettid));
		goto try_again;
	}

	pthread_mutex_lock(&m);
	counter++;
	pthread_mutex_unlock(&m);

	return NULL;
}

void * set_status(void *val) {
	printf("[%lu] Setting status = 1\n", syscall(SYS_gettid));
	status = *(int *)val;
	return NULL;
}

int main() {
	pthread_t t1, t2, t3, t4, t5;

	pthread_create(&t1, NULL, increment, NULL);
	pthread_create(&t2, NULL, increment, NULL);
	pthread_create(&t3, NULL, increment, NULL);

	printf("counter=%d\n", counter);

	sleep(2);
	//getchar();
	int temp = 1;
	pthread_create(&t4, NULL, set_status, &temp);
	sleep(1);
	pthread_create(&t5, NULL, set_status, &temp);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	pthread_join(t3, NULL);
	pthread_join(t4, NULL);
	pthread_join(t5, NULL);

	printf("counter=%d\n", counter);

	return 0;
}










