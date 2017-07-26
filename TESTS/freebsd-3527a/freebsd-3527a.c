#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

struct knote {
  struct filterops *kn_fop;
};

struct file {
  int *f_ops;
};

struct filterops {
  int (*f_attach)(struct knote *kn);
  int (*f_event)(struct knote *kn, long hint);
}; 

static int badfileops = -1;
struct knote *kn;
static struct filterops *file_filtops;

//Normal fo_kqfilter() function
static int fo_kqfilter(struct knote *kn){
  return (1);
}

//badfo_kqfilter() function will be called after closing a file
static int badfo_kqfilter(struct knote *kn){
  return (0);
}

static int event(struct knote *kn, long hint){
  return (1);
}

//Set f_ops to badfileops when closing a file
static int vn_closefile(struct file *fp){
  fp->f_ops = &badfileops;
  file_filtops->f_attach = badfo_kqfilter;
  file_filtops->f_event = NULL;

  return (0);
}

//kqueue_register() will run f_event which is a function pointer
int kqueue_register(){
  int error, event;
  if ((error = kn->kn_fop->f_attach(kn)) != 0) {
    printf("No close happened!\n");
    return -1;
  }
  event = kn->kn_fop->f_event(kn, 0); // dangerous operation
  return 0;
}

//kern_kevent() will first check f_ops then call kqueue_register() function.
int kern_kevent(struct file *fp){
  int error;
  if (fp->f_ops == &badfileops){
    printf("file close first!\n");
    return -1;
  }
  sleep(1);
  error = kqueue_register();
  return 0;
}

int main()
{
  pthread_t thread1, thread2;
  struct file *fp;

  file_filtops = (struct filterops*)malloc(sizeof(struct filterops));
  file_filtops->f_attach = fo_kqfilter;
  file_filtops->f_event = event;

  kn = (struct knote*)malloc(sizeof(struct knote));
  kn->kn_fop = file_filtops;

  fp = (struct file*)malloc(sizeof(struct file));

  pthread_create (&thread1, NULL, (void *) &kern_kevent, (void *) fp);
  pthread_create (&thread2, NULL, (void *) &vn_closefile, (void *) fp);

  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  free(kn);
  free(fp);

  return 0;
}
