#include <stdio.h>      /* Input/Output */
#include <stdlib.h>     /* General Utilities */
#include <pthread.h>    /* POSIX Threads */
#include <unistd.h>

struct vnode{
  int *v_rdev;
};

struct file{
  int f_ops;
  struct vnode *f_vnode;
};

int i = 10;
int devfs_ops_f = 100;
struct vnode *g_vp;

//Use f_vnode in this function
static int devfs_kqfilter_f(struct file *fp){
  int error = devfs_fp_check(fp);
  return error;
}

int devfs_fp_check(struct file *fp){
  int dswp = devvn_refthread(fp->f_vnode);
  return 0;
}

int devvn_refthread(struct vnode *vp){
  int *devp;
  devp = vp->v_rdev; // dangerous operation
  printf("read fp: %d \n", *devp);
  return 0;
}

//Assign non-zero value to f_ops and allocate a vnode for this opening file
static int devfs_open(struct file *fp){
  fp->f_ops = devfs_ops_f;
  fp->f_vnode = g_vp;

  return 0;
}

//Set f_vnode to NULL initially
void falloc(struct file *fp){
  fp->f_ops = 0;
  int local_i = 10;
  fp->f_vnode = &local_i;
}

int main(){
  pthread_t thread1, thread2;
  struct file *fp = (struct file*) malloc(sizeof(struct file));

  g_vp = (struct vnode*)malloc(sizeof(struct vnode));
  g_vp->v_rdev = &i;

  falloc(fp);

  pthread_create (&thread1, NULL, (void *) &devfs_kqfilter_f, (void *) fp);
  pthread_create (&thread2, NULL, (void *) &devfs_open, (void *) fp);

  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  free(fp);
  return 0;

}
