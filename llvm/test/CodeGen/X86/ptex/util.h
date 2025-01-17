extern void leak(void *);
extern void leak2(void *);
#define leak(x) ((leak)((void *) (x)))
#define leak2(x) ((leak2)((void *) (x)))
