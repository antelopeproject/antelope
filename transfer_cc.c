#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/in.h>
struct shared_use_st
{
    long key; //作为拥塞算法选择的key
    char text[10];
};
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short int *array;
    struct seminfo *__buf;
};

int sem_id = 0;
int shm_id = 0;
struct shared_use_st *shared = NULL;
char cong[5][9]={"bbr","cubic","illinois","c2tcp","westwood"};

void seminit(int semid, int nsignum, int sem_value)
{
    union semun sem_union;
    sem_union.val = sem_value;
    if (semctl(semid, nsignum, SETVAL, sem_union) == -1)
    {
        printf("init error\n");
        perror("semctl");
        exit(EXIT_FAILURE);
    }
}

void sem_p(int semid, int nsignum)
{
    struct sembuf sops;
    sops.sem_num = nsignum;
    sops.sem_op = -1;
    sops.sem_flg = SEM_UNDO;
    if (semop(sem_id, &sops, 1) == -1)
    {
        perror("semop");
        exit(EXIT_FAILURE);
    }
}
void sem_v(int semid, int nsignum)
{
    struct sembuf sops;
    sops.sem_num = nsignum;
    sops.sem_op = 1;
    sops.sem_flg = SEM_UNDO;
    if (semop(sem_id, &sops, 1) == -1)
    {
        perror("semop");
        exit(EXIT_FAILURE);
    }
}

void sem_print(int sem_id, int nsignum)
{
    int sem_value;
    sem_value = semctl(sem_id, nsignum, GETVAL);
    printf("sem[%d] = %d\n", nsignum, sem_value);
}
int init()
{
    printf("enter init\n");
    key_t shm_key = (key_t)5161;
    key_t sem_key = (key_t)5162;

    shm_id = shmget(shm_key, 1028, IPC_CREAT | 0644);
    void *shm_addr = shmat(shm_id, NULL, 0);
    shared = (struct shared_use_st *)shm_addr;
    //memset(shm_addr, 0, 128);

    sem_id = semget(sem_key, 2, IPC_CREAT | 0644);
    printf("sem_id:%d\n", sem_id);
    if (sem_id == -1)
    {
        sem_id = semget(sem_key, 2, 0644);
    }
    else
    {
        seminit(sem_id, 0, 0); // for read
        seminit(sem_id, 1, 1); // for write
    }

    return 0;
}

void updatehash(unsigned long key, char *val)
{
        char data[10] = {0};
        strcpy(data, val);
        sem_p(sem_id, 1);
        printf("parent data: %s\n", data);
        strcpy(shared->text, data);
        shared->key = key;
        sem_v(sem_id, 0);
        
    
}
//因为python无法向c传递long和string，于是就将long拆分后进行传输
 void updateCongHash(long pk, long beishu,long yushu, int pv,int ipv)
{
    printf("enter update cong hash\n");
     printf("pv:%d,ipv:%d,pk:%ld,beishu:%ld,yushu:%ld\n", pv,ipv,pk,beishu,yushu);
    if (sem_id == 0)
    {
        init();
    }
    printf("id: %d\n", sem_id);
    //char *val = (*env)->GetStringUTFChars(env, s,NULL);
    char *pval=cong[pv];
    char *ipval=cong[ipv];
    long ipk= beishu*1000+yushu;
    printf("ps:%s,ips:%s,pk:%ld,ipk:%lld\n", pval,ipval, (long)pk,ipk);
    updatehash((long)pk, pval);
    updatehash((unsigned long)ipk, ipval);
    return;
}