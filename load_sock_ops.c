/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/types.h>

struct shared_use_st
{
	long key; //作为拥塞算法选择的key
	char text[10];
};

static void usage(char *pname)
{
	printf("USAGE:\n  %s [-l] <cg-path> <prog filename>\n", pname);
	printf("\tLoad and attach a sock_ops program to the specified "
		   "cgroup\n");
	printf("\tIf \"-l\" is used, the program will continue to run\n");
	printf("\tprinting the BPF log buffer\n");
	printf("\tIf the specified filename does not end in \".o\", it\n");
	printf("\tappends \"_kern.o\" to the name\n");
	printf("\n");
	printf("  %s -r <cg-path>\n", pname);
	printf("\tDetaches the currently attached sock_ops program\n");
	printf("\tfrom the specified cgroup\n");
	printf("\n");
	exit(1);
}
int change_hash(long key, char *congestion)
{

	printf("congestion：%s\n", congestion);
	int result;
	char s_value[10] = {0};
	strcpy(s_value, congestion);

	if (key > 65535)
	{
		printf("map_data:%d", map_data[0].fd);
		result = bpf_map_update_elem(map_data[1].fd, &key, &s_value, BPF_ANY);
	}
	else
	{
		printf("map_data:%d", map_data[0].fd);
		result = bpf_map_update_elem(map_data[0].fd, &key, &s_value, BPF_ANY);
	}
	if (result == 0)
		printf("Map updated with new element\n");
	else
		printf("Failed to update map with new value: %d (%s)\n", result, strerror(errno));
	return 0;
}

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};

int sem_id;

void sem_init(int semid, int nsignum, int sem_value)
{
	union semun sem_union;
	sem_union.val = sem_value;
	if (semctl(semid, nsignum, SETVAL, sem_union) == -1)
	{
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

void read_mem_and_change(void)
{
	printf("enter read_mem_and_change\n");
	struct shared_use_st *shared = NULL;
	int shm_id;
	key_t shm_key = (key_t)5161;
	key_t sem_key = (key_t)5162;

	shm_id = shmget(shm_key, 1028, IPC_CREAT | 0644);
	void *shm_addr = shmat(shm_id, NULL, 0);
	shared = (struct shared_use_st *)shm_addr;
	//memset(shm_addr, 0, 128);

	sem_id = semget(sem_key, 2, IPC_CREAT | 0644);
	if (sem_id == -1)
	{
		perror("semget");
		exit(EXIT_FAILURE);
	}
	else
	{
		sem_init(sem_id, 0, 0); // init read semaphore
		sem_init(sem_id, 1, 1); // init  write semaphore
	}

	while (1) //read
	{
		sem_p(sem_id, 0);
		printf("pid %d key:%ld data: %s\n", getpid(), shared->key, shared->text);
		change_hash(shared->key, shared->text);
		sem_v(sem_id, 1);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int logFlag = 0;
	int error = 0;
	char *cg_path;
	char fn[500];
	char *prog;
	int cg_fd;
	if (argc < 3)
		usage(argv[0]);

	if (!strcmp(argv[1], "-r"))
	{
		cg_path = argv[2];
		cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
		error = bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
		if (error)
		{
			printf("ERROR: bpf_prog_detach: %d (%s)\n",
				   error, strerror(errno));
			return 2;
		}
		return 0;
	}
	else if (!strcmp(argv[1], "-h"))
	{
		usage(argv[0]);
	}
	else if (!strcmp(argv[1], "-l"))
	{
		logFlag = 1;
		if (argc < 4)
			usage(argv[0]);
	}

	prog = argv[argc - 1];
	cg_path = argv[argc - 2];
	if (strlen(prog) > 480)
	{
		fprintf(stderr, "ERROR: program name too long (> 480 chars)\n");
		return 3;
	}
	cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);

	if (!strcmp(prog + strlen(prog) - 2, ".o"))
		strcpy(fn, prog);
	else
		sprintf(fn, "%s_kern.o", prog);
	if (logFlag)
		printf("loading bpf file:%s\n", fn);
	if (load_bpf_file(fn))
	{
		printf("ERROR: load_bpf_file failed for: %s\n", fn);
		printf("%s", bpf_log_buf);
		return 4;
	}
	if (logFlag)
		printf("TCP BPF Loaded %s\n", fn);

	error = bpf_prog_attach(prog_fd[0], cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (error)
	{
		printf("ERROR: bpf_prog_attach: %d (%s)\n",
			   error, strerror(errno));
		return 5;
	}
	else if (logFlag)
	{
		int ret_from_fork;
		if ((ret_from_fork = fork()) == -1)
		{
			perror("fork");
			exit(EXIT_FAILURE);
		}
		else if (ret_from_fork == 0)
		{

			read_mem_and_change();
		}
		else
		{
			printf("enter read trace pip\n");
			read_trace_pipe();
		}
	}

	return error;
}
