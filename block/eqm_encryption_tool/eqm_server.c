#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include "eqm_socket.h"
FILE* logfd = NULL;

#define MAXBUFLEN 512
#define HBMAXBUFLEN 9
#define HBCONTENT "OKSERVER"

static char *g_encryption_buf[MAXBUFLEN];
static char *g_decryption_buf[MAXBUFLEN];
static char *g_hbtset_buf[HBMAXBUFLEN];

pthread_t encryption_pid;
pthread_t decryption_pid;

static struct server_addr g_encryption_server;
static struct server_addr g_decryption_server;
static struct server_addr g_hbtest_server;

static int g_flag = 1;

static int encryption(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
 		buf[i] += 1;

	return len;
}

static int decryption(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
		buf[i] -= 1;
	return len;
}

static int hbtestupdate(unsigned char *buf, int len)
{
	strcpy(buf, HBCONTENT);
}

void* encryption_thread(void* data)
{
	while(g_flag)
		server(&g_encryption_server, (char *)g_encryption_buf, MAXBUFLEN, encryption);
	return NULL;
}


void* decryption_thread(void* data)
{
	while(g_flag)
		server(&g_decryption_server, (char *)g_decryption_buf, MAXBUFLEN, decryption);
	return NULL;
}

static void end_server_exit()
{
	g_flag = 0;	
}

int set_logfd(char* tag)
{
	int is_deamon = 0;
		if(tag && strlen(tag))
		is_deamon = atoi(tag);
	else 
		is_deamon = 0;

	if(is_deamon){
		logfd = fopen("/tmp/encryption_server.log", "a");
		if(!logfd)
			logfd = stdout;
	}
	else
		logfd = stdout;
	return is_deamon;
}

int main(int argc, char** argv)
{
	int ret = 0;
	char *encryption_saddr, *decryption_saddr, *hbtest_saddr;
     int encryption_sport, decryption_sport, hbtest_sport;

#if 0
     if(argc < 4)
     {
     	PLog("the argc is error! argc = %d", argc);
     	return -1;	
     }
     encryption_saddr = argv[1];
     encryption_sport = atoi(argv[2]);
     decryption_saddr = argv[3];
     decryption_sport = atoi(argv[4]);
     hbtest_saddr = argv[5];
     hbtest_sport = atoi(argv[6]);
     PLog("%s, %s,%s,%s,%s,%s\n", argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);	
#else
	 set_logfd(argv[1]);
	 struct addr_info addr = {0};
     read_addr_info(argv, EQM_NETWORK_CONFIG, &addr);
	 encryption_saddr = addr.server_ip;
     encryption_sport = addr.encryption_port;
     decryption_saddr = addr.server_ip;
     decryption_sport = addr.decryption_port;
     hbtest_saddr = addr.server_ip;
     hbtest_sport = addr.heartbeat_port;
#endif
     /*change to daemon*/
     //xdaemon(0, 0, 0);
  //   signal(SIGHUP, end_server_exit);
  //   signal(SIGINT, end_server_exit);
	//signal(SIGTERM, end_server_exit);
     
	/*init encryption, decryption server and hbtest server*/
	init_server(&g_encryption_server, encryption_saddr, encryption_sport);
	init_server(&g_decryption_server, decryption_saddr, decryption_sport);
	init_server(&g_hbtest_server, hbtest_saddr, hbtest_sport);
     
	/*build connect to encryption and decryption server*/
	ret = open_server(&g_encryption_server) ;
	if(ret < 0)
	{
		PLog("[Error] open_remote_server to build connect to encryption server failed.\n");	
		return -1;
	}
	
	ret = open_server(&g_decryption_server) ;
	if(ret < 0)
	{
		close_server(&g_encryption_server);
		PLog("[Error] open_remote_server to build connect to decryption server failed.\n");	
		return -1;
	}
	ret = open_server(&g_hbtest_server) ;
	if(ret < 0)
	{
		close_server(&g_encryption_server);
		close_server(&g_decryption_server);
		PLog("[Error] open_remote_server to build connect to heartbeat server failed.\n");	
		return -1;
	}
	/* create two thread */
	ret = pthread_create(&encryption_pid, NULL, encryption_thread, NULL);
	if(ret) {
		PLog("[Error] pthread_create encryption failed.\n");
		return -1;
	}

	ret = pthread_create(&decryption_pid, NULL, decryption_thread, NULL);
	if(ret) {
		PLog("[Error] pthread_create decryption failed.\n");
		return -1;
	}
	
	/*heart beat check of two server*/
	memset((char *)g_hbtset_buf, 0x00, HBMAXBUFLEN);
	strcpy((char *)g_hbtset_buf, HBCONTENT);
	while(g_flag)
	{
		server(&g_hbtest_server, (char *)g_hbtset_buf, HBMAXBUFLEN, hbtestupdate);
		PLog("hbtest send buf is:%s\n", g_hbtset_buf);
	}

	/* ²é¿´event_sd.c */
	pthread_join(encryption_pid, NULL);
	pthread_join(decryption_pid, NULL);
	
	/*close connect of two server*/
	close_server(&g_encryption_server);
	close_server(&g_decryption_server) ;
	close_server(&g_hbtest_server) ;
	fclose(logfd);
	return 0;
}
