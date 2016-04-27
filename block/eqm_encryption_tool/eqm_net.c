#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <signal.h> 
#include <sys/param.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <time.h>
#include "eqm_socket.h"
#include "eqm.h"

#define HBMAXBUFLEN 9
#define HBCONTENT "OKCLIENT"



static struct server_addr g_encryption_server;
static struct server_addr g_decryption_server;
static struct server_addr g_hbtest_server;
static int g_flag = 1;

static void end_client_exit()
{
	set_network_status(0);
	PLog("[Info] [%s] client exit.\n ", __func__);
	g_flag = 0;	
}


int network_init(int argc, char** argv)
{
	int ret = 0;
	char *encryption_saddr, *decryption_saddr, *hbtest_saddr;
     int encryption_sport, decryption_sport, hbtest_sport;
     struct addr_info addr = {0};
     read_addr_info(argv, EQM_NETWORK_CONFIG, &addr);
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
#else
	 encryption_saddr = addr.server_ip;
     encryption_sport = addr.encryption_port;
     decryption_saddr = addr.server_ip;
     decryption_sport = addr.decryption_port;
     hbtest_saddr = addr.server_ip;
     hbtest_sport = addr.heartbeat_port;
#endif
	      /*change to deamon*/
     //xdaemon(0, 0, 0);
   //  signal(SIGHUP, end_client_exit);
    // signal(SIGINT, end_client_exit);
	// signal(SIGTERM, end_client_exit);
     
	/*init encryption and decryption server*/
	init_remote_server(&g_encryption_server, encryption_saddr, encryption_sport);
	init_remote_server(&g_decryption_server, decryption_saddr, decryption_sport);
	init_remote_server(&g_hbtest_server, hbtest_saddr, hbtest_sport);

	/*build connect to encryption and decryption server*/
	ret = open_remote_server(&g_encryption_server) ;
	if(ret < 0)
	{
		PLog("[Error] open_remote_server to build connect to encryption server failed.\n");	
		return -1;
	}
	
	ret = open_remote_server(&g_decryption_server) ;
	if(ret < 0)
	{
		close_remote_server(&g_encryption_server);
		PLog("[Error] open_remote_server to build connect to decryption server failed.\n");	
		return -1;
	}
	
	ret = open_remote_server(&g_hbtest_server) ;
	if(ret < 0)
	{
		close_remote_server(&g_encryption_server);
		close_remote_server(&g_decryption_server);
		PLog("[Error] open_remote_server to build connect to heartbeat server failed.\n");	
		return -1;
	}
	return 0;
}



static int hbtest_in_network(unsigned char *buf, int len)
{
	int ret;
	/*send to encrytion server*/
	PLog("hbtest send the buf is:%s\n", buf);
	ret = send_remote_server(&g_hbtest_server, buf, len);
	if(ret < 0)
	{
		PLog("send fail or no byte!");
		return ret;
	}
	
	ret = recv_remote_server(&g_hbtest_server, buf, len);
	if(ret < 0)
		PLog("recv fail!");	
	PLog("hbtest recv the buf is:%s\n", buf);	
	return ret;
}


int heartbeat_check(network_status fn)
{
	char hbbuf[HBMAXBUFLEN];
	int ret = 0;
	int status = 0;
			/*heart beat check of two server*/
	while(g_flag)
	{
		memset((void *)hbbuf, 0x00, sizeof(hbbuf));
		strcpy(hbbuf, HBCONTENT);
		ret = hbtest_in_network(hbbuf, strlen(hbbuf)+1);
		if(ret < 0) /* net error*/
			status = 0;
		else /*net OK*/
			status = 1; 
		
		fn(status);		
		//if(ret < 0)
		//	break;
		sleep(5);
	}
	return 0;
}

int network_close(void)
{
		/*close connect of two server*/
	close_remote_server(&g_encryption_server);
	close_remote_server(&g_decryption_server) ;
	close_remote_server(&g_hbtest_server) ;
	return 0;
}

int encryption_data_send_recv(unsigned char* buf, int len)
{
		int ret;
	/*send to encrytion server*/
	//PLog("encryption before the buf is:%c\n", buf[0]);
	ret = send_remote_server(&g_encryption_server, buf, len);
	if(ret < 0)
	{
		PLog("send fail or no byte!");
		return ret;
	}
	
	ret = recv_remote_server(&g_encryption_server, buf, len);
	if(ret < 0)
		PLog("recv fail!");	
	//PLog("encryption after the buf is:%c\n", buf[0]);	
	return ret;
}

int decryption_data_send_recv(unsigned char* buf, int len)
{
	int ret;
	/*send to encrytion server*/
	//PLog("decryption before the buf is:%c\n", buf[0]);
	ret = send_remote_server(&g_decryption_server, buf, len);
	if(ret < 0)
	{
		PLog("send fail or no byte!");
		return ret;
	}
	
	ret = recv_remote_server(&g_decryption_server, buf, len);
	if(ret < 0)
		PLog("recv fail!");	
	//PLog("decryption after the buf is:%c\n", buf[0]);	
	return ret;
}


