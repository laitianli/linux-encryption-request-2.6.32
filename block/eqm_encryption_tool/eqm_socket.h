#ifndef _eqm_client_h_
#define _eqm_client_h_
/*
struct server_addr{
	struct sockaddr_in servaddr;
	int serverflag;
	int connfd;
};
*/
extern FILE* logfd;

#define PLog(fmt,arg...) do { \
	FILE* fd = logfd ? logfd : stdout;\
	fprintf(fd, "[%s:%d]="fmt"\n",__func__,__LINE__,##arg);\
	fflush(fd);\
}while(0)
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct server_addr{
	struct sockaddr_in servaddr;
	int listennfd;
	int connfd;
};

struct addr_info {
	char server_ip[20];
	int  encryption_port;
	int  decryption_port;
	int  heartbeat_port;
};

#define EQM_NETWORK_CONFIG "eqm_network.conf"

//public
pid_t xdaemon(int nochdir, int noclose, int exitflag);
int read_addr_info(char** argv,const char* config_name, struct addr_info *info);

//client
int init_remote_server(struct server_addr *server, char *saddr, int sport);

int open_remote_server(struct server_addr *server);

int send_remote_server(struct server_addr *server, char *buf, int len);

int recv_remote_server(struct server_addr *server, char *buf, int len);

void close_remote_server(struct server_addr *server);

//server
int init_server(struct server_addr *server, char *saddr, int sport);

int open_server(struct server_addr *server);

int server(struct server_addr *server, char *buf, int len, int (*processfunc)(unsigned char *buf, int len));

void close_server(struct server_addr *server);
#endif
