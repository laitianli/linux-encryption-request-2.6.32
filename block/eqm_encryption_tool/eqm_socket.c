#include <stdio.h>
#include <errno.h>
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
#include "eqm_socket.h"


pid_t xdaemon(int nochdir, int noclose, int exitflag)
{
	pid_t pid;

	/* In case of fork is error. */
	pid = fork();
	if (pid < 0) {
		PLog("xdaemon: fork error");
		return -1;
	}

	/* In case of this is parent process. */
	if (pid != 0) {
		if (!exitflag)
			exit(0);
		else
			return pid;
	}

	/* Become session leader and get pid. */
	pid = setsid();
	if (pid < -1) {
		PLog("xdaemon: setsid error");
		return -1;
	}

	/* Change directory to root. */
	if (!nochdir)
		chdir("/");

	/* File descriptor close. */
	if (!noclose) {
		int fd;

		fd = open("/dev/null", O_RDWR, 0);
		if (fd != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > 2)
				close(fd);
		}
	}

	umask(0);
	return 0;
}


int read_addr_info(char** argv,const char* config_name, struct addr_info *info)
{
	if(!config_name || !argv || !info) {
		PLog("[Error] config name is null\n");
		return -1;
	}
	char exe_path[1024] = {0}, config_path[1024] = {0};
	strncpy(exe_path, argv[0], strlen(argv[0]));
	char*pp = exe_path;
	char* qq = NULL;
	while(( pp = strstr(pp, "/")) != NULL)
	{
		qq = pp++;
	}
	*qq = '\0';

	sprintf(config_path, "%s/%s", exe_path, config_name);
	FILE* pf = fopen(config_path, "r");
	if (pf <= 0) {
		PLog("[error] open file [%s] failed.\n", config_path);
		return -1;
	}
	char *p = NULL, *q = NULL;
	char resultbuf[1024] = {0};
	int i = 0;
#define IP_ATTR "service_ip="
#define ENCRYPTION_ATTR "encryption_port="
#define DECRYPTION_ATTR "decryption_port="
#define HEARTBEAT_ATTR "heartbeat_port="
	while(fgets(resultbuf, sizeof(resultbuf) - 1, pf) != NULL )
	{
		if(resultbuf[0] == '#')
			continue;
		 if(strncmp(resultbuf, IP_ATTR, strlen(IP_ATTR))==0)		 	
			sscanf(resultbuf, IP_ATTR"%s", info->server_ip);
		 else if(strncmp(resultbuf, ENCRYPTION_ATTR, strlen(ENCRYPTION_ATTR))==0)
		 	sscanf(resultbuf, ENCRYPTION_ATTR"%d", &info->encryption_port);
		 else if(strncmp(resultbuf, DECRYPTION_ATTR, strlen(DECRYPTION_ATTR))==0)
		 	sscanf(resultbuf, DECRYPTION_ATTR"%d", &info->decryption_port);
		  else if(strncmp(resultbuf, HEARTBEAT_ATTR, strlen(HEARTBEAT_ATTR))==0)
		 	sscanf(resultbuf, HEARTBEAT_ATTR"%d", &info->heartbeat_port);
		memset(resultbuf, 0, sizeof(resultbuf));
		//PLog("%s:%s:%s\n", g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		//i++;
	}
	PLog("ip_info: %s:%d:%d:%d\n",
		info->server_ip,info->encryption_port, info->decryption_port, info->heartbeat_port);
	fclose(pf);
}

//client 
int init_remote_server(struct server_addr *server, char *saddr, int sport)
{
	bzero(&server->servaddr, sizeof(struct sockaddr_in));
     server->servaddr.sin_family = AF_INET;
     server->servaddr.sin_port = htons(sport);
     inet_pton(AF_INET, saddr, &server->servaddr.sin_addr);
     return 0;	
}

int open_remote_server(struct server_addr *server)
{
   int ret;
   int connfd;
   if(!server)
   		return -1;
   
   connfd = socket(AF_INET, SOCK_STREAM, 0);

    if (connect(connfd, (struct sockaddr *) &server->servaddr, sizeof(struct sockaddr)) < 0) {
        perror("connect error");
        return -1;
    }
    server->connfd = connfd;
    PLog("welcome to echoclient\n");
    return 0;
}

int send_remote_server(struct server_addr *server, char *buf, int len)
{
	int n;
	int count;
	count = 0;
	do{
		n = write(server->connfd, buf+count, len-count);
		if(n < 0)
		{
			perror("write message fail!\n");
			return -1;
		}
		count += n;
	}while(len - count > 0);
	
	return count;
}

int recv_remote_server(struct server_addr *server, char *buf, int len)
{
	int n;
	int count;
	count = 0;
	do{
		n = read(server->connfd, buf+count, len-count);
		if(n < 0)
		{
			perror("recv message fail!\n");
			return -1;
		}
		count += n;
	}while(len - count > 0);
	
	return count;

}

void close_remote_server(struct server_addr *server)
{
	if(server->connfd > 0)
	{
		//flush(server->connfd);
		close(server->connfd);
		PLog("close connfd:%d\n",server->connfd);	
	}
}


// server below
int init_server(struct server_addr *server, char *saddr, int sport)
{
	bzero(&server->servaddr, sizeof(struct sockaddr_in));
     server->servaddr.sin_family = AF_INET;
     //server->servaddr.sin_addr.s_addr = htonl(saddr);
     server->servaddr.sin_port = htons(sport);
     inet_pton(AF_INET, saddr, &server->servaddr.sin_addr);
     return 0;	
}

int open_server(struct server_addr *server)
{
   int ret;
   int listenfd, connfd;
   
   if(!server)
   		return -1;
   listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("socket error");
        return -1;
    }
    if (bind(listenfd, (struct sockaddr *)&server->servaddr, sizeof(struct sockaddr)) < 0) {
        perror("bind error");
        return -1;
    }
    if (listen(listenfd, 1024) < 0) {
        perror("listen error");    
        return -1;
    }
    server->listennfd = listenfd;
    PLog("echo server startup,listen on port:%d\n", server->servaddr.sin_port);
    
    return 0;
}

int server(struct server_addr *server, char *buf, int len, int (*processfunc)(unsigned char *buf, int len))
{
	int connfd;
	int socklen;
	int ret;
	
	socklen = sizeof(struct sockaddr_in);
     connfd = accept(server->listennfd, (struct sockaddr *)&server->servaddr, &socklen);
     if (connfd < 0) {
        perror("accept error");
        return -1;
     }
     //PLog( "accept form %s:%d\n", inet_ntoa(server->servaddr.sin_addr), server->servaddr.sin_port);
     ret = 0;
     while(1)
     {
        ret = read(connfd, buf, len);
        if (ret < 0) {
           // if(ret != EINTR) {
                PLog("read error");
                break;
           // }
        }
        if (ret == 0) {
        	 PLog("client already close.\n");
          break;
        }
        if(processfunc != NULL)
        		processfunc(buf, ret);
       ret = write(connfd, buf, ret); //write maybe fail,here don't process failed error	
     }
     
     close(connfd);
     return ret;
}

void close_server(struct server_addr *server)
{
	if(server->listennfd > 0)
	{
		close(server->listennfd);	
	}
}
