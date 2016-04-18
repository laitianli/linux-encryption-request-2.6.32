#include "eqm.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <signal.h> 
#include <sys/param.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <time.h>

void init_deamon(void) 
{ 
    int pid; 
    int i;

    /* ����SIGCHLD�źš�����SIGCHLD�źŲ����Ǳ���ġ�������ĳЩ���̣��ر��Ƿ���������������������ʱ�����ӽ��̴���������������̲��ȴ��ӽ��̽������ӽ��̽���Ϊ��ʬ���̣�zombie���Ӷ�ռ��ϵͳ��Դ��*/
    if(signal(SIGCHLD,SIG_IGN) == SIG_ERR){
        printf("Cant signal in init_daemon.");
        exit(1);
    }
    if(pid=fork()) 
        exit(0);//�Ǹ����̣����������� 
    else if(pid< 0){ 
        perror("fail to fork1");
        exit(1);//forkʧ�ܣ��˳�
    }
    //�ǵ�һ�ӽ��̣���̨����ִ��
    setsid();//��һ�ӽ��̳�Ϊ�µĻỰ�鳤�ͽ����鳤 
    //��������ն˷��� 
    if(pid=fork()) 
        exit(0);//�ǵ�һ�ӽ��̣�������һ�ӽ��� 
    else if(pid< 0) 
        exit(1);//forkʧ�ܣ��˳� 
    //�ǵڶ��ӽ��̣����� 
    //�ڶ��ӽ��̲����ǻỰ�鳤 

    for(i=0;i< getdtablesize();++i)//�رմ򿪵��ļ������� 
        close(i); 
    chdir("/tmp");//�ı乤��Ŀ¼��/tmp 
    umask(0);//�����ļ�������ģ 
    return; 
}

void sigint_handler(int sig)
{
	
	exit(0); 
}

int setup_signal(void)
{
//	init_deamon();
	signal(SIGINT, &sigint_handler);

}