#ifndef _EQM_H_
#define _EQM_H_
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
#include <limits.h>
#include <sys/mount.h>
#include <signal.h>
extern FILE* logfd;

#define PLog(fmt,arg...) do { \
	FILE* fd = logfd ? logfd : stdout;\
	fprintf(fd, "[%s:%d]="fmt"\n",__func__,__LINE__,##arg);\
	fflush(fd);\
}while(0)


#define EQM_MOUNT_CONFIG	"eqm_fstab.conf"
#define EQM_DISK_NAME 		"/proc/encryption_disk_name"
#define EQM_ENCRYPTION_DEVICE "/dev/eqm-encryption"
#define EQM_DECRYPTION_DEVICE "/dev/eqm-decryption"
/* ioctl���� */
/* ��ȡ���ݴ�С */
#define MISC_EQM_GET_DATA_LENGTH	('E' << 16 | 'Q' << 8 | 'A')

/* ����״̬(1:��ʾ������ͨ��0:��ʾ����Ͽ�) */
#define MISC_EQM_NET_STATUS			('E' << 16 | 'Q' << 8 | 'B')

/* �ӽ���ʧ������Ϣ֪ͨkernel������argΪ������*/
#define MISC_EQM_ENCRYPTION_FAILED	('E' << 16 | 'Q' << 8 | 'C')

/* ӳ����� */
#define MISC_EQM_MMAP_COMPLETE	('E' << 16 | 'Q' << 8 | 'D')

/* ��ȡPAGE_SIZE��С */
#define MISC_EQM_GET_PAGE_SIZE	('E' << 16 | 'Q' << 8 | 'E')

/* ��ȡ���̷���������Ϊ�����豸�����Ǵ��̷���(��: /dev/sdb) */
#define MISC_EQM_GET_DISK_PARTITION ('E' << 16 | 'Q' << 8 | 'F')
/*====================================*/


typedef int (*encryption_fn)(unsigned char *buf, int len);
typedef int (*network_status)(int status);

struct eqm_data_info{
	unsigned char 		count;
	unsigned int 		len;
	unsigned int 		offset;
};
int read_mount_info(char** argv, const char* config_name);
/* ���ؼ����� */
int mount_encryption_disk(void); 

/* ж�ؼ����� */
int umount_encryption_disk(void);

int setup_signal(int is_deamon);

int get_disk_partition(const char *fullname);

/* ��������״̬ */
int set_network_status(int status);

int network_init(int argc, char** argv);

int heartbeat_check(network_status fn);

int network_close(void);

int encryption_data_send_recv(unsigned char* buf, int len);

int decryption_data_send_recv(unsigned char* buf, int len);
#endif

