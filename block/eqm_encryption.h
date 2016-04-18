#ifndef _EQM_ENCRYPTION_H_
#define _EQM_ENCRYPTION_H_
#include <linux/blkdev.h>
#include <linux/bio.h>

struct eqm_data {
	unsigned char* 		buf;
	unsigned int 		len;
	int 				err_code;
}; 
extern int is_encrytion_disk(const char *name);

int encryption_request(struct request_queue *q, struct bio **bio);
int decryption_reuqest(struct request_queue *q, struct bio *bio);
int decryption_reuqest_ex(struct request_queue *q, struct bio *bio);


typedef void (*eqm_wake_up_fn)(void*);

int send_encryption_data_to_network(unsigned char* buf, unsigned int len);
void clear_encryption_data(void);

int send_decryption_data_to_network(unsigned char* buf, unsigned int len);
void clear_decryption_data(void);

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

/* ��ȡ���̷��� */
#define MISC_EQM_GET_DISK_PARTITION ('E' << 16 | 'Q' << 8 | 'F')
/*====================================*/

#endif

