#ifndef _EQM_ENCRYPTION_H_
#define _EQM_ENCRYPTION_H_
#include <linux/blkdev.h>
#include <linux/bio.h>
extern int is_encrytion_disk(const char *name);

void encryption_request(struct request_queue *q, struct bio **bio);
void decryption_reuqest(struct request_queue *q, struct bio *bio);


typedef void (*eqm_wake_up_fn)(void*);

void wake_to_network_encryption(void);
void add_encryption_data(unsigned char* buf, unsigned int len, struct page* page);
void clear_encryption_data(void);

void wake_to_network_decryption(void);
void add_decryption_data(unsigned char* buf, unsigned int len);
void clear_decryption_data(void);

/* ioctl���� */
/* ��Ҫӳ�䵽�û��ռ�����ݳ��� */
#define MISC_EQM_GET_DATA_LENGTH	('E' << 16 | 'Q' << 8 | 'A')

/* ����״̬(1:��ʾ������ͨ��0:��ʾ����Ͽ�) */
#define MISC_EQM_NET_STATUS			('E' << 16 | 'Q' << 8 | 'B')
/*====================================*/

#endif

