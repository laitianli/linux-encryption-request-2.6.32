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

/* ioctl命令 */
/* 需要映射到用户空间的数据长度 */
#define MISC_EQM_GET_DATA_LENGTH	('E' << 16 | 'Q' << 8 | 'A')

/* 网络状态(1:表示网络连通；0:表示网络断开) */
#define MISC_EQM_NET_STATUS			('E' << 16 | 'Q' << 8 | 'B')
/*====================================*/

#endif

