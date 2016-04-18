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

/* ioctl命令 */
/* 获取数据大小 */
#define MISC_EQM_GET_DATA_LENGTH	('E' << 16 | 'Q' << 8 | 'A')

/* 网络状态(1:表示网络连通；0:表示网络断开) */
#define MISC_EQM_NET_STATUS			('E' << 16 | 'Q' << 8 | 'B')

/* 加解密失败用消息通知kernel，参数arg为错误码*/
#define MISC_EQM_ENCRYPTION_FAILED	('E' << 16 | 'Q' << 8 | 'C')

/* 映射完成 */
#define MISC_EQM_MMAP_COMPLETE	('E' << 16 | 'Q' << 8 | 'D')

/* 获取PAGE_SIZE大小 */
#define MISC_EQM_GET_PAGE_SIZE	('E' << 16 | 'Q' << 8 | 'E')

/* 获取磁盘分区 */
#define MISC_EQM_GET_DISK_PARTITION ('E' << 16 | 'Q' << 8 | 'F')
/*====================================*/

#endif

