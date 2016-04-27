#ifndef _EQM_ENCRYPTION_H_
#define _EQM_ENCRYPTION_H_
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <asm/io.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/syscalls.h>
#define MISC_EQM_ENCRYPTION_NAME  "eqm-encryption"
#define MISC_EQM_DECRYPTION_NAME  "eqm-decryption"

struct eqm_data {
	struct page* 		ppage;
	unsigned int 		len;
	unsigned int 		offset;
	int 				err_code;
}; 

struct eqm_data_info{
	unsigned int 		len;
	unsigned int 		offset;
};
extern int is_encrytion_disk(const char *name);

int encryption_request(struct request_queue *q, struct bio **bio);
int decryption_reuqest(struct request_queue *q, struct bio *bio);
 
typedef void (*eqm_wake_up_fn)(void*);

int send_encryption_data_to_network(struct page* ppage, unsigned int len,  unsigned int offset);
void clear_encryption_data(void);

int send_decryption_data_to_network(struct page* ppage, unsigned int len, unsigned int offset);
void clear_decryption_data(void);

int get_network_status(void);

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

#endif

