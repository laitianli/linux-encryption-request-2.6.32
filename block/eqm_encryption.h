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
#include <linux/highmem.h>
#include <linux/kthread.h>
#define MISC_EQM_ENCRYPTION_NAME  "eqm-encryption"
#define MISC_EQM_DECRYPTION_NAME  "eqm-decryption"
#define EQM_ENCRYPTION_UNPLUG_TIMEOUT 100	/* 加密操作"泄流"超时时间(ms) */
#define EQM_ENCRYPTION_DATA_SIZE 	  32	/* 加密操作队列中bio请求个数 */
#define EQM_DECRYPTION_UNPLUG_TIMEOUT 20    /* 解密操作"泄流"超时时间(ms) */
#define EQM_DECRYPTION_DATA_SIZE 	  32	/* 解密操作队列中bio请求个数 */

#undef NLog
#undef ELog
#define ELog(fmt,arg...) printk(KERN_WARNING"[Encryption]=[%s:%d]="fmt"\n",__func__,__LINE__,##arg);
#define NLog(n,fmt,arg...)	do{	static int i = 0;if(i++ < n){printk(KERN_WARNING"[Encryption]=[%s:%d]="fmt"\n",__func__,__LINE__,##arg);}}while(0)
 

struct eqm_data {
	struct bio_vec* bi_io_vec;
	struct list_head entry_list;
};

struct eqm_data_info{
	unsigned char 		count;
	unsigned int 		len;
	unsigned int 		offset;
};
extern int is_encrytion_disk(const char *name);

int decryption_reuqest(struct request_queue *q, struct bio *bio);
 
typedef void (*eqm_wake_up_fn)(void*);
int send_decryption_data_to_network(struct bio* bio); 
int get_network_status(void);

typedef void generic_make_request_fn(struct bio *bio);
int encrytion_disk(struct bio* bio);
void encryption_make_request(struct bio *bio, generic_make_request_fn fn);
int send_encryption_data_to_network(struct bio* bio, generic_make_request_fn fn);


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

/* 获取磁盘分区，参数为磁盘设备，而非磁盘分区(如: /dev/sdb) */
#define MISC_EQM_GET_DISK_PARTITION ('E' << 16 | 'Q' << 8 | 'F')
/*====================================*/

#endif

