/******
 * ʵ��bio����ļӽ��ܹ���
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include "eqm_encryption.h"

#define LOCAL_ENCRYPTION_ALGORITHM 0 /*�Ƿ�ʹ�ñ����㷨*/

static struct task_struct* decryption_thread_handle = NULL;
static spinlock_t g_thread_spinlock;
static LIST_HEAD(read_bio_list);

#undef NLog
#undef ELog
#define ELog(fmt,arg...) printk(KERN_WARNING"[Encryption]=[%s:%d]="fmt"\n",__func__,__LINE__,##arg);
#define NLog(n,fmt,arg...)	do{	static int i = 0;if(i++ < n){printk(KERN_WARNING"[Encryption]=[%s:%d]="fmt"\n",__func__,__LINE__,##arg);}}while(0)

#if LOCAL_ENCRYPTION_ALGORITHM > 0
static char* encryption(unsigned char *buf, int len);
static char* decryption(unsigned char *buf, int len);
#else
static int encryption_in_network(struct request_queue* q, struct bio* bio);
static int decryption_in_network(struct request_queue* q, struct bio* bio);
#endif
static int be_encryption_disk(const char* partition_name);
static void add_bio_to_list(struct bio* bio);

static int be_encryption_disk(const char* partition_name)
{
#if 0
	if( !strcmp(partition_name,"sdb")  || 
		!strcmp(partition_name,"sdb1") ||
		!strcmp(partition_name,"sdb2") ||
		!strcmp(partition_name,"sdb3") ||
		!strcmp(partition_name,"sdb4") ||
		!strcmp(partition_name,"sdc")  ||
		!strcmp(partition_name,"sdc1") ||
		!strcmp(partition_name,"sdc2") ||
		!strcmp(partition_name,"sdc3"))
		return 1;
	
	return 0;
#else
	return is_encrytion_disk(partition_name);
#endif
} 
/**ltl
 * ����: ����дbio�������ɻص�������
 * ����: bio	-> bio�������
 *	    err	-> ������
 * ����ֵ: ��
 * ˵��: �����������������ɺ����
 */
static void encryption_end_io_write(struct bio *bio, int err)
{
	struct bio *bio_orig = bio->bi_private;
	struct bio_vec *bvec, *org_vec;
	int i;
	/* �ͷż���bio�����ÿ��page */
 	__bio_for_each_segment(bvec, bio, i, 0) {
		org_vec = bio_orig->bi_io_vec + i;
		__free_page(bvec->bv_page);
	} 
	kfree(bio->bi_private1);
	bio->bi_private1 = NULL;
	bio_orig->bi_private1 = NULL;
	/* �������ǰ��bio����ɴ����� */
	bio_endio(bio_orig, err);
	bio_put(bio); /* �ͷ�bio���� */
}
 
/**ltl
 * ����: ����bio����
 * ����: q	-> ������ж���
 *	    org_bio->bio����
 * ����ֵ: �µ�bio����
 * ˵��: ��дbio����Ŀ����ӿ�
 */
static struct bio* copy_bio(struct request_queue *q, struct bio* org_bio,
		bio_end_io_t* end_bio_fun)
{
	struct bio_vec *to, *from;
	int i, rw = bio_data_dir(org_bio); 
	char *vto, *vfrom;	
	unsigned int cnt = org_bio->bi_vcnt;
	/* ����bio���� */
	struct bio* bio = bio_alloc(GFP_NOIO, cnt);
	if (!bio)
		return org_bio;
	memset(bio->bi_io_vec, 0, cnt * sizeof(struct bio_vec));
	/* ����bio,���������ݺ����� */
	bio_for_each_segment(from, org_bio, i) {		
		to = bio->bi_io_vec + i;
		to->bv_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		to->bv_len = from->bv_len;
		to->bv_offset = from->bv_offset;
		
		flush_dcache_page(from->bv_page);
		vto = page_address(to->bv_page) + to->bv_offset;
		if(rw == WRITE) {/* ֻ�ж������ſ������� */
			/* page�ڸ߶��ڴ��� */
			if (page_to_pfn(from->bv_page) > queue_bounce_pfn(q)) 
				vfrom = kmap(from->bv_page) + from->bv_offset;
			else /* page�ڵ׶��ڴ��� */
				vfrom = page_address(from->bv_page) + from->bv_offset;
			memcpy(vto, vfrom, to->bv_len); /* �������� */
			if (page_to_pfn(from->bv_page) > queue_bounce_pfn(q))
				kunmap(from->bv_page);
		}
	}
	/* �������� */
	bio->bi_bdev = org_bio->bi_bdev;
	bio->bi_flags = org_bio->bi_flags;
	bio->bi_sector = org_bio->bi_sector;
	bio->bi_rw = org_bio->bi_rw;

	bio->bi_vcnt = org_bio->bi_vcnt;
	bio->bi_idx = org_bio->bi_idx;
	bio->bi_size = org_bio->bi_size;
	bio->bi_end_io = end_bio_fun;
	bio->bi_private = org_bio;
	bio->bi_private1 = org_bio->bi_private1;
	return bio;
	
}
/**ltl
 * ����:д������ܽӿ�
 * ����: q	-> ������ж���
 *		bio	->[in] bioд������� ; [out] �������ɵ��Ѿ������ܹ�������
 * ����ֵ: ��
 * ˵��: 1. copy bio�����С�
 */
int encryption_request(struct request_queue *q, struct bio **bio)
{	
	int err_code = 0;
	struct bio *new_bio = NULL; /* ������Ҫ���´���һ��bio�����ײ㴦�� */	
	char b[BDEVNAME_SIZE]={0}; 
	
 	if ((*bio)->bi_private1) /* ���Ѿ����ܹ� */
 		return err_code;

	/* �Ƿ�����Ҫ���ܵĴ��� */
	if(!(*bio)->bi_bdev || 
		!(bdevname((*bio)->bi_bdev, b) && strlen(b))|| 
		!be_encryption_disk(b))
		return err_code;
	
	/* ��������̵ķ����� */
	(*bio)->bi_private1 = kzalloc(BDEVNAME_SIZE, GFP_KERNEL);
	if(!(*bio)->bi_private1)
		return -EIO;
	strncpy((char*)((*bio)->bi_private1), b, BDEVNAME_SIZE-1);
	
	if(bio_data_dir(*bio) != WRITE)
	{/* �����̵Ķ����� */ 
		return 0; /* ���ܵ����Ǵ���Ĳ������Զ����� */
	}
	
	/*д���� */
	/* ����bio���� */
	new_bio = copy_bio(q, *bio, encryption_end_io_write);
	if(new_bio == *bio)
		return err_code;
	NLog(30,"begin encryption disk: %s", b);
#if LOCAL_ENCRYPTION_ALGORITHM > 0	
	struct bio_vec *from;
	struct page *page;
	unsigned char* buf = NULL;
	int i = 0;
	bio_for_each_segment(from, new_bio, i) { 
		page = from->bv_page;
 		/* page�ڸ߶��ڴ��� */
		if (page_to_pfn(page) > queue_bounce_pfn(q))
			buf = kmap(page) + from->bv_offset;
		else /* page�ڵ׶��ڴ��� */
			buf = page_address(page) + from->bv_offset;
		/* ��buf���� */
		encryption(buf, from->bv_len);	
	}
	err_code = 0;
//	return 0;
#else
	err_code = encryption_in_network(q, new_bio);
	if(err_code) {
		encryption_end_io_write(new_bio, -EIO);
	}
#endif
	/* �����ܹ���bio���󷵻� */
	*bio = new_bio; 
	return err_code;
}

/**ltl
 * ����: ��������ܽӿ�
 * ����: q	->������ж���
 *		bio	->bio���������
 * ����ֵ:��
 * ˵��: ����bio�����е�ÿһpage����page�е����ݽ���
 */
int decryption_reuqest(struct request_queue *q, struct bio *bio)
{
	 /* �Ƿ��Ƕ����� */
	if(bio_data_dir(bio) != READ || 
		!bio->bi_private1 || 
		!be_encryption_disk(bio->bi_private1)) /* �Ƿ�����Ҫ���ܵĴ��� */
		return 0; 
	
	NLog(30,"decryption disk: %s", (const char*)(bio->bi_private1));
	kfree(bio->bi_private1);
	bio->bi_private1 = NULL;
	/* ��bio�е��������ݽ��ܴ��� */
#if LOCAL_ENCRYPTION_ALGORITHM > 0	
	struct bio_vec *from;
	struct page *page;
	unsigned char* buf = NULL;
	int i = 0;
	bio_for_each_segment(from, bio, i) {
		page = from->bv_page;
		flush_dcache_page(page);
		/* page�ڸ߶��ڴ��� */
		if (page_to_pfn(page) > queue_bounce_pfn(q))
			buf = kmap(page) + from->bv_offset;
		else /* page�ڵ׶��ڴ��� */
			buf = page_address(page) + from->bv_offset;
		/* buf���� */
		decryption(buf, from->bv_len);	
	}	
	return 0;
#else
	return decryption_in_network(q, bio);
#endif
	
}

int decryption_reuqest_ex(struct request_queue *q, struct bio *bio)
{
	 /* �Ƿ��Ƕ����� */
	if(bio_data_dir(bio) != READ || 
		!bio->bi_private1 || 
		!be_encryption_disk(bio->bi_private1)) /* �Ƿ�����Ҫ���ܵĴ��� */
		return 0; 
	
	//NLog(300,"decryption disk: %s", (const char*)(bio->bi_private1));
	kfree(bio->bi_private1);
	bio->bi_private1 = NULL;

	/* ��bio���뵽bio�б��У������̴߳���ͬʱ����fn�ӿ� */
	add_bio_to_list(bio);
	return 1;//decryption_in_network(q, bio);
}
EXPORT_SYMBOL(encryption_request);
EXPORT_SYMBOL(decryption_reuqest);
EXPORT_SYMBOL(decryption_reuqest_ex);

#if LOCAL_ENCRYPTION_ALGORITHM > 0	
/**ltl
 * ����:�����㷨�ӿ�
 * ����:
 * ����ֵ:
 * ˵��: ����������+1
 */
static int encryption(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
 		buf[i] += 1;

	return len;
}
/**ltl
 * ����:�����㷨�ӿ�
 * ����:
 * ����ֵ:
 * ˵��: ����������-1
 */
static int decryption(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
		buf[i] -= 1;
	return len;
}
#else
static int encryption_in_network(struct request_queue* q, struct bio* bio)
{
	struct bio_vec *from;
	struct page *page;
	struct bio *new_bio = bio; /* ������Ҫ���´���һ��bio�����ײ㴦�� */
	unsigned char* buf = NULL;
	int i = 0, err_code = 0;
	bio_for_each_segment(from, new_bio, i) { 
		page = from->bv_page;
 		/* page�ڸ߶��ڴ��� */
		if (page_to_pfn(page) > queue_bounce_pfn(q))
			buf = kmap(page) + from->bv_offset;
		else /* page�ڵ׶��ڴ��� */
			buf = page_address(page) + from->bv_offset;
		/* ����Ҫ���ܵ����ݼ��뵽�б���, �����û�����ȥ��ȡ���ݣ������ܴ��� */
		err_code = send_encryption_data_to_network(buf, from->bv_len);
		if(err_code) {
			printk(KERN_ERR"[Error] encryption the data fail. it's possible the network error.\n");
			return err_code;
		}
	} 
	return 0;
}

static int decryption_in_network(struct request_queue* q, struct bio* bio)
{
	struct bio_vec *from;
	struct page *page;
	unsigned char* buf = NULL;
	int i = 0, err_code = 0;

	bio_for_each_segment(from, bio, i) {
		page = from->bv_page;
		
		flush_dcache_page(page);

		/* page�ڸ߶��ڴ��� */
		if (page_to_pfn(page) > queue_bounce_pfn(q))
			buf = kmap(page) + from->bv_offset;
		else /* page�ڵ׶��ڴ��� */
			buf = page_address(page) + from->bv_offset;

		/* ����Ҫ���ܵ����ݼ��뵽�б���,�����û�����ȥ��ȡ���ݣ������ܴ���  */
		err_code = send_decryption_data_to_network(buf, from->bv_len);	
		if(err_code) {
			printk(KERN_ERR"[Error] decryption the data fail. it's possible the network error.\n");
			return err_code;
		}
	}
	return 0;
}

#endif
static void add_bio_to_list(struct bio* bio)
{
	INIT_LIST_HEAD(&bio->list);
	spin_lock(&g_thread_spinlock);
	list_add_tail(&bio->list, &read_bio_list);
	wake_up_process(decryption_thread_handle);	
	spin_unlock(&g_thread_spinlock);

}
static int decryption_request_handler(void *data)
{
	int err_code = 0;
	struct list_head local_list;
	struct request_queue* q = NULL;	
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
			
			if(list_empty(&read_bio_list))
			{
				schedule();
				set_current_state(TASK_INTERRUPTIBLE);
				continue;
			}

			__set_current_state(TASK_RUNNING);		
	
			spin_lock(&g_thread_spinlock);
			list_replace_init(&read_bio_list, &local_list);
			spin_unlock(&g_thread_spinlock); 			
			while (!list_empty(&local_list)) {	
				/*do bio*/
				struct bio *bio;
				bio = list_entry(local_list.next, struct bio, list);
				list_del_init(&bio->list);
				q = bio->bi_bdev->bd_disk->queue;
				err_code = 0;

				
				err_code = decryption_in_network(q, bio);
				/* ��bio�ύ */
				if (err_code)
					clear_bit(BIO_UPTODATE, &bio->bi_flags);
				else if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
					err_code = -EIO;
		
				if(bio->bi_end_io)
					bio->bi_end_io(bio, err_code);
			}
			set_current_state(TASK_INTERRUPTIBLE);
		}
	__set_current_state(TASK_RUNNING);
	return 0;
}

/**ltl
 * ����: ���������߳�
 */
static int __init decryption_request_module_init(void)
{	
	spin_lock_init(&g_thread_spinlock);
	decryption_thread_handle = kthread_run(decryption_request_handler, NULL, 
		"decryption_handle_thread");
	if (IS_ERR(decryption_thread_handle)) {
		printk(KERN_ERR"[Error] Create thread \"decryption_handle_thread\" failed.\n");
		return -1;
	}
	printk(KERN_INFO"Create thread \"decryption_handle_thread\" Success.\n");

	return 0;
}
subsys_initcall(decryption_request_module_init);

