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

/* �����߳� */
static struct task_struct* decryption_thread_handle = NULL;
static spinlock_t g_thread_spinlock;
static LIST_HEAD(read_bio_list);

static int decryption_in_network(struct request_queue* q, struct bio* bio);
static int be_encryption_disk(const char* partition_name);
static void add_bio_to_list(struct bio* bio);

static int be_encryption_disk(const char* partition_name)
{
	return is_encrytion_disk(partition_name);
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
	
	if(!get_network_status()){
		//Log("[Error] network failed.");
		return -EIO;
	}
	/* ��bio���뵽bio�б��У������̴߳��� */
	add_bio_to_list(bio);
	//NLog(300,"after call add_bio_to_list fun");
	return 1;//decryption_in_network(q, bio);
}

EXPORT_SYMBOL(decryption_reuqest);

/**ltl
 * ����:���ܽӿڣ�����Ҫ���ܵ��������׵��û��ռ�
 * ����:
 * ����ֵ:
 * ˵��: ����������-1
 */

static int decryption_in_network(struct request_queue* q, struct bio* bio)
{
	struct bio_vec *from;
	struct page *page;
	int i = 0, err_code = 0;

	bio_for_each_segment(from, bio, i) {
		page = from->bv_page;		
		flush_dcache_page(page);
		/* ����Ҫ���ܵ����ݼ��뵽�б���,�����û�����ȥ��ȡ���ݣ������ܴ���  */
		err_code = send_decryption_data_to_network(page, from->bv_len, from->bv_offset);	
		if(err_code) {
			printk(KERN_ERR"[Error] decryption the data fail. it's possible the network error.\n");
			return err_code;
		}
	}
	return 0;
}


/**ltl
 * ����: ����Ҫ���ܵ�bio���������߳�decryption_request_handler
 * ����: bio	->bio����
 * ����ֵ:
 * ˵��:
 */

static void add_bio_to_list(struct bio* bio)
{
	INIT_LIST_HEAD(&bio->list);
	spin_lock(&g_thread_spinlock);
	list_add_tail(&bio->list, &read_bio_list);
	wake_up_process(decryption_thread_handle);	
	spin_unlock(&g_thread_spinlock);

}

/**ltl
 * ����: �����߳�
 * ����: bio	->bio����
 * ����ֵ:
 * ˵��: ���ڽ����������ж��������У��ж������Ĳ��������ȣ���˴������̴߳���
 */
static int decryption_request_handler(void *data)
{
	int err_code = 0;
	struct list_head local_list;
	
	struct request_queue* q = NULL;	
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {			
			if(list_empty(&read_bio_list)) {
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
				/* ��Ҫ���ܵ�����ӳ�䵽�û��ռ� */
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

int encrytion_disk(struct bio* bio)
{
	char b[BDEVNAME_SIZE]={0}; 
	
	/* �Ƿ�����Ҫ���ܵĴ��� */
	if(!(bio)->bi_bdev || 
		!(bdevname((bio)->bi_bdev, b) && strlen(b))|| 
		!be_encryption_disk(b))
		return 0;

	return 1;
}


void encryption_make_request(struct bio *bio, generic_make_request_fn fn)
{	
	char b[BDEVNAME_SIZE] = {0};
	struct bio* new_bio = NULL;
	struct request_queue* q = NULL;
	
	if (bio->bi_private1) { /* ���Ѿ����ܹ� */
		goto MAKE_REQUEST;
	}	
	
	/* ��������̵ķ����� */
	bio->bi_private1 = kzalloc(BDEVNAME_SIZE, GFP_KERNEL);
	BUG_ON(!bio->bi_private1);	
	bdevname(bio->bi_bdev, b);
	strncpy((char*)(bio->bi_private1), b, BDEVNAME_SIZE-1);
	
	if(bio_data_dir(bio) != WRITE) {/* �����̵Ķ����� */ 
		goto MAKE_REQUEST;
	}
		/* ���粻ͨ */
	if(!get_network_status()) {
		bio->bi_rw |= 1 << BIO_RW_DISCARD; /* ���������� */
		ELog("[Error] network failed.");
		goto MAKE_REQUEST;
	}
	NLog(30,"begin encryption disk: %s", b);
	/*д���� */
	/* ����bio���� */
	q = bdev_get_queue(bio->bi_bdev);
	new_bio = copy_bio(q, bio, encryption_end_io_write);
	if(new_bio == bio)
		goto MAKE_REQUEST;
	
	send_encryption_data_to_network_ex(new_bio, fn);
	
	return ;
MAKE_REQUEST:
	fn(bio);
}

/**ltl
 * ����: ���������߳�
 */
static int __init decryption_request_module_init(void)
{	
	spin_lock_init(&g_thread_spinlock);
	decryption_thread_handle = kthread_run(decryption_request_handler, NULL, 
		"decryption_thread");
	if (IS_ERR(decryption_thread_handle)) {
		printk(KERN_ERR"[Error] Create thread \"decryption_thread\" failed.\n");
		return -1;
	}
	printk(KERN_INFO"Create thread \"decryption_thread\" Success.\n");

	return 0;
}

subsys_initcall(decryption_request_module_init);



