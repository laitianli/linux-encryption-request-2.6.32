/******
 * 实现bio请求的加解密功能
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

/* 解密线程 */
static struct task_struct* decryption_thread_handle = NULL;
static spinlock_t g_thread_spinlock;
static LIST_HEAD(read_bio_list);

#undef NLog
#undef ELog
#define ELog(fmt,arg...) printk(KERN_WARNING"[Encryption]=[%s:%d]="fmt"\n",__func__,__LINE__,##arg);
#define NLog(n,fmt,arg...)	do{	static int i = 0;if(i++ < n){printk(KERN_WARNING"[Encryption]=[%s:%d]="fmt"\n",__func__,__LINE__,##arg);}}while(0)


static int encryption_in_network(struct request_queue* q, struct bio* bio);
static int decryption_in_network(struct request_queue* q, struct bio* bio);
static int be_encryption_disk(const char* partition_name);
static void add_bio_to_list(struct bio* bio);

static int be_encryption_disk(const char* partition_name)
{
	return is_encrytion_disk(partition_name);
} 
/**ltl
 * 功能: 加密写bio请求的完成回调函数。
 * 参数: bio	-> bio请求对象
 *	    err	-> 错误码
 * 返回值: 无
 * 说明: 这个函数由请求处理完成后调用
 */
static void encryption_end_io_write(struct bio *bio, int err)
{
	struct bio *bio_orig = bio->bi_private;
	struct bio_vec *bvec, *org_vec;
	int i;
	/* 释放加密bio请求的每个page */
 	__bio_for_each_segment(bvec, bio, i, 0) {
		org_vec = bio_orig->bi_io_vec + i;
		__free_page(bvec->bv_page);
	} 
	kfree(bio->bi_private1);
	bio->bi_private1 = NULL;
	bio_orig->bi_private1 = NULL;
	/* 请求加密前的bio的完成处理函数 */
	bio_endio(bio_orig, err);
	bio_put(bio); /* 释放bio请求 */
}
 
/**ltl
 * 功能: 拷贝bio对象
 * 参数: q	-> 请求队列对象
 *	    org_bio->bio对象
 * 返回值: 新的bio对象
 * 说明: 读写bio请求的拷贝接口
 */
static struct bio* copy_bio(struct request_queue *q, struct bio* org_bio,
		bio_end_io_t* end_bio_fun)
{
	struct bio_vec *to, *from;
	int i, rw = bio_data_dir(org_bio); 
	char *vto, *vfrom;	
	unsigned int cnt = org_bio->bi_vcnt;
	/* 分配bio对象 */
	struct bio* bio = bio_alloc(GFP_NOIO, cnt);
	if (!bio)
		return org_bio;
	memset(bio->bi_io_vec, 0, cnt * sizeof(struct bio_vec));
	/* 遍历bio,拷贝其数据和属性 */
	bio_for_each_segment(from, org_bio, i) {		
		to = bio->bi_io_vec + i;
		to->bv_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		to->bv_len = from->bv_len;
		to->bv_offset = from->bv_offset;
		
		flush_dcache_page(from->bv_page);
		vto = page_address(to->bv_page) + to->bv_offset;
		if(rw == WRITE) {/* 只有读操作才拷贝数据 */
			/* page在高端内存中 */
			if (page_to_pfn(from->bv_page) > queue_bounce_pfn(q)) 
				vfrom = kmap(from->bv_page) + from->bv_offset;
			else /* page在底端内存中 */
				vfrom = page_address(from->bv_page) + from->bv_offset;
			memcpy(vto, vfrom, to->bv_len); /* 拷贝数据 */
			if (page_to_pfn(from->bv_page) > queue_bounce_pfn(q))
				kunmap(from->bv_page);
		}
	}
	/* 拷贝属性 */
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
 * 功能:写请求加密接口
 * 参数: q	-> 请求队列对象
 *		bio	->[in] bio写请求对象 ; [out] 重新生成的已经被加密过的请求。
 * 返回值: 无
 * 说明: 1. copy bio对象中。
 */
int encryption_request(struct request_queue *q, struct bio **bio)
{	
	int err_code = 0;
	struct bio *new_bio = NULL; /* 在这里要重新创建一个bio交给底层处理 */	
	char b[BDEVNAME_SIZE]={0}; 
	
 	if ((*bio)->bi_private1) /* 此已经加密过 */
 		return err_code;

	/* 是否是需要加密的磁盘 */
	if(!(*bio)->bi_bdev || 
		!(bdevname((*bio)->bi_bdev, b) && strlen(b))|| 
		!be_encryption_disk(b))
		return err_code;
	
	/* 网络不通 */
	if(!get_network_status()) {
//		Log("[Error] network failed.");
		return -EIO;
	}
	
	/* 保存加密盘的分区名 */
	(*bio)->bi_private1 = kzalloc(BDEVNAME_SIZE, GFP_KERNEL);
	if(!(*bio)->bi_private1)
		return -EIO;
	strncpy((char*)((*bio)->bi_private1), b, BDEVNAME_SIZE-1);
	
	if(bio_data_dir(*bio) != WRITE)
	{/* 加密盘的读操作 */ 
		return 0; /* 不能当作是错误的操作，对读流程 */
	}
	NLog(30,"begin encryption disk: %s", b);
	/*写操作 */
	/* 拷贝bio对象 */
	new_bio = copy_bio(q, *bio, encryption_end_io_write);
	if(new_bio == *bio)
		return err_code;
	

	err_code = encryption_in_network(q, new_bio);
	if(err_code) {
		encryption_end_io_write(new_bio, -EIO);
	}
	/* 将加密过的bio请求返回 */
	*bio = new_bio; 
	return err_code;
}

/**ltl
 * 功能: 读请求加密接口
 * 参数: q	->请求队列对象
 *		bio	->bio读请求对象
 * 返回值:无
 * 说明: 遍历bio对象中的每一page，对page中的数据解密
 */
int decryption_reuqest(struct request_queue *q, struct bio *bio)
{
	 /* 是否是读操作 */
	if(bio_data_dir(bio) != READ || 
		!bio->bi_private1 || 
		!be_encryption_disk(bio->bi_private1)) /* 是否是需要加密的磁盘 */
		return 0; 
	if(!get_network_status()){
		//Log("[Error] network failed.");
		return -EIO;
	}
	NLog(30,"decryption disk: %s", (const char*)(bio->bi_private1));
	kfree(bio->bi_private1);
	bio->bi_private1 = NULL;

	/* 将bio加入到bio列表中，唤醒线程处理 */
	add_bio_to_list(bio);
	//NLog(300,"after call add_bio_to_list fun");
	return 1;//decryption_in_network(q, bio);
}
EXPORT_SYMBOL(encryption_request);
EXPORT_SYMBOL(decryption_reuqest);

/**ltl
 * 功能:加密算法接口，将需要加密的数据上抛到用户空间
 * 参数:
 * 返回值:
 * 说明: 对所有数据+1
 */
static int encryption_in_network(struct request_queue* q, struct bio* bio)
{
	struct bio_vec *from;
	struct page *page;
	struct bio *new_bio = bio; /* 在这里要重新创建一个bio交给底层处理 */
	int i = 0, err_code = 0;
	bio_for_each_segment(from, new_bio, i) { 
		page = from->bv_page;
		/* 将需要加密的数据加入到列表中, 唤醒用户进程去读取数据，并加密处理 */
		err_code = send_encryption_data_to_network(page, from->bv_len, from->bv_offset);
		if(err_code) {
			printk(KERN_ERR"[Error] encryption the data fail. it's possible the network error.\n");
			return err_code;
		}
	} 
	return 0;
}

/**ltl
 * 功能:解密接口，将需要解密的数据上抛到用户空间
 * 参数:
 * 返回值:
 * 说明: 对所有数据-1
 */
static int decryption_in_network(struct request_queue* q, struct bio* bio)
{
	struct bio_vec *from;
	struct page *page;
	int i = 0, err_code = 0;

	bio_for_each_segment(from, bio, i) {
		page = from->bv_page;		
		flush_dcache_page(page);
		/* 将需要加密的数据加入到列表中,唤醒用户进程去读取数据，并解密处理  */
		err_code = send_decryption_data_to_network(page, from->bv_len, from->bv_offset);	
		if(err_code) {
			printk(KERN_ERR"[Error] decryption the data fail. it's possible the network error.\n");
			return err_code;
		}
	}
	return 0;
}

#define PER_CPU_LIST 0
/**ltl
 * 功能: 将需要解密的bio交给解密线程decryption_request_handler
 * 参数: bio	->bio对象
 * 返回值:
 * 说明:
 */
#if  PER_CPU_LIST <= 0

static void add_bio_to_list(struct bio* bio)
{
	INIT_LIST_HEAD(&bio->list);
	spin_lock(&g_thread_spinlock);
	list_add_tail(&bio->list, &read_bio_list);
	wake_up_process(decryption_thread_handle);	
	spin_unlock(&g_thread_spinlock);

}

/**ltl
 * 功能: 解密线程
 * 参数: bio	->bio对象
 * 返回值:
 * 说明: 由于解密是在软中断上下文中，中断上下文不允许被调度，因此创建此线程处理。
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
				/* 将要解密的数据映射到用户空间 */
				err_code = decryption_in_network(q, bio);
				/* 将bio提交 */
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
 * 功能: 创建解密线程
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

#else

static DEFINE_PER_CPU(struct list_head, read_bio_per_cup_list);
static void add_bio_to_list(struct bio* bio)
{
	struct list_head *list;
	unsigned long flags;
	INIT_LIST_HEAD(&bio->list);
	local_irq_save(flags);
	list = &__get_cpu_var(read_bio_per_cup_list);
	list_add_tail(&bio->list, list);
	wake_up_process(decryption_thread_handle);	

	local_irq_restore(flags);
 }

/**ltl
 * 功能: 解密线程
 * 参数: bio	->bio对象
 * 返回值:
 * 说明: 由于解密是在软中断上下文中，中断上下文不允许被调度，因此创建此线程处理。
 */
static int decryption_request_handler(void *data)
{
	int err_code = 0;
	struct list_head *cpu_list, local_list;
	
	struct request_queue* q = NULL;	
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
			local_irq_disable();
			cpu_list = &__get_cpu_var(read_bio_per_cup_list);
			list_replace_init(cpu_list, &local_list);
			local_irq_enable();
			if(list_empty(local_list)) {
				schedule();
				set_current_state(TASK_INTERRUPTIBLE);
				continue;
			}

			__set_current_state(TASK_RUNNING);		
	
			//spin_lock(&g_thread_spinlock);
			//list_replace_init(&read_bio_list, &local_list);
			//spin_unlock(&g_thread_spinlock); 			
			while (!list_empty(&local_list)) {	
				/*do bio*/
				struct bio *bio;
				bio = list_entry(local_list.next, struct bio, list);
				list_del_init(&bio->list);
				q = bio->bi_bdev->bd_disk->queue;
				err_code = 0;
				/* 将要解密的数据映射到用户空间 */
				err_code = decryption_in_network(q, bio);
				/* 将bio提交 */
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
 * 功能: 创建解密线程
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


#endif
subsys_initcall(decryption_request_module_init);

