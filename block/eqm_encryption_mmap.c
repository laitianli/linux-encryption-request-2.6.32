/**ltl
 * 功能: 此文件主要是将加密的数据映射到用户空间，同时等待用户空间的返回。
 */
#include "eqm_encryption.h"
/* 加密的错误码 */
static int g_err_code = 0;
static wait_queue_head_t eqm_encryption_qh; 
static wait_queue_head_t eqm_complete_qh;
static atomic_t be_eqm_encryption_read;
static spinlock_t g_data_spinlock;
static DEFINE_MUTEX(g_data_mutex);
struct timer_list	eqm_unplug_timer; 
struct work_struct	eqm_unplug_work;
static struct workqueue_struct *eqm_workqueue;
static atomic_t eqm_encryption_index;
static LIST_HEAD(g_eqm_encryption_bio_vec_slot);
static LIST_HEAD(g_eqm_encryption_bio_slot);
static unsigned char eqm_only_one_page = 0;
static unsigned char eqm_page_count = 0;
static struct bio_vec *eqm_bio_vec = NULL;
static generic_make_request_fn* gfn;

static int send_encryption_data_network(generic_make_request_fn fn);
static int eqm_encryption_open(struct inode* inode, struct file* file);
static int eqm_encryption_release(struct inode* inode, struct file* file);
static unsigned int eqm_encryption_poll(struct file* pf, struct poll_table_struct* table);
static int eqm_encryption_mmap(struct file* pf, struct vm_area_struct* vma);
static int eqm_encryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg);
static void eqm_encryption_vm_close(struct vm_area_struct * area);
static struct file_operations eqm_encryption_fops = {
	.owner = THIS_MODULE,
	.open = eqm_encryption_open, 
	.release = eqm_encryption_release,
	.poll = eqm_encryption_poll,
	.mmap =  eqm_encryption_mmap,
	.ioctl = eqm_encryption_ioctl,
 };

static struct miscdevice eqm_encryption_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = MISC_EQM_ENCRYPTION_NAME, 
	.fops = &eqm_encryption_fops,
};

static struct vm_operations_struct eqm_vm_ops = {
	.close = eqm_encryption_vm_close,
};

/**ltl
 * 功能: 当映射到用户空间的数据经过加密后，调用此接口唤醒内核进程
 * 参数: data	->存入错误码
 * 返回值:
 * 说明:
 */
static void eqm_wake_up_function(void* data)
{
 	atomic_set(&be_eqm_encryption_read, 0);
	wake_up_interruptible(&eqm_complete_qh);
}
 
static int eqm_encryption_open(struct inode* inode, struct file* file)
{
	printk(KERN_INFO"[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
 
	return 0;
}

static int eqm_encryption_release(struct inode* inode, struct file* file)
{
	printk(KERN_INFO"[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
	return 0;
}

/**ltl
 * 功能: poll接口
 * 参数:
 * 返回值:
 * 说明: 当用户空间调用poll时会执行。
 */
static unsigned int eqm_encryption_poll(struct file* pf, struct poll_table_struct* table)
{
	unsigned int mask = 0;

	poll_wait(pf, &eqm_encryption_qh, table);	/* read */
	if(atomic_read(&be_eqm_encryption_read) == 1)/* 表示设备可以读取 */
		mask |= POLLIN | POLLRDNORM;
 
	return mask;
}
/**ltl
 * 功能: 内存区域的close接口
 * 参数:
 * 返回值:
 * 说明: 当用户空间调用munmap时会执行。
 */
static void eqm_encryption_vm_close(struct vm_area_struct * area)
{
	int err_code = 0;
	eqm_wake_up_function(&err_code);
}
/**ltl
 * 功能: 内存映射接口
 * 参数:
 * 返回值:
 * 说明: 当用户空间调用mmap时会执行。
 */
static int eqm_encryption_mmap(struct file* pf, struct vm_area_struct* vma)
{	
	int i = 0;
	struct list_head *list_node, *tmp;
	struct eqm_data *eqm = NULL;
	
	vma->vm_ops = &eqm_vm_ops;
 	spin_lock(&g_data_spinlock);
	if(eqm_only_one_page) { /* 映射单页 */
		if (remap_pfn_range(vma, vma->vm_start, 
			page_to_pfn(eqm_bio_vec->bv_page), PAGE_SIZE, vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
		}
	}
	else if(eqm_page_count > 0) {  /* 映射多页面 */
		i = 0;		
		list_for_each_safe(list_node, tmp, &g_eqm_encryption_bio_vec_slot) {
			eqm = list_entry(list_node, struct eqm_data, entry_list);
			list_del(list_node);
			if (remap_pfn_range(vma, vma->vm_start + i * PAGE_SIZE, 
				page_to_pfn(eqm->bi_io_vec->bv_page), PAGE_SIZE, vma->vm_page_prot)) {
				spin_unlock(&g_data_spinlock);
				return -EAGAIN;
			}
			i++;		
			kfree(eqm);			
		}
	}

 	spin_unlock(&g_data_spinlock);	
	return 0;
}

static int eqm_encryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg)
{
	unsigned long __user *argp = (void __user *)arg;
	switch (cmd)
	{
	case MISC_EQM_GET_DATA_LENGTH:
	{
		struct eqm_data_info info = {0};
		spin_lock(&g_data_spinlock);

		if(eqm_only_one_page){ /* 映射单页面时，将数据长度和偏移显示返回 */
			info.count = 1;
			info.len = eqm_bio_vec->bv_len;
			info.offset = eqm_bio_vec->bv_offset;
		}
		else if(eqm_page_count > 0) { /* 映射多页面时，只要将页面数返回 */
			info.count = eqm_page_count;
			info.offset = 0;
			if(eqm_page_count == 1)
				info.len = PAGE_SIZE;
			else
				info.len = 0;
		}

		spin_unlock(&g_data_spinlock);
		if(copy_to_user(argp, &info, sizeof(struct eqm_data_info))) {
			printk("[Error]=copy_to_user error.\n");
			return -EINVAL;
		}
		break;
	}
	case MISC_EQM_GET_PAGE_SIZE:
		{ /* 获取页面大小 */
			unsigned long page_size = PAGE_SIZE;
			put_user(page_size, argp);
			break;
		}
	case MISC_EQM_ENCRYPTION_FAILED:
		{/* 设置错误码 */
			get_user(g_err_code, argp);
			eqm_wake_up_function(&g_err_code);
		break;
		}
	default:
		printk(KERN_INFO "[%s] Unkown command id=%d\n", __func__, cmd);
		return -1;
	}
	return 0;
}

/* 开启定时器 */
void start_eqm_unplug_timer(void)
{
	mod_timer(&eqm_unplug_timer, jiffies + EQM_ENCRYPTION_UNPLUG_TIMEOUT);
}
/* 停止定时器 */
void end_eqm_unplug_timer(void)
{
	del_timer(&eqm_unplug_timer);
}
/* "泄流"定时器处理函数 */
static void eqm_blk_unplug_timeout(unsigned long data)
{
	/* 唤醒"泄流"工作队列 */
	queue_work(eqm_workqueue, &eqm_unplug_work);
}
/* "泄流"工作队列处理函数*/
static void eqm_blk_unplug_work(struct work_struct *work)
{
	mutex_lock(&g_data_mutex);
	end_eqm_unplug_timer();
	/* 将请求提交给上层处理 */
	send_encryption_data_network(gfn);	
	mutex_unlock(&g_data_mutex);
}
/* 1.唤醒用户进程encryptio_client；2.等待进程encryption_client将数据加密完成 */
static int wait_for_encryption_complete(void)
{
	g_err_code = 0;
	atomic_set(&be_eqm_encryption_read, 1);	
	/* 唤醒用户空间的读数据进程 */
	wake_up_interruptible(&eqm_encryption_qh);
	/* 等待eqm_wake_up_function函数被执行到 */
	wait_event_interruptible(eqm_complete_qh, atomic_read(&be_eqm_encryption_read)==0);
	return g_err_code; /* 错误码在ioctl命令MISC_EQM_ENCRYPTION_FAILED中设置 */
}
/**ltl
 * 功能: 将需要加密的请求添加映射到用户空间
 * 参数: fn->此函数指针为__generic_make_request
 * 返回值:
 * 说明:
 */
int send_encryption_data_network(generic_make_request_fn fn)
{
	int j = 0;
	struct bio_vec *from = NULL;
	struct eqm_data* eqm = NULL;
	struct list_head *list_node, *tmp;
	struct bio *bio = NULL;
	int err_code = 0;
	/* 遍历bio请求列表 */
	list_for_each_safe(list_node, tmp, &g_eqm_encryption_bio_slot)
	{
		bio = list_entry(list_node, struct bio, list);
		bio_for_each_segment(from, /*bio_array[i]*/bio, j) { 
			/* 说明需要加密的数据小于PAGE_SIZE, 则将此请求单独的映射(不单独映射的话，映射到的用户空间的数据会出错) */
			if( from->bv_offset > 0 ||  from->bv_len < PAGE_SIZE) {
				spin_lock(&g_data_spinlock);
				eqm_only_one_page = 1;	
				eqm_bio_vec = from;				
				spin_unlock(&g_data_spinlock);
				/* 1.唤醒用户进程encryptio_client；2.等待进程encryption_client将数据加密完成 */
				err_code = wait_for_encryption_complete();
				
				eqm_only_one_page = 0;	
				eqm_bio_vec = NULL;
				if(err_code)
					goto ERROR;
				continue;
			}
			else 
			{	/* 将要加密的page插入到列表中 */			
				eqm = kzalloc(sizeof(struct eqm_data), GFP_KERNEL);				
				BUG_ON(!eqm);
				
				spin_lock(&g_data_spinlock);
				eqm->bi_io_vec = from;
				
				INIT_LIST_HEAD(&eqm->entry_list);
				list_add_tail(&eqm->entry_list, &g_eqm_encryption_bio_vec_slot);
				eqm_page_count ++;
				spin_unlock(&g_data_spinlock);
			}
		}
	}

	eqm_only_one_page = 0;	
	if (eqm_page_count) /* 1.唤醒用户进程encryptio_client；2.等待进程encryption_client将数据加密完成 */
		err_code = wait_for_encryption_complete();	
ERROR:
	eqm_page_count = 0;	
	INIT_LIST_HEAD(&g_eqm_encryption_bio_vec_slot);	
	/* 将加密完成的bio请求提交给下层 */
	list_for_each_safe(list_node, tmp, &g_eqm_encryption_bio_slot)
	{
		bio = list_entry(list_node, struct bio, list);
		list_del_init(list_node);
		if(err_code)
			bio->bi_rw |= 1 << BIO_RW_DISCARD;
		fn(bio); /*__generic_make_request(bio)  */
	}
	INIT_LIST_HEAD(&g_eqm_encryption_bio_slot);
	atomic_set(&eqm_encryption_index,0);
	
	return 0;
}
/**ltl
 * 功能: 将需要加密的请求插入到列表
 * 参数: bio	->需要加密的bio对象
 *		fn	->此函数指针值为__generic_make_request
 * 返回值: 
 * 说明:	将bio插入到全局列表g_eqm_encryption_bio_slot中，如果列表中的bio请求个数小于EQM_ENCRYPTION_DATA_SIZE
 *		则开启定时器，此定时器的超时时间为EQM_ENCRYPTION_UNPLUG_TIMEOUT(ms);若bio请求个数超出EQM_ENCRYPTION_DATA_SIZE，
 *		停止定时器，直接处理列表中的请求
 */
int send_encryption_data_to_network(struct bio* bio, generic_make_request_fn fn)
{
	gfn = fn;
	/* 注:只有在进程上下文中，才可能使用mutex锁 */
	mutex_lock(&g_data_mutex); 
	list_add_tail(&bio->list, &g_eqm_encryption_bio_slot);
	atomic_inc(&eqm_encryption_index);
	
	if(atomic_read(&eqm_encryption_index) < EQM_ENCRYPTION_DATA_SIZE)
		start_eqm_unplug_timer();/* 开启定时器功能 */
	else  
	{
		end_eqm_unplug_timer();	/* 停止定时器功能 */
		send_encryption_data_network(fn); /* 处理列表中的bio请求 */
	}
	
	mutex_unlock(&g_data_mutex);
	return 0;
}

/* 加密模块的初始化接口 */
static int __init eqm_encryption_module_init(void)
{
	int ret = 0;

	eqm_workqueue = create_workqueue("eqm_kblockd");
	if (!eqm_workqueue)
		panic("Failed to create eqm_kblockd\n");
	
	init_timer(&eqm_unplug_timer);
	eqm_unplug_timer.function = eqm_blk_unplug_timeout;
	eqm_unplug_timer.data 	  = 0;
	INIT_WORK(&eqm_unplug_work, eqm_blk_unplug_work);	

	spin_lock_init(&g_data_spinlock);
	init_waitqueue_head(&eqm_encryption_qh);
	init_waitqueue_head(&eqm_complete_qh);
	
	atomic_set(&be_eqm_encryption_read, 0);
	atomic_set(&eqm_encryption_index, 0);

    ret = misc_register(&eqm_encryption_dev);
	if(!ret)
		printk(KERN_INFO"[INFO] load eqm encryption module success.\n");
	return ret;
}

static void __exit eqm_encryption_module_exit(void)
{
    printk("[:%s%s:%d]\n",__FILE__,__func__,__LINE__);
 	misc_deregister(&eqm_encryption_dev);
}

module_init(eqm_encryption_module_init);
module_exit(eqm_encryption_module_exit);

MODULE_LICENSE("GPL");

