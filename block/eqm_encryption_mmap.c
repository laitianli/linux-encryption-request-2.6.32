/**ltl
 * 功能: 此文件主要是将加密的数据映射到用户空间，同时等待用户空间的返回。
 */
#include "eqm_encryption.h"
#define EQM_ENCRYPTION_DATA_SIZE 			32

static wait_queue_head_t eqm_encryption_qh; 
static wait_queue_head_t eqm_complete_qh;
static atomic_t be_eqm_encryption_read;
static spinlock_t g_data_spinlock;
static DEFINE_MUTEX(g_data_mutex);
struct timer_list	eqm_unplug_timer; 
struct work_struct	eqm_unplug_work;
static struct workqueue_struct *eqm_workqueue;
static unsigned char eqm_encryption_index = 0;
static struct bio *bio_array[EQM_ENCRYPTION_DATA_SIZE];
static LIST_HEAD(g_eqm_encryption_bio_vec_slot);
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
	struct eqm_data_ex *eqm = NULL;
	
	vma->vm_ops = &eqm_vm_ops;
 	spin_lock(&g_data_spinlock);
	if(eqm_only_one_page) {
		if (remap_pfn_range(vma, vma->vm_start, 
			page_to_pfn(eqm_bio_vec->bv_page), PAGE_SIZE, vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
		}
	}
	else if(eqm_page_count > 0) { 
		i = 0;		
		list_for_each_safe(list_node, tmp, &g_eqm_encryption_bio_vec_slot) {
			eqm = list_entry(list_node, struct eqm_data_ex, entry_list);
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

		if(eqm_only_one_page){
			info.count = 1;
			info.len = eqm_bio_vec->bv_len;
			info.offset = eqm_bio_vec->bv_offset;
		}
		else if(eqm_page_count > 0) {
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
		{
			unsigned long page_size = PAGE_SIZE;
			put_user(page_size, argp);
			break;
		}
	case MISC_EQM_ENCRYPTION_FAILED:
		{
			int error_code = 0;
			ELog("MISC_EQM_ENCRYPTION_FAILED=%d",MISC_EQM_ENCRYPTION_FAILED);
			get_user(error_code, argp);
			eqm_wake_up_function(&error_code);
		break;
		}
	default:
		printk(KERN_INFO "[%s] Unkown command id=%d\n", __func__, cmd);
		return -1;
	}
	return 0;
}


void start_eqm_unplug_timer(void)
{
	mod_timer(&eqm_unplug_timer, jiffies + EQM_ENCRYPTION_UNPLUG_TIMEOUT);
}

void end_eqm_unplug_timer(void)
{
	del_timer(&eqm_unplug_timer);
}

static void eqm_blk_unplug_timeout(unsigned long data)
{
	queue_work(eqm_workqueue, &eqm_unplug_work);
}

static void eqm_blk_unplug_work(struct work_struct *work)
{
	mutex_lock(&g_data_mutex);
	end_eqm_unplug_timer();
	/* 将请求提交给上层处理 */
	send_encryption_data_network(gfn);	
	mutex_unlock(&g_data_mutex);
}

static void wait_for_encryption_complete(void)
{
	atomic_set(&be_eqm_encryption_read, 1);	
	/* 唤醒用户空间的读数据进程 */
	wake_up_interruptible(&eqm_encryption_qh);
	/* 等待eqm_wake_up_function函数被执行到 */
	wait_event_interruptible(eqm_complete_qh, atomic_read(&be_eqm_encryption_read)==0);

}

int send_encryption_data_network(generic_make_request_fn fn)
{
	int i = 0, j = 0;
	struct bio_vec *from = NULL;
	struct eqm_data_ex* eqm = NULL;

	for (i = 0; i < eqm_encryption_index && i <= EQM_ENCRYPTION_DATA_SIZE; i++)
	{
		bio_for_each_segment(from, bio_array[i], j) { 
			if( from->bv_offset > 0 ||  from->bv_len < PAGE_SIZE) {
				spin_lock(&g_data_spinlock);
				eqm_only_one_page = 1;	
				eqm_bio_vec = from;				
				spin_unlock(&g_data_spinlock);
				
				wait_for_encryption_complete();
				
				eqm_only_one_page = 0;	
				eqm_bio_vec = NULL;
				continue;
			}
			else 
			{				
				eqm = kzalloc(sizeof(struct eqm_data_ex), GFP_KERNEL);				
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
	if (eqm_page_count)
		wait_for_encryption_complete();	
	eqm_page_count = 0;	
	INIT_LIST_HEAD(&g_eqm_encryption_bio_vec_slot);	

	for (i = 0; i < eqm_encryption_index && i <= EQM_ENCRYPTION_DATA_SIZE; i++) 
	{
		fn(bio_array[i]); 
		bio_array[i] = NULL;
	}
	eqm_encryption_index = 0;
	
	return 0;
}

int send_encryption_data_to_network_ex(struct bio* bio, generic_make_request_fn fn)
{
	int i = 0;
	gfn = fn;

	mutex_lock(&g_data_mutex);

	i = eqm_encryption_index;
	bio_array[i]= bio;
	eqm_encryption_index ++;
	if(eqm_encryption_index < EQM_ENCRYPTION_DATA_SIZE)
		start_eqm_unplug_timer();
	else  
	{
		end_eqm_unplug_timer();		
		send_encryption_data_network(fn);
	}
	
	mutex_unlock(&g_data_mutex);
	return 0;
}

 

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

