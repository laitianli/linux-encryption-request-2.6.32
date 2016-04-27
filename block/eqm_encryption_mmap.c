/**ltl
 * 功能: 此文件主要是将加密的数据映射到用户空间，同时等待用户空间的返回。
 */
#include "eqm_encryption.h"

static wait_queue_head_t eqm_encryption_qh; 
static wait_queue_head_t eqm_complete_qh;
static atomic_t be_eqm_encryption_read;
static LIST_HEAD(g_list_eqm_data);
static spinlock_t g_data_spinlock;
static struct eqm_data *gpdata = NULL;
static DEFINE_MUTEX(g_data_mutex);

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
	gpdata->err_code = *(int*)data;
 	atomic_set(&be_eqm_encryption_read, 0);
	wake_up_interruptible(&eqm_complete_qh);
}
/**ltl
 * 功能: 将数据映射到用户空间，同时等待加密返回。
 * 参数:
 * 返回值:
 * 说明:
 */
int send_encryption_data_to_network(struct page* ppage,  unsigned int len, unsigned int offset)
{
	int err_code = 0;
	if(!gpdata)
		return -ENOMEM;
	
	mutex_lock(&g_data_mutex);
	spin_lock(&g_data_spinlock);
	gpdata->len = len;
	gpdata->ppage = ppage;
	gpdata->offset = offset;
	gpdata->err_code = 0;
	spin_unlock(&g_data_spinlock);
	
	atomic_set(&be_eqm_encryption_read, 1);	
	/* 唤醒用户空间的读数据进程 */
	wake_up_interruptible(&eqm_encryption_qh);
	/* 等待eqm_wake_up_function函数被执行到 */
	wait_event_interruptible(eqm_complete_qh, atomic_read(&be_eqm_encryption_read)==0);
	err_code = gpdata->err_code;
	gpdata->ppage = NULL;
	gpdata->len = 0;
	gpdata->err_code = 0; 
	mutex_unlock(&g_data_mutex);
	return err_code;
}
EXPORT_SYMBOL(send_encryption_data_to_network);


void clear_encryption_data(void)
{
	spin_lock(&g_data_spinlock); 

	gpdata->len = 0;
	gpdata->err_code = 0;	
	spin_unlock(&g_data_spinlock);
	atomic_set(&be_eqm_encryption_read, 0);
}
EXPORT_SYMBOL(clear_encryption_data);


static int eqm_encryption_open(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
 
	return 0;
}

static int eqm_encryption_release(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
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
	vma->vm_ops = &eqm_vm_ops;
	spin_lock(&g_data_spinlock);
	if (remap_pfn_range(vma, vma->vm_start, 
			page_to_pfn(gpdata->ppage), vma->vm_end - vma->vm_start, 
			vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
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
		struct eqm_data_info info;
		spin_lock(&g_data_spinlock);
		info.len = gpdata->len;
		info.offset = gpdata->offset;		
		//put_user(gpdata->len, argp);
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

static int __init eqm_encryption_module_init(void)
{
	int ret = 0;
	gpdata = kzalloc(sizeof(struct eqm_data), GFP_KERNEL);
	if(!gpdata) {
		printk(KERN_ERR"[ERROR] malloc eqm_data failed.\n");
		return -ENOMEM;
	}
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
	if(gpdata) {
		kfree(gpdata);
		gpdata = NULL;
	}
 	misc_deregister(&eqm_encryption_dev);
}

module_init(eqm_encryption_module_init);
module_exit(eqm_encryption_module_exit);

MODULE_LICENSE("GPL");

