/**ltl
 * ����: ���ļ���Ҫ�ǽ����ܵ�����ӳ�䵽�û��ռ䣬ͬʱ�ȴ��û��ռ�ķ��ء�
 */
#include "eqm_encryption.h" 
static wait_queue_head_t eqm_decryption_qh; 
static wait_queue_head_t eqm_decryption_complete_qh;
static atomic_t be_eqm_decryption_read;
static LIST_HEAD(g_list_eqm_data);
static spinlock_t g_de_data_spinlock;
static struct eqm_data *gp_de_data = NULL;
static atomic_t eqm_network_status;
static DEFINE_MUTEX(g_de_data_mutex);

static int eqm_decryption_open(struct inode* inode, struct file* file);
static int eqm_decryption_release(struct inode* inode, struct file* file);
static unsigned int eqm_decryption_poll(struct file* pf, struct poll_table_struct* table);
static int eqm_decryption_mmap(struct file* pf, struct vm_area_struct* vma);
static int eqm_decryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg);
static void eqm_decryption_vm_close(struct vm_area_struct * area);


static struct file_operations eqm_decryption_fops = {
	.owner = THIS_MODULE,
	.open = eqm_decryption_open, 
	.release = eqm_decryption_release,
	.poll = eqm_decryption_poll,
	.mmap =  eqm_decryption_mmap,
	.ioctl = eqm_decryption_ioctl,
 };

static struct miscdevice eqm_decryption_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = MISC_EQM_DECRYPTION_NAME, 
	.fops = &eqm_decryption_fops,
};

static struct vm_operations_struct eqm_vm_ops = {
	.close = eqm_decryption_vm_close,
};

static void eqm_wake_up_function(void* data)
{
	gp_de_data->err_code = *(int*)data;
 	atomic_set(&be_eqm_decryption_read, 0);	
	wake_up_interruptible(&eqm_decryption_complete_qh);	
}

int send_decryption_data_to_network(struct page* ppage,  unsigned int len, unsigned int offset)
{
	int err_code = 0;
	if(!gp_de_data)
		return -ENOMEM;
	
	mutex_lock(&g_de_data_mutex);
	spin_lock(&g_de_data_spinlock);
	gp_de_data->len = len;	
	gp_de_data->ppage = ppage;
	gp_de_data->offset = offset;
	gp_de_data->err_code = 0;
	spin_unlock(&g_de_data_spinlock);
		
	atomic_set(&be_eqm_decryption_read, 1);	
	/* �����û��ռ�Ķ����ݽ��� */
	wake_up_interruptible(&eqm_decryption_qh); 
	/* �ȴ�eqm_wake_up_function������ִ�е� */
	wait_event_interruptible(eqm_decryption_complete_qh, !atomic_read(&be_eqm_decryption_read));
	gp_de_data->ppage = NULL;
	gp_de_data->len = 0;	
	err_code = gp_de_data->err_code;
	gp_de_data->err_code = 0;
	mutex_unlock(&g_de_data_mutex);
	return err_code;
}
EXPORT_SYMBOL(send_decryption_data_to_network);

/* ��ȡ��ǰ������״̬ */
int get_network_status(void)
{
	return atomic_read(&eqm_network_status);
}
EXPORT_SYMBOL(get_network_status);

void clear_decryption_data(void)
{
	spin_lock(&g_de_data_spinlock);
	gp_de_data->len = 0;
	gp_de_data->err_code = 0;	
	spin_unlock(&g_de_data_spinlock);
	atomic_set(&be_eqm_decryption_read, 0);
	
}
EXPORT_SYMBOL(clear_decryption_data);


static int eqm_decryption_open(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
 		
	return 0;
}

static int eqm_decryption_release(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
	
	return 0;
}
static unsigned int eqm_decryption_poll(struct file* pf, struct poll_table_struct* table)
{
	unsigned int mask = 0;

	poll_wait(pf, &eqm_decryption_qh, table);	/* read */
	if(atomic_read(&be_eqm_decryption_read) == 1)/* ��ʾ�豸���Զ�ȡ */
		mask |= POLLIN | POLLRDNORM;
 
	return mask;
}
static void eqm_decryption_vm_close(struct vm_area_struct * area)
{
	int error_code = 0;
	/* �����ں˽��� */
	eqm_wake_up_function(&error_code); 
}

static int eqm_decryption_mmap(struct file* pf, struct vm_area_struct* vma)
{
	
	spin_lock(&g_de_data_spinlock);
	vma->vm_ops = &eqm_vm_ops;

	if (remap_pfn_range(vma, vma->vm_start, 
			page_to_pfn(gp_de_data->ppage), vma->vm_end - vma->vm_start, 
			vma->vm_page_prot)) {
			spin_unlock(&g_de_data_spinlock);
			return -EAGAIN;
		}
  	spin_unlock(&g_de_data_spinlock);	
	return 0;
}

static int eqm_decryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg)
{
	unsigned long __user *argp = (void __user *)arg;
	switch (cmd)
	{
	case MISC_EQM_GET_DATA_LENGTH:
	{
		struct eqm_data_info info;
		spin_lock(&g_de_data_spinlock);

		info.len = gp_de_data->len;
		info.offset = gp_de_data->offset;
		info.count = 1;

		spin_unlock(&g_de_data_spinlock);
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
	case MISC_EQM_NET_STATUS: /* ����״̬ */
		{
			unsigned int status = 0;
			get_user(status, argp);
			
			if(status == 1) /* net ok*/
			{/* ����ʶ����̷���(ȥ����config_encryption_disk.c�еĽӿ�) */
				atomic_set(&eqm_network_status, 1);				
			}
			else
				atomic_set(&eqm_network_status, 0);
			break;
		}
	case MISC_EQM_GET_DISK_PARTITION:
		{
			char fullname[256] = {0};
			int fd = 0;
			if(copy_from_user(fullname, argp, sizeof(fullname)-1))
				return -EINVAL;

			printk(KERN_INFO"fullname=%s (cmd: MISC_EQM_GET_DISK_PARTITION)\n", fullname);
			
			fd = sys_open(fullname, 0, 0);
			sys_ioctl(fd, BLKRRPART, 0);
			break;
		}
	case MISC_EQM_MMAP_COMPLETE:
		{
			int error_code = 0;
			eqm_wake_up_function(&error_code);
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
	}
	return 0;
}

static int __init eqm_decryption_module_init(void)
{
	int ret = 0;
	gp_de_data = kzalloc(sizeof(struct eqm_data), GFP_KERNEL);
	if(!gp_de_data)
	{
		printk(KERN_ERR"[ERROR] alloc eqm_data memery failed.\n");
		return -ENOMEM;
	}
	spin_lock_init(&g_de_data_spinlock);

	init_waitqueue_head(&eqm_decryption_qh);
	init_waitqueue_head(&eqm_decryption_complete_qh);
	
	atomic_set(&be_eqm_decryption_read, 0);
	atomic_set(&eqm_network_status, 0);
    ret = misc_register(&eqm_decryption_dev);
	if(ret)
		printk(KERN_ERR"[Error] load eqm decryption module failed.\n");
	printk(KERN_INFO"[INFO] load eqm decryption module success.\n");
	return ret;
}

static void __exit eqm_decryption_module_exit(void)
{
    printk("[:%s%s:%d]\n",__FILE__,__func__,__LINE__);
 	misc_deregister(&eqm_decryption_dev);
	if(gp_de_data) {
		kfree(gp_de_data);
		gp_de_data = NULL;
	}
}

module_init(eqm_decryption_module_init);
module_exit(eqm_decryption_module_exit);

MODULE_LICENSE("GPL");

