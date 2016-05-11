/**ltl
 * ����: ���ļ���Ҫ�ǽ����ܵ�����ӳ�䵽�û��ռ䣬ͬʱ�ȴ��û��ռ�ķ��ء�
 */
#include "eqm_encryption.h" 
static wait_queue_head_t eqm_decryption_qh; 
static wait_queue_head_t eqm_decryption_complete_qh;
static atomic_t be_eqm_decryption_read;
static unsigned char eqm_de_pluged;
static LIST_HEAD(g_list_eqm_data);
static atomic_t eqm_network_status;
static DEFINE_MUTEX(g_de_data_mutex);
/*********************************************/
static int g_de_err_code = 0;
struct timer_list	eqm_de_unplug_timer; 

/* �����߳� */
static struct task_struct* decryption_thread_handle = NULL;
static spinlock_t g_thread_spinlock;
static unsigned char eqm_decryption_index = 0;
static LIST_HEAD(g_eqm_decryption_bio_vec_slot);
static LIST_HEAD(g_eqm_decryption_bio_slot);
static unsigned char eqm_de_only_one_page = 0;
static unsigned char eqm_de_page_count = 0;
static struct bio_vec *eqm_de_bio_vec = NULL;
/*********************************************/

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
 	atomic_set(&be_eqm_decryption_read, 0);	
	wake_up_interruptible(&eqm_decryption_complete_qh);	
}

/* ��ȡ��ǰ������״̬ */
int get_network_status(void)
{
	return atomic_read(&eqm_network_status);
}
EXPORT_SYMBOL(get_network_status);

static int eqm_decryption_open(struct inode* inode, struct file* file)
{
	//printk(KERN_INFO"[%s:%s:%d]\n",__FILE__,__func__,__LINE__); 		
	return 0;
}

static int eqm_decryption_release(struct inode* inode, struct file* file)
{
	//printk(KERN_INFO"[%s:%s:%d]\n",__FILE__,__func__,__LINE__);	
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
	int i = 0;
	struct list_head *list_node, *tmp;
	struct eqm_data *eqm = NULL;
		
	vma->vm_ops = &eqm_vm_ops;

	if(eqm_de_only_one_page) {
		if (remap_pfn_range(vma, vma->vm_start, 
			page_to_pfn(eqm_de_bio_vec->bv_page), PAGE_SIZE, vma->vm_page_prot)) {
			return -EAGAIN;
		}
	}
	else if(eqm_de_page_count > 0) { 
		i = 0;		
		list_for_each_safe(list_node, tmp, &g_eqm_decryption_bio_vec_slot) {
			eqm = list_entry(list_node, struct eqm_data, entry_list);
			list_del(list_node);
			if (remap_pfn_range(vma, vma->vm_start + i * PAGE_SIZE, 
				page_to_pfn(eqm->bi_io_vec->bv_page), PAGE_SIZE, vma->vm_page_prot)) {
				return -EAGAIN;
			}
			i++;		
			kfree(eqm);			
		}
	}
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

		if(eqm_de_only_one_page){
			info.count = 1;
			info.len = eqm_de_bio_vec->bv_len;
			info.offset = eqm_de_bio_vec->bv_offset;
		}
		else if(eqm_de_page_count > 0) {
			info.count = eqm_de_page_count;
			info.offset = 0;
			if(eqm_de_page_count == 1)
				info.len = PAGE_SIZE;
			else
				info.len = 0;
		}
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
			get_user(g_de_err_code, argp);
			eqm_wake_up_function(&g_de_err_code);
		break;
		}
	default:
		printk(KERN_INFO "[%s] Unkown command id=%d\n", __func__, cmd);
	}
	return 0;
}

void start_de_eqm_unplug_timer(void)
{
	if(!eqm_de_pluged) {
		mod_timer(&eqm_de_unplug_timer, jiffies + EQM_DECRYPTION_UNPLUG_TIMEOUT);
		eqm_de_pluged = 1;
	}
}

void end_de_eqm_unplug_timer(void)
{
	if(eqm_de_pluged) {
		del_timer(&eqm_de_unplug_timer);
		eqm_de_pluged=0;
	}
}

static void eqm_de_blk_unplug_timeout(unsigned long data)
{
	//end_de_eqm_unplug_timer();
	wake_up_process(decryption_thread_handle);
}

static int wait_for_decryption_complete(void)
{
	g_de_err_code = 0;
	atomic_set(&be_eqm_decryption_read, 1);	
	/* �����û��ռ�Ķ����ݽ��� */
	wake_up_interruptible(&eqm_decryption_qh); 
	/* �ȴ�eqm_wake_up_function������ִ�е� */
	wait_event_interruptible(eqm_decryption_complete_qh, !atomic_read(&be_eqm_decryption_read));
	return g_de_err_code;
}
/**ltl
 * ����: <�˺���������send_encryption_data_network����>
 * ����:
 * ����ֵ:
 * ˵��:
 */
static int send_decryption_data_network(void)
{
	int j = 0;
	int err_code = 0;
	struct bio_vec *from = NULL;
	struct eqm_data* eqm = NULL;
	struct list_head *list_node, *tmp;
	struct bio *bio = NULL;
	struct list_head local_list;
	
	spin_lock(&g_thread_spinlock);	
	list_replace_init(&g_eqm_decryption_bio_slot, &local_list);
	eqm_decryption_index = 0;
	spin_unlock(&g_thread_spinlock);
	
	list_for_each_safe(list_node, tmp, &local_list)
	{
		bio = list_entry(list_node, struct bio, list);
		bio_for_each_segment(from, /*bio_array[i]*/bio, j) { 
			if( from->bv_offset > 0 ||  from->bv_len < PAGE_SIZE) {
				eqm_de_only_one_page = 1;	
				eqm_de_bio_vec = from;				
				
				err_code = wait_for_decryption_complete();
				eqm_de_only_one_page = 0;	
				eqm_de_bio_vec = NULL;
				if(err_code)
					goto ERROR;
				continue;
			}
			else 
			{				
				eqm = kzalloc(sizeof(struct eqm_data), GFP_KERNEL);				
				BUG_ON(!eqm);
				
				eqm->bi_io_vec = from;
				
				INIT_LIST_HEAD(&eqm->entry_list);
				list_add_tail(&eqm->entry_list, &g_eqm_decryption_bio_vec_slot);
				eqm_de_page_count ++;
			}
		}
	}
	eqm_de_only_one_page = 0;	
	if (eqm_de_page_count)
		err_code = wait_for_decryption_complete();	
ERROR:
	eqm_de_page_count = 0;	
	INIT_LIST_HEAD(&g_eqm_decryption_bio_vec_slot);	

	list_for_each_safe(list_node, tmp, &local_list)
	{
		bio = list_entry(list_node, struct bio, list);
		list_del_init(list_node);
		
		/* ��bio�ύ */
		if (err_code)
			clear_bit(BIO_UPTODATE, &bio->bi_flags);
		else if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
			err_code = -EIO;
		if (bio->bi_end_io)
			bio->bi_end_io(bio, err_code);
	}
	return 0;
}

/**ltl
 * ����: ����Ҫ���ܵ����ݲ��뵽�������
 * ����: bio	->��Ҫ���ܵ�����
 * ����ֵ:
 * ˵��: ������������ж������ĵ��ã����ֻ��ʹ����������
 *       ���б��е�bio�����������EQM_DECRYPTION_DATA_SIZE�����ѽ����̡߳�
 *		����û�г���EQM_DECRYPTION_DATA_SIZE������һ��25ms��ʱ��
 */
int send_decryption_data_to_network(struct bio* bio)
{
	/* ע:ֻ���ڽ����������У��ſ���ʹ��mutex��������ǰ�������ж��������У�����ֻ��ʹ�������� */
	spin_lock(&g_thread_spinlock);
	list_add_tail(&bio->list, &g_eqm_decryption_bio_slot);
	eqm_decryption_index ++;
	if(eqm_decryption_index < EQM_DECRYPTION_DATA_SIZE)
		start_de_eqm_unplug_timer();
	else  
	{
		wake_up_process(decryption_thread_handle);
	}
	spin_unlock(&g_thread_spinlock);
	return 0;
}


/**ltl
 * ����: �����߳�
 * ����: bio	->bio����
 * ����ֵ:
 * ˵��: ���ڽ����������ж��������У��ж������Ĳ��������ȣ���˴������̴߳���
 */
static int decryption_request_handler(void *data)
{
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {	
			spin_lock(&g_thread_spinlock);
			if(!eqm_decryption_index) {
				spin_unlock(&g_thread_spinlock);
				schedule();
				set_current_state(TASK_INTERRUPTIBLE);
				continue;
			}
			spin_unlock(&g_thread_spinlock);
			__set_current_state(TASK_RUNNING);	
			end_de_eqm_unplug_timer();	
			send_decryption_data_network(); /* �����ܵ�����ӳ�䵽�û��ռ� */
			__set_current_state(TASK_INTERRUPTIBLE);
		}
	__set_current_state(TASK_RUNNING);

	return 0;
}

/* ����ģ��ĳ�ʼ�� */
static int __init eqm_decryption_module_init(void)
{
	int ret = 0;

	spin_lock_init(&g_thread_spinlock);
	decryption_thread_handle = kthread_run(decryption_request_handler, NULL, 
		"decryption_thread_ex");
	if (IS_ERR(decryption_thread_handle)) {
		printk(KERN_ERR"[Error] Create thread \"decryption_thread\" failed.\n");
		return -1;
	}
	
	init_timer(&eqm_de_unplug_timer);
	eqm_de_unplug_timer.function = eqm_de_blk_unplug_timeout;
	eqm_de_unplug_timer.data 	  = 0;

	init_waitqueue_head(&eqm_decryption_qh);
	init_waitqueue_head(&eqm_decryption_complete_qh);
	eqm_decryption_index = 0;
	atomic_set(&be_eqm_decryption_read, 0);
	atomic_set(&eqm_network_status, 0);
	eqm_de_pluged=0;
    ret = misc_register(&eqm_decryption_dev);
	if(!ret)
		printk(KERN_INFO"[INFO] load eqm decryption module success.\n");
	return ret;
}

static void __exit eqm_decryption_module_exit(void)
{
    printk(KERN_INFO"[:%s%s:%d]\n",__FILE__,__func__,__LINE__);
 	misc_deregister(&eqm_decryption_dev);
}

module_init(eqm_decryption_module_init);
module_exit(eqm_decryption_module_exit);

MODULE_LICENSE("GPL");

