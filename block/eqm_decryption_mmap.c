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

#include "eqm_encryption.h"

#define MISC_EQM_DECRYPTION_NAME  "eqm-decryption"

static wait_queue_head_t eqm_decryption_qh; 
static wait_queue_head_t eqm_decryption_complete_qh;
static atomic_t be_eqm_decryption_read;
static LIST_HEAD(g_list_eqm_data);
static spinlock_t g_de_data_spinlock;
static struct eqm_data *gp_de_data = NULL;

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

int send_decryption_data_to_network(unsigned char* buf, unsigned int len)
{
	int err_code = 0;
	if(!gp_de_data)
		return -ENOMEM;
	
	mutex_lock(&g_de_data_mutex);
	spin_lock(&g_de_data_spinlock);
	gp_de_data->buf = buf;
	gp_de_data->len = len;	
	gp_de_data->err_code = 0;
	spin_unlock(&g_de_data_spinlock);
		
	atomic_set(&be_eqm_decryption_read, 1);	
	/* 唤醒用户空间的读数据进程 */
	wake_up_interruptible(&eqm_decryption_qh); 
	/* 等待eqm_wake_up_function函数被执行到 */
	wait_event_interruptible(eqm_decryption_complete_qh, !atomic_read(&be_eqm_decryption_read));
	
	gp_de_data->buf = NULL;
	gp_de_data->len = 0;	
	err_code = gp_de_data->err_code;
	gp_de_data->err_code = 0;
	mutex_unlock(&g_de_data_mutex);
	return err_code;
}
EXPORT_SYMBOL(send_decryption_data_to_network);


void clear_decryption_data(void)
{

	spin_lock(&g_de_data_spinlock);
	gp_de_data->buf = NULL;
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
	if(atomic_read(&be_eqm_decryption_read) == 1)/* 表示设备可以读取 */
		mask |= POLLIN | POLLRDNORM;
 
	return mask;
}
static void eqm_decryption_vm_close(struct vm_area_struct * area)
{
	int error_code = 0;
	eqm_wake_up_function(&error_code);
}

static int eqm_decryption_mmap(struct file* pf, struct vm_area_struct* vma)
{
	spin_lock(&g_de_data_spinlock);

	vma->vm_ops = &eqm_vm_ops;
	if (remap_pfn_range(vma, vma->vm_start, 
			virt_to_phys(gp_de_data->buf) >> PAGE_SHIFT, vma->vm_end - vma->vm_start, 
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
		spin_lock(&g_de_data_spinlock);
		put_user(gp_de_data->len, argp);
		spin_unlock(&g_de_data_spinlock);
		break;
	case MISC_EQM_GET_PAGE_SIZE:
		{
			unsigned long page_size = PAGE_SIZE;
			put_user(page_size, argp);
			break;
		}
	case MISC_EQM_NET_STATUS: /* 网络状态 */
		{
			unsigned int status = 0;
			get_user(status, argp);
			if(status == 1) /* net ok*/
			{/* 重新识别磁盘分区(去调用config_encryption_disk.c中的接口) */
				/*
				 * fd = sys_open("/dev/sdb", 0, 0);
				 * sys_ioctl(fd, BLKRRPART, 0);
				 */
			}
			break;
		}
	case MISC_EQM_GET_DISK_PARTITION:
		{
			int fd = sys_open("/dev/sdb", 0, 0);
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
		printk(KERN_INFO "Unkown command id=%d\n", cmd);
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

