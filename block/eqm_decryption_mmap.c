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
#include <linux/spinlock.h>

#include "eqm_encryption.h"

#define MISC_EQM_ENCRYPTION_NAME  "eqm-decryption"

static wait_queue_head_t eqm_decryption_qh; 
static wait_queue_head_t eqm_complete_qh;
static atomic_t be_eqm_decryption_complete;
static atomic_t be_eqm_decryption_read;

static int eqm_decryption_open(struct inode* inode, struct file* file);
static int eqm_decryption_release(struct inode* inode, struct file* file);
static unsigned int eqm_decryption_poll(struct file* pf, struct poll_table_struct* table);
static int eqm_decryption_mmap(struct file* pf, struct vm_area_struct* vma);
static int eqm_decryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg);
static void eqm_decryption_vm_close(struct vm_area_struct * area);


struct decryption_data {
	unsigned char* 		buf;
	unsigned int 		len;
}; 
static struct decryption_data *gpdata = NULL;

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
	.name = MISC_EQM_ENCRYPTION_NAME, 
	.fops = &eqm_decryption_fops,
};

static struct vm_operations_struct eqm_vm_ops = {
	.close = eqm_decryption_vm_close,
	//.fault = eqm_encryption_vm_fault,
};
static LIST_HEAD(g_list_decryption_data);

static spinlock_t g_data_spinlock;

static void eqm_wake_up_function(void* data)
{
 	atomic_set(&be_eqm_decryption_read, 0);
	wake_up_interruptible(&eqm_complete_qh);
}

void wake_to_network_decryption(void)
{
	atomic_set(&be_eqm_decryption_read, 1);	

	wake_up_interruptible(&eqm_decryption_qh); /* 唤醒用户空间的读数据进程 */
	/* 等待eqm_wake_up_function函数被执行到 */
	wait_event_interruptible(eqm_complete_qh, atomic_read(&be_eqm_decryption_read)==0);

	gpdata->buf = NULL;
	gpdata->len = 0;
}
EXPORT_SYMBOL(wake_to_network_decryption);

void add_decryption_data(unsigned char* buf, unsigned int len)
{
	if(!gpdata)
		return ;
	spin_lock(&g_data_spinlock);
	gpdata->buf = buf;
	gpdata->len = len;	
	spin_unlock(&g_data_spinlock);

}
EXPORT_SYMBOL(add_decryption_data);


void clear_decryption_data(void)
{
	spin_lock(&g_data_spinlock);
	gpdata->buf = NULL;
	gpdata->len = 0;
	spin_unlock(&g_data_spinlock);
	atomic_set(&be_eqm_decryption_read, 0);
}
EXPORT_SYMBOL(clear_decryption_data);


static int eqm_decryption_open(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
	gpdata = kzalloc(sizeof(struct decryption_data), GFP_KERNEL);
	clear_decryption_data();
	return 0;
}

static int eqm_decryption_release(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
	kfree(gpdata);
	gpdata = NULL;
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
	eqm_wake_up_function(NULL);
}

static int eqm_decryption_mmap(struct file* pf, struct vm_area_struct* vma)
{
	vma->vm_ops = &eqm_vm_ops;
	spin_lock(&g_data_spinlock);
	if (remap_pfn_range(vma, vma->vm_start, 
			virt_to_phys(gpdata->buf) >> PAGE_SHIFT, vma->vm_end - vma->vm_start, 
			vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
		}
  	spin_unlock(&g_data_spinlock);
	
	return 0;
}

static int eqm_decryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg)
{
	unsigned long __user *argp = (void __user *)arg;
	switch (cmd)
	{
	case MISC_EQM_GET_DATA_LENGTH:
		spin_lock(&g_data_spinlock);
		put_user(gpdata->len, argp);
		spin_unlock(&g_data_spinlock);
		break;
	case MISC_EQM_NET_STATUS: /* 网络状态 */
		{
			unsigned int status = 0;
			get_user(status, argp);
			if(status == 1) /* net ok*/
			{/* 重新识别磁盘分区(去调用config_encryption_disk.c中的接口) */
				/*
				 * fd = sys_open(name, 0, 0);
				 * sys_ioctl(fd, BLKRRPART, 0);
				 */
			}
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

	spin_lock_init(&g_data_spinlock);

	init_waitqueue_head(&eqm_decryption_qh);
	init_waitqueue_head(&eqm_complete_qh);
	
	atomic_set(&be_eqm_decryption_read, 0);
	atomic_set(&be_eqm_decryption_complete,0);

    ret = misc_register(&eqm_decryption_dev);
	if(!ret)
		printk(KERN_INFO"[INFO] load eqm encryption module success.\n");
	return ret;
}

static void __exit eqm_decryption_module_exit(void)
{
    printk("[:%s%s:%d]\n",__FILE__,__func__,__LINE__);
 	misc_deregister(&eqm_decryption_dev);
}

module_init(eqm_decryption_module_init);
module_exit(eqm_decryption_module_exit);

MODULE_LICENSE("GPL");

