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

#define MISC_EQM_ENCRYPTION_NAME  "eqm-encryption"

static wait_queue_head_t eqm_encryption_qh; 
static wait_queue_head_t eqm_complete_qh;
static atomic_t be_eqm_encryption_complete;
static atomic_t be_eqm_encryption_read;

static int eqm_encryption_open(struct inode* inode, struct file* file);
static int eqm_encryption_release(struct inode* inode, struct file* file);
static unsigned int eqm_encryption_poll(struct file* pf, struct poll_table_struct* table);
static int eqm_encryption_mmap(struct file* pf, struct vm_area_struct* vma);
static int eqm_encryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg);
static void eqm_encryption_vm_close(struct vm_area_struct * area);
static int eqm_encryption_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

struct encryption_data {
	unsigned char* 		buf;
	unsigned int 		len;
	struct list_head 	list;
}; 
static struct encryption_data *gpdata = NULL;
struct eqm_wake_up {
	eqm_wake_up_fn eqm_wake_up_callback;
	void *data;
};

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
	//.fault = eqm_encryption_vm_fault,
};
static LIST_HEAD(g_list_encryption_data);
static unsigned int g_data_length = 0;
static struct eqm_wake_up g_eqm_wakeup;
static spinlock_t g_data_spinlock;

static void eqm_wake_up_function(void* data)
{
 	atomic_set(&be_eqm_encryption_read, 0);
	wake_up_interruptible(&eqm_complete_qh);
}

void wake_to_network_encryption(void)
{
	atomic_set(&be_eqm_encryption_read, 1);	

	wake_up_interruptible(&eqm_encryption_qh); /* 唤醒用户空间的读数据进程 */
	/* 等待eqm_wake_up_function函数被执行到 */
	wait_event_interruptible(eqm_complete_qh, atomic_read(&be_eqm_encryption_read)==0);

	gpdata->buf = NULL;
	gpdata->len = 0;
}
EXPORT_SYMBOL(wake_to_network_encryption);

void add_encryption_data(unsigned char* buf, unsigned int len, struct page* page)
{
#if 0
	struct encryption_data *pdata = kzalloc(sizeof(struct encryption_data), GFP_KERNEL);
	if(!pdata) {
		printk(KERN_ERR"[error] alloc memry failed.\n");
		return ;
	}
	pdata->buf = buf;
	pdata->len = len;
	INIT_LIST_HEAD(&pdata->list);
	spin_lock(&g_data_spinlock);
	list_add(&pdata->list, &g_list_encryption_data);
	g_data_length += len;
	spin_unlock(&g_data_spinlock);
#else
	if(!gpdata)
		return ;
	spin_lock(&g_data_spinlock);
	gpdata->buf = buf;
	gpdata->len = len;
	
	spin_unlock(&g_data_spinlock);
#endif
}
EXPORT_SYMBOL(add_encryption_data);


void clear_encryption_data(void)
{
	spin_lock(&g_data_spinlock);
#if 0
	struct encryption_data *pdata, *n = NULL;
	
	list_for_each_entry_safe(pdata, n,&g_list_encryption_data, list) {
		list_del(&pdata->list);
		kfree(pdata);
		pdata = NULL;
	}
	g_data_length = 0;		
#else
	gpdata->buf = NULL;
	gpdata->len = 0;
	
#endif
	spin_unlock(&g_data_spinlock);
	atomic_set(&be_eqm_encryption_read, 0);
}
EXPORT_SYMBOL(clear_encryption_data);


static int eqm_encryption_open(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
	gpdata = kzalloc(sizeof(struct encryption_data), GFP_KERNEL);
	clear_encryption_data();
	return 0;
}

static int eqm_encryption_release(struct inode* inode, struct file* file)
{
	printk("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
	kfree(gpdata);
	gpdata = NULL;
	return 0;
}
 
static unsigned int eqm_encryption_poll(struct file* pf, struct poll_table_struct* table)
{
	unsigned int mask = 0;

	poll_wait(pf, &eqm_encryption_qh, table);	/* read */
	if(atomic_read(&be_eqm_encryption_read) == 1)/* 表示设备可以读取 */
		mask |= POLLIN | POLLRDNORM;
 
	return mask;
}
static void eqm_encryption_vm_close(struct vm_area_struct * area)
{
	eqm_wake_up_function(NULL);
}

static int eqm_encryption_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#if 0
	spin_lock(&g_data_spinlock);
	struct page *page= gpdata->ppage;
	if(!page)
	{
		spin_unlock(&g_data_spinlock);
		return VM_FAULT_SIGBUS;
	}
	get_page(page);
	vmf->page = page;
	spin_unlock(&g_data_spinlock);
#endif
	return 0;
}
static int eqm_encryption_mmap(struct file* pf, struct vm_area_struct* vma)
{
	struct encryption_data* pdata = NULL;
	int offset_len = 0;
	//unsigned long flags;
//	unsigned long size = vma->vm_end - vma->vm_start;
	//if(!size || size != gpdata->len) {
	//	printk(KERN_WARNING "mmap size not equel to data size, Please call ioctl(MISC_EQM_GET_DATA_LENGTH) to get the length.(%d:%d)\n", size, gpdata->len);
	//}


	vma->vm_ops = &eqm_vm_ops;

#if 1
	spin_lock(&g_data_spinlock);
#if 0
	list_for_each_entry(pdata, &g_list_encryption_data, list) {
		if (remap_pfn_range(vma, vma->vm_start + offset_len, 
			virt_to_phys(pdata->buf) >> PAGE_SHIFT, pdata->len, 
			vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
		}

		offset_len += pdata->len;
	}
	
#endif
#if 1 /*ok*/
	if (remap_pfn_range(vma, vma->vm_start, 
			virt_to_phys(gpdata->buf) >> PAGE_SHIFT, vma->vm_end - vma->vm_start, 
			vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
		}
#endif	
#if 0

	if (remap_pfn_range(vma, vma->vm_start, 
			page_to_pfn(gpdata->ppage), PAGE_SIZE, 
			vma->vm_page_prot)) {
			spin_unlock(&g_data_spinlock);
			return -EAGAIN;
		}
	#endif	
	spin_unlock(&g_data_spinlock);
#endif	
	return 0;
}

static int eqm_encryption_ioctl(struct inode *inode, struct file *pf, unsigned int cmd, unsigned long arg)
{
	unsigned long __user *argp = (void __user *)arg;
//	unsigned long flags;
	switch (cmd)
	{
	case MISC_EQM_GET_DATA_LENGTH:
		spin_lock(&g_data_spinlock);
		put_user(gpdata->len, argp);
		//put_user(g_data_length, argp);
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

static int __init eqm_encryption_module_init(void)
{
	int ret = 0;

	spin_lock_init(&g_data_spinlock);

	init_waitqueue_head(&eqm_encryption_qh);
	init_waitqueue_head(&eqm_complete_qh);
	
	atomic_set(&be_eqm_encryption_read, 0);
	atomic_set(&be_eqm_encryption_complete,0);

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

