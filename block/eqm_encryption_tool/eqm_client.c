#include "eqm.h"


typedef int (*encryption_fn)(unsigned char *buf, int len);
#define LOCAL_ENCRYPTION_ALGORITHM 0	/* 是否使用本地的加密算法 */


pthread_t encryption_pid;
pthread_t decryption_pid;

static int encryption_thread_is_ok = 0;
static int decryption_thread_is_ok = 0;

#if LOCAL_ENCRYPTION_ALGORITHM > 0	
static int encryption(unsigned char *buf, int len);
static int decryption(unsigned char *buf, int len);
#else
static int encryption_in_network(unsigned char *buf, int len);
static int decryption_in_network(unsigned char *buf, int len);
#endif

void print_buf(unsigned char* buf, int len)
{
	int i = 0;
	for(i = 0; i < len; i++)
		printf("%c ", buf[i]);
}

#define PBuf(STR, COUNT, buf, len) \
	do {\
		static int i = 0;\
		if(i++ < COUNT)\
		{	printf("%s:\n", STR); \
			if(len > 0)print_buf(buf, len);\
			}\
	}while(0)
static int do_kernel_mmap_data(const char* dev, encryption_fn fn)
{
	unsigned char* addr = NULL;
	int ret = 0;
	unsigned int mmap_size = 0 ;
	unsigned int page_size = 0 ;
	if(!dev || !fn) {
		printf("[error] argument invalid.\n");
		return -1;
	}
	int fd = open(dev, O_RDWR);
	if (fd <= 0) {
		printf("[error] open file [%s] failed.\n", dev);
		return -1;
	}
	ret = ioctl(fd, MISC_EQM_GET_PAGE_SIZE, &page_size);
	if (fd < 0) {
		printf("[error] get page size failed. cmd=MISC_EQM_GET_PAGE_SIZE\n", dev);
		return -1;
	}
	printf("[%s] page size is %d\n", dev, page_size);
	struct pollfd fds[1] = {fd, POLLIN, 0};

	do
	{
		ret = poll(fds, 1, 1000);
		if(ret < 0)
		{
			printf("[error]=poll error.\n");
			return -1;
		} else if(ret == 0) {
			if(!strcmp(dev, EQM_ENCRYPTION_DEVICE))
				encryption_thread_is_ok = 1;
			if(!strcmp(dev, EQM_DECRYPTION_DEVICE))
				decryption_thread_is_ok = 1;
			printf("read [%s] dev file thread poll timeout.\n", dev);
			continue;
		}
		else if(ret > 0) {			
	 
		//	ret = ioctl(fd, MISC_EQM_GET_DATA_LENGTH, &mmap_size);
		//	if (fd < 0) {
			//	printf("[error] get page size failed. cmd=MISC_EQM_GET_PAGE_SIZE\n", dev);
		//		return -1;
		//	}
			addr =(unsigned char*)mmap(0, page_size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
					
			ret = fn(addr, page_size);
			if(ret != page_size) {	/* 通知操作做错误处理 */
				int error_code = -1;
				printf("[Error] ret != page_size [%s].\n", dev);
				ret = ioctl(fd, MISC_EQM_ENCRYPTION_FAILED, &error_code);
			}
			fsync(fd);	
			munmap(addr, page_size);
			continue;
		}
	}while(1);

	close(fd);
	return 0;
}
 
void* encryption_thread(void* data)
{
	do_kernel_mmap_data(EQM_ENCRYPTION_DEVICE, encryption_in_network);
	printf("%s:%d thread exit.\n", __func__, __LINE__);
	return NULL;
}


void* decryption_thread(void* data)
{
	do_kernel_mmap_data(EQM_DECRYPTION_DEVICE, decryption_in_network);
	printf("%s:%d thread exit.\n", __func__, __LINE__);
	return NULL;
}

int test_fun(char** argv)			
{
	read_mount_info(argv, EQM_MOUNT_CONFIG);
	mount_encryption_disk();
	umount_encryption_disk();
	return 0;
}


int main(int argc, char** argv)
{
//	return test_fun(argv);
	int ret = 0;
	
	//read_mount_info(argv, EQM_MOUNT_CONFIG);
	
//	setup_signal();
	ret = pthread_create(&encryption_pid, NULL, encryption_thread, NULL);
	if(ret) {
		printf("[Error] pthread_create encryption failed.\n");
		return -1;
	}

	ret = pthread_create(&decryption_pid, NULL, decryption_thread, NULL);
	if(ret) {
		printf("[Error] pthread_create decryption failed.\n");
		return -1;
	}
	/*等待解密线程OK */
	while(!decryption_thread_is_ok )
		sleep(1);
	
	{/* 等网络功能OK */
	}
	//printf("==========\n");
	//get_disk_partition();
	//printf("====adasfdasfa======\n");
	//mount_encryption_disk();
	/* 查看event_sd.c */
	pthread_join(encryption_pid, NULL);
	pthread_join(decryption_pid, NULL);

	return 0;
}

#if LOCAL_ENCRYPTION_ALGORITHM > 0	
static int encryption(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
 		buf[i] += 1;

	return len;
}


static int decryption(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
		buf[i] -= 1;
	return len;
}
#else
static int encryption_in_network(unsigned char *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
 		buf[i] += 1;

	return len;
}


static int decryption_in_network(unsigned char *buf, int len)
{
	int i = 0;
	
	for (i = 0; i < len; i++)
		buf[i] -= 1;
	return len;
}
#endif

