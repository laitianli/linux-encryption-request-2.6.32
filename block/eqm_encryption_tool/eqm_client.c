#include "eqm.h"
#include "eqm_socket.h"

/* 是否使用本地的加密算法 
 * 0: 使用网络功能进行加解密
 * 1: 使用本地加解密算法。
 */
#define LOCAL_ENCRYPTION_ALGORITHM 1 

pthread_t encryption_pid;
pthread_t decryption_pid;

FILE* logfd = NULL;
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
		PLog("%c ", buf[i]);
}

#define PBuf(STR, COUNT, buf, len) \
	do {\
		static int i = 0;\
		if(i++ < COUNT)\
		{	PLog("%s:\n", STR); \
			if(len > 0)print_buf(buf, len);\
			}\
	}while(0)
struct speed_info {
	unsigned long data_len;
	struct timeval begin_time;
	struct timeval end_time;
//	unsigned long time;
};
static struct speed_info  g_encryption_info = {0};
static struct speed_info  g_decryption_info = {0};
struct timeval tv_start;
struct timeval tv_end;

#define POLLTIMEOUT 1000

void set_begin_speed(const char* dev, struct eqm_data_info* info)
{
	if(!strcmp(dev, EQM_ENCRYPTION_DEVICE)) {
		if(g_encryption_info.data_len == 0) {
			gettimeofday(&g_encryption_info.begin_time, NULL);
			memset(&g_encryption_info.end_time, 0, sizeof(struct timeval));			
		}
		g_encryption_info.data_len += info->len;
	}
	else if(!strcmp(dev, EQM_DECRYPTION_DEVICE)) {
		if(g_decryption_info.data_len == 0) {
			gettimeofday(&g_decryption_info.begin_time, NULL);
			memset(&g_decryption_info.end_time, 0, sizeof(struct timeval));
		}
		g_decryption_info.data_len += info->len;
	}
}

void show_speed_rate(const char* dev, struct speed_info* info)
{
	unsigned long timeout = info->end_time.tv_sec - info->begin_time.tv_sec;
	PLog("\"%s\" speed [%5.2f KB/s]\n", dev, ((float)(info->data_len /1024 * 100) / (float)timeout ) / 100);

}

void set_end_speed(const char* dev)
{
	if(!strcmp(dev, EQM_ENCRYPTION_DEVICE)) {
		if(g_encryption_info.data_len != 0) {
			gettimeofday(&g_encryption_info.end_time, NULL);
			show_speed_rate(dev, &g_encryption_info);
		}
		memset(&g_encryption_info, 0, sizeof(struct speed_info));
	}
	else if(!strcmp(dev, EQM_DECRYPTION_DEVICE)) {
		if(g_decryption_info.data_len != 0) {
			gettimeofday(&g_decryption_info.end_time, NULL);
			show_speed_rate(dev, &g_decryption_info);
		}		
		memset(&g_decryption_info, 0, sizeof(struct speed_info));
	}
}

/* 加密线程和解密线程的实现过程。 */
static int do_kernel_mmap_data(const char* dev, encryption_fn fn)
{
	unsigned char* addr = NULL;
	int ret = 0;
	unsigned int mmap_size = 0 ;
	unsigned int page_size = 0 ;
	if(!dev || !fn) {
		PLog("[error] argument invalid.\n");
		return -1;
	}
	/* 打开设备文件 */
	int fd = open(dev, O_RDWR);
	if (fd <= 0) {
		PLog("[error] open file [%s] failed.\n", dev);
		return -1;
	}
	/* 获取OS 的PAGE_SIZE */
	ret = ioctl(fd, MISC_EQM_GET_PAGE_SIZE, &page_size);
	if (fd < 0) {
		PLog("[error] get page size failed. cmd=MISC_EQM_GET_PAGE_SIZE\n", dev);
		return -1;
	}
	PLog("[%s] page size is %d\n", dev, page_size);
	struct pollfd fds[1] = {fd, POLLIN, 0};
	memset(&g_encryption_info, 0, sizeof(struct speed_info));
	memset(&g_decryption_info, 0, sizeof(struct speed_info));
	do
	{
		ret = poll(fds, 1, POLLTIMEOUT); /* poll模型 */
		if(ret < 0)
		{
			PLog("[error]=poll error.\n");
			return -1;
		} else if(ret == 0) {
			if(!strcmp(dev, EQM_ENCRYPTION_DEVICE))
				encryption_thread_is_ok = 1;
			if(!strcmp(dev, EQM_DECRYPTION_DEVICE))
				decryption_thread_is_ok = 1;
			//PLog("read [%s] dev file thread poll timeout.\n", dev);
			set_end_speed(dev);
			continue;
		}
		else if(ret > 0) {	
			struct eqm_data_info info;
			 /* 获取数据相关信息，数据长度和当前数据在page中的偏移量 */
			ret = ioctl(fd, MISC_EQM_GET_DATA_LENGTH, &info);
			if (fd < 0) {
				printf("[error] get data info failed. cmd=MISC_EQM_GET_DATA_LENGTH\n", dev);
				return -1;
			}
			
			set_begin_speed(dev, &info);
			/* 内存映射 */
			addr =(unsigned char*)mmap(0, page_size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
			/* 调用加解密接口 */
			ret = fn(addr + info.offset, info.len);
			if(ret != info.len) {	/* 通知操作做错误处理 */
				int error_code = -1;
				PLog("[Error] ret != page_size [%s].\n", dev);
				ret = ioctl(fd, MISC_EQM_ENCRYPTION_FAILED, &error_code);
			}
			/* 同步文件 */
			fsync(fd);
			/* 反映射 */
			munmap(addr, page_size);
			continue;
		}
	}while(1);

	close(fd);
	return 0;
}
/* 加密线程 */ 
void* encryption_thread(void* data)
{
#if LOCAL_ENCRYPTION_ALGORITHM > 0 
	do_kernel_mmap_data(EQM_ENCRYPTION_DEVICE, encryption);
#else
	do_kernel_mmap_data(EQM_ENCRYPTION_DEVICE, encryption_in_network);
#endif
	PLog("%s:%d thread exit.\n", __func__, __LINE__);
	return NULL;
}

/* 解密线程 */
void* decryption_thread(void* data)
{
#if LOCAL_ENCRYPTION_ALGORITHM > 0 
	do_kernel_mmap_data(EQM_DECRYPTION_DEVICE, decryption);
#else
	do_kernel_mmap_data(EQM_DECRYPTION_DEVICE, decryption_in_network);
#endif
	PLog("%s:%d thread exit.\n", __func__, __LINE__);
	return NULL;
}

int test_fun(char** argv)			
{
	//read_mount_info(argv, EQM_MOUNT_CONFIG);
	//mount_encryption_disk();
	//umount_encryption_disk();
	return 0;
}
/* 设置网络状态 */
int set_network_status(int status)
{
	int ret = 0;
	int fd = open(EQM_DECRYPTION_DEVICE, O_RDONLY);
	if (fd <= 0) {
		PLog("[error] open file [%s] failed.\n", EQM_DECRYPTION_DEVICE);
		return -1;
	}
	ret = ioctl(fd, MISC_EQM_NET_STATUS, &status);
	if (fd < 0) {
		PLog("[error] get page size failed. cmd=MISC_EQM_GET_PAGE_SIZE\n", EQM_DECRYPTION_DEVICE);
		return -1;
	}
	close(fd);
	return 0;
}

int set_logfd(char* tag)
{
	int is_deamon = 0;
		if(tag && strlen(tag))
		is_deamon = atoi(tag);
	else 
		is_deamon = 0;

	if(is_deamon){
		logfd = fopen("/tmp/encryption_client.log", "a");
		if(!logfd)
			logfd = stdout;
	}
	else
		logfd = stdout;
	return is_deamon;
}

int main(int argc, char** argv)
{
	//return test_fun(argv);
	int ret = 0;	

	setup_signal(set_logfd(argv[1]));
//	printf("MISC_EQM_GET_DATA_LENGTH=%d\n",MISC_EQM_GET_DATA_LENGTH);
//	printf("MISC_EQM_GET_DISK_PARTITION=%d\n",MISC_EQM_GET_DISK_PARTITION);
//	return 0;
	/* 读取加密盘挂载信息 */
	read_mount_info(argv, EQM_MOUNT_CONFIG);	
	
#if LOCAL_ENCRYPTION_ALGORITHM <= 0 
	/* 初始化网络 */
	ret = network_init(argc, argv);
	if(ret < 0) {
		PLog("[Error] can't connet to service.\n ");
		goto NET_ERROR;
	}
#endif


	
	/* 设置网络状态 */
	set_network_status(1);
	/* 创建加密线程 */
	ret = pthread_create(&encryption_pid, NULL, encryption_thread, NULL);
	if(ret) {
		PLog("[Error] pthread_create encryption failed.\n");
		return -1;
	}
	/* 创建解密线程 */
	ret = pthread_create(&decryption_pid, NULL, decryption_thread, NULL);
	if(ret) {
		PLog("[Error] pthread_create decryption failed.\n");
		return -1;
	}
	/*等待解密线程OK */
	while(!decryption_thread_is_ok )
		sleep(1);
	
	get_disk_partition("/dev/sdb");

	mount_encryption_disk();
#if LOCAL_ENCRYPTION_ALGORITHM <= 0 
	heartbeat_check(set_network_status); /* 心跳 */
#endif	
	/* 查看event_sd.c */
	pthread_join(encryption_pid, NULL);
	pthread_join(decryption_pid, NULL);
#if LOCAL_ENCRYPTION_ALGORITHM <= 0 	
NET_ERROR:
	network_close();
#endif	
	fclose(logfd);
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
	return encryption_data_send_recv(buf, len);
}


static int decryption_in_network(unsigned char *buf, int len)
{
	return decryption_data_send_recv(buf, len);
}
#endif

