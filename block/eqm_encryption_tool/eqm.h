#ifndef _EQM_H_
#define _EQM_H_
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <limits.h>
#include <sys/mount.h>
#include <signal.h>

#define EQM_MOUNT_CONFIG	"eqm_fstab.conf"
#define EQM_DISK_NAME 		"/proc/encryption_disk_name"
#define EQM_ENCRYPTION_DEVICE "/dev/eqm-encryption"
#define EQM_DECRYPTION_DEVICE "/dev/eqm-decryption"
/* ioctl命令 */
/* 获取数据大小 */
#define MISC_EQM_GET_DATA_LENGTH	('E' << 16 | 'Q' << 8 | 'A')

/* 网络状态(1:表示网络连通；0:表示网络断开) */
#define MISC_EQM_NET_STATUS			('E' << 16 | 'Q' << 8 | 'B')

/* 加解密失败用消息通知kernel，参数arg为错误码*/
#define MISC_EQM_ENCRYPTION_FAILED	('E' << 16 | 'Q' << 8 | 'C')

/* 映射完成 */
#define MISC_EQM_MMAP_COMPLETE	('E' << 16 | 'Q' << 8 | 'D')

/* 获取PAGE_SIZE大小 */
#define MISC_EQM_GET_PAGE_SIZE	('E' << 16 | 'Q' << 8 | 'E')

/* 获取磁盘分区 */
#define MISC_EQM_GET_DISK_PARTITION ('E' << 16 | 'Q' << 8 | 'F')

int read_mount_info(char** argv, const char* config_name);
/* 挂载加密盘 */
int mount_encryption_disk(void); 

/* 卸载加密盘 */
int umount_encryption_disk(void);

int setup_signal(void);

int get_disk_partition(void);
#endif

