
#include "eqm.h"

struct mount_info
{
	char dev[256];			/* 设备路径 */
	char mount_point[256];	/* 挂载点 */
	char fs_type[10];	/* 文件系统名 */
	char lov_name[50];	/* 逻辑卷名 */
};

static struct mount_info g_mount[30] = {0};

int read_mount_info(char** argv,const char* config_name)
{
	if(!config_name || !argv) {
		PLog("[Error] config name is null\n");
		return -1;
	}
	char exe_path[1024] = {0}, config_path[1024] = {0};
	strncpy(exe_path, argv[0], strlen(argv[0]));
	char*pp = exe_path;
	char* qq = NULL;
	while(( pp = strstr(pp, "/")) != NULL)
	{
		qq = pp++;
	}
	*qq = '\0';
	sprintf(config_path, "%s/%s", exe_path, config_name);
	FILE* pf = fopen(config_path, "r");
	if (pf <= 0) {
		PLog("[error] open file [%s] failed.\n", config_path);
		return -1;
	}
	char *p = NULL, *q = NULL;
	char resultbuf[1024] = {0};
	int i = 0;
	while(fgets(resultbuf, sizeof(resultbuf) - 1, pf) != NULL )
	{
		if(resultbuf[0] == '#')
			continue;
		 
		sscanf(resultbuf, "%s\t%s\t%s\t%s", 
			g_mount[i].dev,g_mount[i].mount_point, g_mount[i].fs_type, g_mount[i].lov_name);

		PLog("%s:%s:%s:%s\n", g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type, g_mount[i].lov_name);
		i++;
	}
	fclose(pf);
		
	return 0;
}

int vgchange_encryption_disk(void)
{
	int ret = 0;
	int i = 0;
}

int mount_encryption_disk(void)
{
	int ret = 0;
	int i = 0;
	while(strlen(g_mount[i].dev))
	{
		if(strncmp(g_mount[i].lov_name, "NULL", strlen("NULL"))) {
			char cmdbuf[256] = {0};
			sprintf(cmdbuf, "vgchange -a y %s", g_mount[i].lov_name);
			ret = system(cmdbuf);
			if (ret < 0) {
				PLog("[Error] run cmd \"%s\" failed.", cmdbuf);
				i++;
				continue;
			}
		}
		ret= mount(g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type, 0, NULL);
		if(ret < 0){
			PLog("[Error] mount [%s] at [%s] failed. filesystem type [%s]\n",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		}
		else
			PLog("mount [%s] at [%s] success. filesystem type [%s]\n",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		i++;
	}
	return 0;
}

int umount_encryption_disk(void)
{
	int ret = 0, i = 0, j = 0;
	while(strlen(g_mount[i].dev))
	{
		ret= umount(g_mount[i].mount_point);
		if(ret < 0){			
			if(errno == EBUSY && j++ < 3)
			{				
				PLog("[Info] umount [%s] at [%s] failed. filesystem type [%s], retry it again.",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
				sleep(3);
				continue;
			}
			PLog("[Error] umount [%s] at [%s] failed (errno=%d). filesystem type [%s]",
				g_mount[i].dev, g_mount[i].mount_point, errno, g_mount[i].fs_type);
		}
		else
			PLog("umount [%s] at [%s] success. filesystem type [%s]",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		j = 0;
		i++;
	}
	return 0;
}

/**ltl
 * 功能: 重新获取主盘的分区
 * 参数: fullname->主盘路径(/dev/sdb)
 * 返回值:
 * 说明:
 */
int get_disk_partition(const char *fullname)
{
#if 1
	int ret = 0;
	int fd = open(EQM_DECRYPTION_DEVICE, O_RDWR);
	if (fd <= 0) {
		PLog("[error] open file [%s] failed.\n", EQM_DECRYPTION_DEVICE);
		return -1;
	}
	if(!fullname) {
		PLog("[error] fullname is null.\n");
		goto ERROR;
	}
	
	ret = ioctl(fd, MISC_EQM_GET_DISK_PARTITION, fullname);
	if (fd < 0) {
		PLog("[error] get partition failed. cmd=MISC_EQM_GET_DISK_PARTITION\n");
		return -1;
	}
ERROR:
	close(fd);
#else
	int ret = 0;
	int fd = open(fullname, O_RDWR);
	if (fd <= 0) {
		PLog("[error] open file [%s] failed.\n", fullname);
		return -1;
	}
	if(!fullname) {
		PLog("[error] fullname is null.\n");
		goto ERROR;
	}
	
	ret = ioctl(fd, BLKRRPART, 0);
	if (fd < 0) {
		PLog("[error] get partition failed. cmd=BLKRRPART\n");
		return -1;
	}
	ERROR:
	close(fd);
#endif

	return 0;
}



