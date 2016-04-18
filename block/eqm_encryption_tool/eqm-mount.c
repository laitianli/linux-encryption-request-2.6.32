
#include "eqm.h"

struct mount_info
{
	char dev[256];
	char mount_point[256];
	char fs_type[10];
};

static struct mount_info g_mount[30] = {0};

int read_mount_info(char** argv,const char* config_name)
{
	if(!config_name || !argv) {
		printf("[Error] config name is null\n");
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
		printf("[error] open file [%s] failed.\n", config_path);
		return -1;
	}
	char *p = NULL, *q = NULL;
	char resultbuf[1024] = {0};
	int i = 0;
	while(fgets(resultbuf, sizeof(resultbuf) - 1, pf) != NULL )
	{
		if(resultbuf[0] == '#')
			continue;
		 
		sscanf(resultbuf, "%s\t%s\t%s", 
			g_mount[i].dev,g_mount[i].mount_point, g_mount[i].fs_type);

		printf("%s:%s:%s\n", g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		i++;
	}
	fclose(pf);
		
	return 0;
}


int mount_encryption_disk(void)
{
	int ret = 0;
	int i = 0;
	while(strlen(g_mount[i].dev))
	{
		ret= mount(g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type, 0, NULL);
		if(ret < 0){
			printf("[Error] mount [%s] at [%s] failed. filesystem type [%s]\n",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		}
		else
			printf("mount [%s] at [%s] success. filesystem type [%s]\n",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		i++;
	}
	return 0;
}

int umount_encryption_disk(void)
{
	int ret = 0;
	int i = 0;
	while(strlen(g_mount[i].dev))
	{
		ret= umount(g_mount[i].mount_point);
		if(ret < 0){
			printf("[Error] umount [%s] at [%s] failed. filesystem type [%s]\n",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		}
		else
			printf("umount [%s] at [%s] success. filesystem type [%s]\n",
				g_mount[i].dev, g_mount[i].mount_point, g_mount[i].fs_type);
		i++;
	}
	return 0;
}


int get_disk_partition(void)
{
	int ret = 0;
	int fd = open(EQM_DECRYPTION_DEVICE, O_RDWR);
	if (fd <= 0) {
		printf("[error] open file [%s] failed.\n", EQM_DECRYPTION_DEVICE);
		return -1;
	}

	ret = ioctl(fd, MISC_EQM_GET_DISK_PARTITION, 0);
	if (fd < 0) {
		printf("[error] get partition failed. cmd=MISC_EQM_GET_DISK_PARTITION\n", EQM_DECRYPTION_DEVICE);
		return -1;
	}

	close(fd);
	return 0;
}



