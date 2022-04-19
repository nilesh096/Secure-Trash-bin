#include <asm/unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/ioctl.h>

#define MAGIC 'U'
#define NUM 0
#define FS_STB_UNDELETE _IOR(MAGIC, NUM, unsigned long) 

typedef struct argument {
	char *infile;
	int flen;
} arguments;


int main(int argc, char *argv[])
{
	int opt, ret = 0, fd;
    char *cwd = NULL;
    FILE *fp = NULL;
    arguments *args = NULL;

    args = (arguments *)malloc(sizeof(arguments));
    args->infile = NULL;

    while((opt = getopt(argc, argv, "h:u:")) != -1)
    {
        switch(opt)
        {
            case 'h':
                    printf("\nUsage: ./stbfsctl -u ${FILE_NAME} ");
                    printf("\nOptions:\n");
                    printf("-U: Undelete a file already deleted and stored in .stb folder\n");
                    break;
            
            case 'u':
                    if (!optarg)
                    {
                        printf("ERROR: File name not specified\n\
                                File name can't be empty\n\
                                Try stbfsctl -h\n");
                        ret = -1;
                        goto out;
                    }
                    if(strlen(optarg) == 0)
                    {
                        printf("ERROR: File name not specified\n\
                                File name can't be empty\n\
                                Try stbfsctl -h\n");
                        ret = -1;
                        goto out;
                    }
                    args->infile = (char *)malloc(strlen(optarg) + 1);
                    if (args->infile == NULL)
                    {
                        printf("Error in allocating memory\n");
                        ret = -1;
                        goto out;
                    }            
                    strcpy(args->infile, optarg);
                    args->flen = strlen(args->infile);
                    break;   
            default:
                    printf("No options recognized\n\
                            Try stbfsctl -h\n");
                    ret = -1;
                    goto out;    
        }
    }
    if (args->infile == NULL)
    {
        ret = -1;
        printf("No options provided\n");
        goto out;
    }

    printf("File name is %s\n", args->infile);

    cwd = getcwd(NULL,0);
    if (cwd == NULL)
    {
        ret = -1;
        printf("Error in getting the CWD\n");
        goto out;
    }
    printf("Current Working directory is %s\n", cwd);

    fp = fopen(cwd,"r");
    if (fp == NULL)
    {
        ret = -1;
        printf("Error in opening file\n");
        goto out;
    }
    fd = fileno(fp);
    printf("Fd = %d\n", fd);

    ret = ioctl(fd, FS_STB_UNDELETE, (int *)args);
    printf("Result = %d\n", ret);

out:
    if (cwd != NULL)
        free(cwd);
    if (args->infile != NULL)
        free(args->infile);
    if (args != NULL)
        free(args);
    if (fp != NULL)
    {
        printf("Closing file pointer\n");
        fclose(fp);
    }
    return ret;
}