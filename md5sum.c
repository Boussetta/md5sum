#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>

#define BUFSIZE	1024*16

char* compute_md5sum (const char *filepath);

#if !defined(_OSD_POSIX) && !defined(__DJGPP__)
int read(int, void *, unsigned int);
#endif

int main(int argc, char **argv)
{
  char *MD5sum;	
  MD5sum = compute_md5sum (argv[1]);
  if (!MD5sum)
  {
	printf ("Error while computing MD5sum\n");
	return EXIT_FAILURE;
  }
  else
  {
    printf ("%s\n", MD5sum);
    return EXIT_SUCCESS;
  }
}

char* compute_md5sum (const char *filepath)
{
	MD5_CTX c;
	FILE *IN;	
	int fd;
	int i;
	static unsigned char buf[BUFSIZE];
	char *str_md5sum;
	unsigned char *md5sum;
	md5sum = malloc (MD5_DIGEST_LENGTH * sizeof (unsigned char));
	str_md5sum = malloc (((2 * MD5_DIGEST_LENGTH) + 1) * sizeof (char));
	
	IN=fopen(filepath,"r");
	if (!IN)
	{
		printf ("error opening %s file\n", filepath);
		goto bail;
	}
	
	/* clears the end-of-file and error indicators for the stream pointed to by */
	fd = fileno(IN);
	
	/* Initialization of MD5 context. */
	if (!MD5_Init(&c))
	{
		printf ("MD5_Init error\n");
		goto bail;
	}
	
	for (;;)
	{
		i = read (fd, buf, BUFSIZE);
		if (i <= 0) 
			break;
		/* 
		 * update the MD5_CTX struct with data parameter and return
		 * the (deserialized from ctx parameter) updated context.
		 * */
		if (!MD5_Update(&c, buf, (unsigned long)i))
		{
			printf ("MD5_Update  error\n");
			goto bail;
		}
	}
	
	/* 
	 * convert the return value to a 33-character (including the terminating '\0') ASCII string 
	 * which represents the 128 bits in hexadecimal.
	 * */
	if (!MD5_Final(md5sum, &c))
	{
		printf ("MD5_Final error\n");
		goto bail;
	}
	
	/* convert hexadecimal md5sum hash code to a string */
	for(i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(str_md5sum + (i * 2), "%02x", md5sum[i]);
	str_md5sum[2 * MD5_DIGEST_LENGTH] = '\0';
	
	fclose(IN);
	return str_md5sum;
bail:
	free (str_md5sum);
	free (md5sum);
	return NULL;
}
