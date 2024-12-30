#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

static int seek(int fd, char expected)
{
        char value = -1;
        int ret;

        ret = read(fd, &value, 1);
        if (ret != 1) {
                fprintf(stderr, "failed to read from device!\n");
                return -1;
        }
        if (value != expected) {
                fprintf(stderr, "wrong value: %c, expected: %c\n", value, expected);
                return -1;
        }
        return 0;
}

static int hide(int fd, char to_hide)
{
        int ret;

        ret = write(fd, &to_hide, 1);
        if (ret != 1) {
                fprintf(stderr, "failed to write to device!\n");
                return -1;
        }
        return 0;
}


int main(void)
{
        int fd;
        int ret;
        char test = 'y';

        fd = open("/dev/virt_walker", O_RDWR);
        if (fd == -1) {
                fprintf(stderr, "open(): %s\n", strerror(errno));
                goto fail;
        }

        if (seek(fd, 0))
                goto fail_fd;

        if (hide(fd, test))
                goto fail_fd;

        if (seek(fd, test))
                goto fail_fd;

        printf("You've done it!\n");
        return 0;

fail_fd:
        close(fd);
fail:
        return -1;
}