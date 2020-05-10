#ifndef FALLOCATE_H
#define FALLOCATE_H

typedef LONG off_t;

int posix_fallocate(int fd, off_t offset, off_t len);
#endif
