#ifndef _VMA_FILE_PATH_H_
#define _VMA_FILE_PATH_H_

#include <linux/fs.h>
#include <linux/mm.h>

static inline
char *vma_file_path(struct vm_area_struct *vma,
		    char *buf, unsigned int buflen)
{
	char *path;

	struct file *file = vma->vm_file;
	if (!file) return NULL;

	path = dentry_path_raw(file->f_path.dentry, buf, buflen);

	if (IS_ERR(path))
		return NULL;

	return path;
}

#endif // _VMA_FILE_PATH_H_
