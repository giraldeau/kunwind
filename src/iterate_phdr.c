#include "iterate_phdr.h"
#include "vma_file_path.h"

#include <linux/elf.h>
#include <linux/vmalloc.h>

int iterate_phdr(int (*cb) (struct phdr_info *info, void *data),
		 struct task_struct *task, void *data)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = task->mm;
	struct phdr_info pi;
	char buf[NAME_BUFLEN];
	int res = 0, err = 0;
	struct page *page; // FIXME Is one page enough for all phdrs?
	Elf64_Ehdr *ehdr;

	if (!mm) return -EINVAL;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_pgoff)
			// Only the first page contains the elf
			// headers, normally.
			continue;

		err = __get_user_pages_unlocked(
			task, task->mm, vma->vm_start,
			1, 0, 0, &page, FOLL_TOUCH);
		if (err < 0)
			continue;

		ehdr = vmap(&page, 1, vma->vm_flags, vma->vm_page_prot);
		if (!ehdr) goto PUT;

		// Test magic bytes to check that it is an ehdr
		err |= ehdr->e_ident[0] != ELFMAG0;
		err |= ehdr->e_ident[1] != ELFMAG1;
		err |= ehdr->e_ident[2] != ELFMAG2;
		err |= ehdr->e_ident[3] != ELFMAG3;
		if (err) goto UNMAP;

		// Set addresses
		pi.addr = vma->vm_start;
		pi.phdr = ehdr + ehdr->e_phoff;
		pi.phnum = ehdr->e_phnum;

		// Find path
		pi.name = vma_file_path(vma, buf, NAME_BUFLEN);

		// Call the callback
		res = cb(&pi, data);

		// Free resources
	UNMAP:
		vunmap(ehdr);
	PUT:
		put_page(page);

		if (res) break;
	}
	return res;
}
