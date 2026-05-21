#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#define KSUD_PATH "/data/adb/ksud"
extern bool ksu_boot_completed;
__attribute__((cold)) noinline void sys_execve_escape_ksud_internal(void *filename)
{	if (unlikely(!ksu_boot_completed))
{

	// see if its init
	if (!is_init(current_cred()))
		return;

	const char ksud_path[] = KSUD_PATH;
	char path[sizeof(ksud_path)];

	// filename is void * char __user *
	const char __user **filename_user = (const char __user **)filename;

	// see if its trying to execute ksud
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return;

	if (likely(!!memcmp(ksud_path, path, sizeof(path))))
		return;

	pr_info("sys_execve: escape init executing %s with pid: %d\n", path, current->pid);
	escape_to_root_forced(); // give this context all permissions
	return;
}
}

__attribute__((cold)) noinline void kernel_execve_escape_ksud_internal(void *filename)
{
	if (unlikely(!ksu_boot_completed))
{
	// filename is void **
	void **filename_ptr = (void **)filename;

	// see if its init
	if (!is_init(current_cred()))
		return;

	if (!*filename_ptr)
		return;

	if (likely(!!memcmp(*filename_ptr, KSUD_PATH, sizeof(KSUD_PATH))))
		return;

	pr_info("kernel_execve: escape init executing %s with pid: %d\n", *(const char **)filename_ptr, current->pid);
	escape_to_root_forced(); // give this context all permissions
	return;
}
}
#endif // < 4.14 && >= 4.2