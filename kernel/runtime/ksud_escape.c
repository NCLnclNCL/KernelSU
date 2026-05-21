#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#define KSUD_PATH "/data/adb/ksud"
extern bool ksu_boot_completed;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) 
__weak long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
	long ret = -EFAULT;
	mm_segment_t old_fs = get_fs();

	set_fs(USER_DS);

	// normally theres an access_ok check here
	// but for what we use it, it will always be true.
	// so we skip it
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, src, size);
	pagefault_enable();

	set_fs(old_fs);

	if (ret)
		return -EFAULT;
	return 0;
}
#endif
static __always_inline long ksu_copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}
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