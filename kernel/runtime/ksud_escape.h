#ifndef __KSU_H_KSUD_ESCAPE
#define __KSU_H_KSUD_ESCAPE

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static inline void sys_execve_escape_ksud(void *filename)
{
	if (unlikely(!ksu_boot_completed))
		sys_execve_escape_ksud_internal(filename);
}
static inline void kernel_execve_escape_ksud(void *filename)
{
	if (unlikely(!ksu_boot_completed))
		kernel_execve_escape_ksud_internal(filename);
}
#endif // < 4.14 && >= 4.2 

static void ksud_escape_init();
static void ksud_escape_exit();

#endif // __KSU_H_KSUD_ESCAPE