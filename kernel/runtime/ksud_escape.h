#ifndef __KSU_H_KSUD_ESCAPE
#define __KSU_H_KSUD_ESCAPE

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
__attribute__((cold)) static noinline void sys_execve_escape_ksud_internal(void *filename);
__attribute__((cold)) static noinline void kernel_execve_escape_ksud_internal(void *filename);
#endif // < 4.14 && >= 4.2 

static void ksud_escape_init();
static void ksud_escape_exit();

#endif // __KSU_H_KSUD_ESCAPE