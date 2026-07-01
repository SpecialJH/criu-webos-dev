#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <string.h>
#include <compel/plugins/std/syscall-codes.h>
#include <compel/asm/processor-flags.h>
#include <errno.h>

#include "common/page.h"
#include "uapi/compel/asm/infect-types.h"
#include "log.h"
#include "errno.h"
#include "infect.h"
#include "infect-priv.h"

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x00, 0x00, 0x00, 0xef, /* SVC #0  */
	0xf0, 0x01, 0xf0, 0xe7	/* UDF #32 */
};

static const int code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline __always_unused void __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	struct aux_sigframe *aux = (struct aux_sigframe *)(void *)&sigframe->sig.uc.uc_regspace;

	sigframe->sig.uc.uc_mcontext.arm_r0 = regs->ARM_r0;
	sigframe->sig.uc.uc_mcontext.arm_r1 = regs->ARM_r1;
	sigframe->sig.uc.uc_mcontext.arm_r2 = regs->ARM_r2;
	sigframe->sig.uc.uc_mcontext.arm_r3 = regs->ARM_r3;
	sigframe->sig.uc.uc_mcontext.arm_r4 = regs->ARM_r4;
	sigframe->sig.uc.uc_mcontext.arm_r5 = regs->ARM_r5;
	sigframe->sig.uc.uc_mcontext.arm_r6 = regs->ARM_r6;
	sigframe->sig.uc.uc_mcontext.arm_r7 = regs->ARM_r7;
	sigframe->sig.uc.uc_mcontext.arm_r8 = regs->ARM_r8;
	sigframe->sig.uc.uc_mcontext.arm_r9 = regs->ARM_r9;
	sigframe->sig.uc.uc_mcontext.arm_r10 = regs->ARM_r10;
	sigframe->sig.uc.uc_mcontext.arm_fp = regs->ARM_fp;
	sigframe->sig.uc.uc_mcontext.arm_ip = regs->ARM_ip;
	sigframe->sig.uc.uc_mcontext.arm_sp = regs->ARM_sp;
	sigframe->sig.uc.uc_mcontext.arm_lr = regs->ARM_lr;
	sigframe->sig.uc.uc_mcontext.arm_pc = regs->ARM_pc;
	sigframe->sig.uc.uc_mcontext.arm_cpsr = regs->ARM_cpsr;

	memcpy(&aux->vfp.ufp.fpregs, &fpregs->fpregs, sizeof(aux->vfp.ufp.fpregs));
	aux->vfp.ufp.fpscr = fpregs->fpscr;
	aux->vfp.magic = VFP_MAGIC;
	aux->vfp.size = VFP_STORAGE_SIZE;

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

#define PTRACE_GETVFPREGS 27
int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *vfp, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	int ret = -1;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	if (ptrace(PTRACE_GETVFPREGS, pid, NULL, vfp)) {
		pr_perror("Can't obtain FPU registers for %d", pid);
		goto err;
	}

	/* Did we come from a system call? */
	if ((int)regs->ARM_ORIG_r0 >= 0) {
		/* Restart the system call */
		switch ((long)(int)regs->ARM_r0) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs->ARM_r0 = regs->ARM_ORIG_r0;
			regs->ARM_pc -= 4;
			break;
		case -ERESTART_RESTARTBLOCK:
			pr_warn("Will restore %d with interrupted system call\n", pid);
			regs->ARM_r0 = -EINTR;
			break;
		}
	}

	ret = save(pid, arg, regs, vfp);
err:
	return ret;
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	pr_info("Restoring GP/FPU registers for %d\n", pid);

	if (ptrace(PTRACE_SETVFPREGS, pid, NULL, ext_regs)) {
		pr_perror("Can't set FPU registers for %d", pid);
		return -1;
	}
	return 0;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	regs.ARM_r7 = (unsigned long)nr;
	regs.ARM_r0 = arg1;
	regs.ARM_r1 = arg2;
	regs.ARM_r2 = arg3;
	regs.ARM_r3 = arg4;
	regs.ARM_r4 = arg5;
	regs.ARM_r5 = arg6;

	err = compel_execute_syscall(ctl, &regs, code_syscall);

	*ret = regs.ARM_r0;
	return err;
}

void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long map;
	int err;

	if (offset & ~PAGE_MASK)
		return 0;

	err = compel_syscall(ctl, __NR_mmap2, &map, (unsigned long)addr, length, prot, flags, fd, offset >> 12);
	if (err < 0 || map > ctl->ictx.task_size)
		map = 0;

	return (void *)map;
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->ARM_pc = new_ip;
	if (stack)
		regs->ARM_sp = (unsigned long)stack;

	/* Make sure flags are in known state */
	regs->ARM_cpsr &= PSR_f | PSR_s | PSR_x | MODE32_BIT;
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->sig.uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm/include/asm/memory.h
 *   arch/arm/Kconfig (PAGE_OFFSET values in Memory split section)
 */
#define TASK_SIZE_MIN 0x3f000000
#define TASK_SIZE_MAX 0xbf000000
#define SZ_1G	      0x40000000

/*
 * On a 64-bit (AArch64) kernel an AArch32 "compat" task is given the full
 * 4 GiB user address space (the kernel's TASK_SIZE_32 == 0x100000000), not
 * the smaller user/kernel split a 32-bit kernel would use. 0x100000000 is not
 * representable in the 32-bit unsigned long used here, so the reported size is
 * clamped to the last usable page boundary, 0xfffff000. That value sits above
 * every mapping a compat task actually has -- [sigpage] (~0xf7xxx000), [stack]
 * (~0xffexx000) and the high [vectors] page at 0xffff0000-0xffff1000 -- yet
 * below the syscall error-return range (0xfffff001..0xffffffff), so the
 * "result > task_size means error" check in remote_mmap() above stays correct.
 *
 * COMPAT_PROBE is unmapped but valid for a compat task on a 64-bit kernel, and
 * invalid for every 32-bit kernel split (it is above TASK_SIZE_MAX). munmap()
 * of an unmapped-but-valid page is a harmless no-op that succeeds, so probing
 * it tells the two kernels apart without disturbing any real mapping.
 */
#define COMPAT_TASK_SIZE 0xfffff000
#define COMPAT_PROBE	 0xe0000000

unsigned long compel_task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size += SZ_1G)
		if (munmap((void *)task_size, page_size()))
			break;

	/*
	 * A 32-bit kernel makes munmap() fail at or below TASK_SIZE_MAX, so the
	 * loop already found the real boundary. If every probe succeeded
	 * (task_size reached TASK_SIZE_MAX) we are a compat task on a 64-bit
	 * kernel: confirm the high range is ours and report the clamped size.
	 */
	if (task_size == TASK_SIZE_MAX && !munmap((void *)COMPAT_PROBE, page_size()))
		task_size = COMPAT_TASK_SIZE;

	return task_size;
}
