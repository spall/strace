/*
 * Copyright (c) 2010-2018 The strace developers.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef AUDIT_ARCH_I386
# define AUDIT_ARCH_I386 0x40000003
#endif

int
get_personality_from_syscall_info(const struct ptrace_syscall_info *sci)
{
	unsigned int pers = sci->arch == AUDIT_ARCH_I386;

#ifndef X32
	switch(sci->op) {
		case PTRACE_SYSCALL_INFO_ENTRY:
		case PTRACE_SYSCALL_INFO_SECCOMP:
			break;
		default:
			return -1;
	}

	kernel_ulong_t scno = sci->entry.nr;

#ifndef __X32_SYSCALL_BIT
# define __X32_SYSCALL_BIT	0x40000000
#endif

	if (pers == 0 && (scno & __X32_SYSCALL_BIT)) {
		/*
		 * Syscall number -1 requires special treatment:
		 * it might be a side effect of SECCOMP_RET_ERRNO
		 * filtering that sets orig_rax to -1
		 * in some versions of linux kernel.
		 * If that is the case, then
		 * __X32_SYSCALL_BIT logic does not apply.
		 */
		if (scno != (kernel_ulong_t) -1)
			pers = 2;
	}
#endif /* !X32 */

	return pers;
}
