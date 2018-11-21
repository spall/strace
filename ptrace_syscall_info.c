/*
 * Copyright (c) 2018 Dmitry V. Levin <ldv@altlinux.org>
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

#include "defs.h"
#include "kill_save_errno.h"
#include "ptrace.h"
#include "ptrace_syscall_info.h"
#include "scno.h"

#include <signal.h>
#include <sys/wait.h>

bool ptrace_get_syscall_info_supported;

static int
kill_tracee(pid_t pid)
{
	return kill_save_errno(pid, SIGKILL);
}

#define FAIL	do { ptrace_stop = -1U; goto done; } while (0)

/*
 * Test that PTRACE_GET_SYSCALL_INFO API is supported by the kernel, and
 * that the semantics implemented in the kernel matches our expectations.
 */
bool
test_ptrace_get_syscall_info(void)
{
	static const unsigned long args[][7] = {
		/* a sequence of architecture-agnostic syscalls */
		{
			__NR_chdir,
			(unsigned long) "",
			0xbad1fed1,
			0xbad2fed2,
			0xbad3fed3,
			0xbad4fed4,
			0xbad5fed5
		},
		{
			__NR_gettid,
			0xcaf0bea0,
			0xcaf1bea1,
			0xcaf2bea2,
			0xcaf3bea3,
			0xcaf4bea4,
			0xcaf5bea5
		},
		{
			__NR_exit_group,
			0,
			0xfac1c0d1,
			0xfac2c0d2,
			0xfac3c0d3,
			0xfac4c0d4,
			0xfac5c0d5
		}
	};
	const unsigned long *exp_args;

	int pid = fork();
	if (pid < 0)
		perror_func_msg_and_die("fork");

	if (pid == 0) {
		/* get the pid before PTRACE_TRACEME */
		pid = getpid();
		if (ptrace(PTRACE_TRACEME, 0L, 0L, 0L) < 0) {
			/* exit with a nonzero exit status */
			perror_func_msg_and_die("PTRACE_TRACEME");
		}
		kill(pid, SIGSTOP);
		for (unsigned int i = 0; i < ARRAY_SIZE(args); ++i) {
			syscall(args[i][0],
				args[i][1], args[i][2], args[i][3],
				args[i][4], args[i][5], args[i][6]);
		}
		/* unreachable */
		_exit(1);
	}

	const struct {
		unsigned int is_error;
		int rval;
	} *exp_param, exit_param[] = {
		{ 1, -ENOENT },	/* chdir */
		{ 0, pid }	/* gettid */
	};

	unsigned int ptrace_stop;

	for (ptrace_stop = 0; ; ++ptrace_stop) {
		struct ptrace_syscall_info info = {
			.op = 0xff	/* invalid PTRACE_SYSCALL_INFO_* op */
		};
		const size_t size = sizeof(info);
		const int expected_none_size =
			(void *) &info.entry - (void *) &info;
		const int expected_entry_size =
			(void *) &info.entry.args[6] - (void *) &info;
		const int expected_exit_size =
			(void *) (&info.exit.is_error + 1) -
			(void *) &info;
		int status;
		long rc = waitpid(pid, &status, 0);
		if (rc != pid) {
			/* cannot happen */
			kill_tracee(pid);
			perror_func_msg_and_die("#%d: unexpected wait result"
						" %ld", ptrace_stop, rc);
		}
		if (WIFEXITED(status)) {
			/* tracee is no more */
			pid = 0;
			if (WEXITSTATUS(status) == 0)
				break;
			debug_func_msg("#%d: unexpected exit status %u",
				       ptrace_stop, WEXITSTATUS(status));
			FAIL;
		}
		if (WIFSIGNALED(status)) {
			/* tracee is no more */
			pid = 0;
			debug_func_msg("#%d: unexpected signal %u",
				       ptrace_stop, WTERMSIG(status));
			FAIL;
		}
		if (!WIFSTOPPED(status)) {
			/* cannot happen */
			kill_tracee(pid);
			error_func_msg_and_die("#%d: unexpected wait status"
					       " %#x", ptrace_stop, status);
		}

		switch (WSTOPSIG(status)) {
		case SIGSTOP:
			if (ptrace_stop) {
				debug_func_msg("#%d: unexpected signal stop",
					       ptrace_stop);
				FAIL;
			}
			if (ptrace(PTRACE_SETOPTIONS, pid, 0L,
				   PTRACE_O_TRACESYSGOOD) < 0) {
				/* cannot happen */
				kill_tracee(pid);
				perror_func_msg_and_die("PTRACE_SETOPTIONS");
			}
			rc = ptrace(PTRACE_GET_SYSCALL_INFO, pid,
				    (void *) size, &info);
			if (rc < 0) {
				debug_perror_msg("PTRACE_GET_SYSCALL_INFO");
				FAIL;
			}
			if (rc < expected_none_size
			    || info.op != PTRACE_SYSCALL_INFO_NONE
			    || !info.arch
			    || !info.instruction_pointer
			    || !info.stack_pointer) {
				debug_func_msg("signal stop mismatch");
				FAIL;
			}
			break;

		case SIGTRAP | 0x80:
			rc = ptrace(PTRACE_GET_SYSCALL_INFO, pid,
				    (void *) size, &info);
			if (rc < 0) {
				debug_perror_msg("#%d: PTRACE_GET_SYSCALL_INFO",
						 ptrace_stop);
				FAIL;
			}
			switch (ptrace_stop) {
			case 1: /* entering chdir */
			case 3: /* entering gettid */
			case 5: /* entering exit_group */
				exp_args = args[ptrace_stop / 2];
				if (rc < expected_entry_size
				    || info.op != PTRACE_SYSCALL_INFO_ENTRY
				    || !info.arch
				    || !info.instruction_pointer
				    || !info.stack_pointer
				    || (info.entry.nr != exp_args[0])
				    || (info.entry.args[0] != exp_args[1])
				    || (info.entry.args[1] != exp_args[2])
				    || (info.entry.args[2] != exp_args[3])
				    || (info.entry.args[3] != exp_args[4])
				    || (info.entry.args[4] != exp_args[5])
				    || (info.entry.args[5] != exp_args[6])) {
					debug_func_msg("#%d: entry stop"
						       " mismatch",
						       ptrace_stop);
					FAIL;
				}
				break;
			case 2: /* exiting chdir */
			case 4: /* exiting gettid */
				exp_param = &exit_param[ptrace_stop / 2 - 1];
				if (rc < expected_exit_size
				    || info.op != PTRACE_SYSCALL_INFO_EXIT
				    || !info.arch
				    || !info.instruction_pointer
				    || !info.stack_pointer
				    || info.exit.is_error != exp_param->is_error
				    || info.exit.rval != exp_param->rval) {
					debug_func_msg("#%d: exit stop"
						       " mismatch",
						       ptrace_stop);
					FAIL;
				}
				break;
			default:
				debug_func_msg("#%d: unexpected syscall stop",
					       ptrace_stop);
				FAIL;
			}
			break;

		default:
			debug_func_msg("#%d: unexpected stop signal %#x",
				       ptrace_stop, WSTOPSIG(status));
			FAIL;
		}

		if (ptrace(PTRACE_SYSCALL, pid, 0L, 0L) < 0) {
			/* cannot happen */
			kill_tracee(pid);
			perror_func_msg_and_die("PTRACE_SYSCALL");
		}
	}

done:
	if (pid) {
		kill_tracee(pid);
		waitpid(pid, NULL, 0);
		ptrace_stop = -1U;
	}

	ptrace_get_syscall_info_supported =
		ptrace_stop == ARRAY_SIZE(args) * 2;

	if (ptrace_get_syscall_info_supported)
		debug_msg("PTRACE_GET_SYSCALL_INFO works");
	else
		debug_msg("PTRACE_GET_SYSCALL_INFO does not work");

	return ptrace_get_syscall_info_supported;
}
