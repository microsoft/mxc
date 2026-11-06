// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <asm/unistd.h>
#include <linux/capability.h>
#include <linux/prctl.h>

static long linux_syscall(long number, long first, long second, long third, long fourth, long fifth)
{
#if defined(__x86_64__)
    register long argument_four __asm__("r10") = fourth;
    register long argument_five __asm__("r8") = fifth;
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third), "r"(argument_four), "r"(argument_five)
        : "rcx", "r11", "memory", "cc");
    return result;
#elif defined(__aarch64__)
    register long syscall_number __asm__("x8") = number;
    register long argument_one __asm__("x0") = first;
    register long argument_two __asm__("x1") = second;
    register long argument_three __asm__("x2") = third;
    register long argument_four __asm__("x3") = fourth;
    register long argument_five __asm__("x4") = fifth;
    __asm__ volatile(
        "svc #0"
        : "+r"(argument_one)
        : "r"(syscall_number), "r"(argument_two), "r"(argument_three), "r"(argument_four), "r"(argument_five)
        : "memory", "cc");
    return argument_one;
#else
#error Unsupported LXC capability helper architecture
#endif
}

__attribute__((noreturn))
static void write_error_and_exit(const char* message)
{
    unsigned long length = 0;
    while (message[length])
    {
        ++length;
    }
    linux_syscall(__NR_write, 2, (long)message, length, 0, 0);
    linux_syscall(__NR_exit, 126, 0, 0, 0, 0);
    __builtin_unreachable();
}

__attribute__((noreturn, used))
void drop_network_capabilities_and_exec(unsigned long* initial_stack)
{
    const unsigned long argument_count = initial_stack[0];
    char** arguments = (char**)&initial_stack[1];
    char** environment = arguments + argument_count + 1;
    if (argument_count < 3)
    {
        write_error_and_exit("mxc: invalid capability helper arguments\n");
    }

    unsigned long helper_fd = 0;
    const char* descriptor = arguments[1];
    if (!*descriptor)
    {
        write_error_and_exit("mxc: missing capability helper descriptor\n");
    }
    for (; *descriptor; ++descriptor)
    {
        if (*descriptor < '0' || *descriptor > '9'
            || helper_fd > (2147483647UL - (*descriptor - '0')) / 10)
        {
            write_error_and_exit("mxc: invalid capability helper descriptor\n");
        }
        helper_fd = helper_fd * 10 + (*descriptor - '0');
    }
    if (helper_fd < 3)
    {
        write_error_and_exit("mxc: capability helper descriptor must not replace standard IO\n");
    }
    if (linux_syscall(__NR_close, helper_fd, 0, 0, 0, 0) < 0)
    {
        write_error_and_exit("mxc: failed to close capability helper descriptor\n");
    }

    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct capabilities[_LINUX_CAPABILITY_U32S_3];
    if (linux_syscall(__NR_capget, (long)&header, (long)capabilities, 0, 0, 0) < 0)
    {
        write_error_and_exit("mxc: failed to read workload capabilities\n");
    }

    const unsigned int removed_capabilities[] = {CAP_NET_ADMIN, CAP_NET_RAW};
    const unsigned int removed_count = sizeof(removed_capabilities) / sizeof(removed_capabilities[0]);
    for (unsigned int index = 0; index < removed_count; ++index)
    {
        const unsigned int capability = removed_capabilities[index];
        const long bounded = linux_syscall(__NR_prctl, PR_CAPBSET_READ, capability, 0, 0, 0);
        if (bounded < 0
            || (bounded && linux_syscall(__NR_prctl, PR_CAPBSET_DROP, capability, 0, 0, 0) < 0))
        {
            write_error_and_exit("mxc: failed to remove workload network capability from bounding set\n");
        }
        if (linux_syscall(__NR_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, capability, 0, 0) < 0)
        {
            write_error_and_exit("mxc: failed to remove workload network capability from ambient set\n");
        }

        const unsigned int retained_bits = ~(1U << (capability % 32));
        capabilities[capability / 32].effective &= retained_bits;
        capabilities[capability / 32].permitted &= retained_bits;
        capabilities[capability / 32].inheritable &= retained_bits;
    }
    if (linux_syscall(__NR_capset, (long)&header, (long)capabilities, 0, 0, 0) < 0)
    {
        write_error_and_exit("mxc: failed to remove workload network capabilities\n");
    }
    if (linux_syscall(__NR_capget, (long)&header, (long)capabilities, 0, 0, 0) < 0)
    {
        write_error_and_exit("mxc: failed to verify workload capabilities\n");
    }
    for (unsigned int index = 0; index < removed_count; ++index)
    {
        const unsigned int capability = removed_capabilities[index];
        const unsigned int capability_bit = 1U << (capability % 32);
        const struct __user_cap_data_struct* word = &capabilities[capability / 32];
        if (((word->effective | word->permitted | word->inheritable) & capability_bit)
            || linux_syscall(__NR_prctl, PR_CAPBSET_READ, capability, 0, 0, 0) != 0
            || linux_syscall(__NR_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0) != 0)
        {
            write_error_and_exit("mxc: workload network capability removal was incomplete\n");
        }
    }

    linux_syscall(__NR_execve, (long)arguments[2], (long)&arguments[2], (long)environment, 0, 0);
    write_error_and_exit("mxc: failed to execute workload after removing network capabilities\n");
}

// Pass the original ELF entry stack to C without a C runtime.
#if defined(__x86_64__)
__asm__(
    ".global _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "mov %rsp,%rdi\n"
    "and $-16,%rsp\n"
    "call drop_network_capabilities_and_exec\n"
    "ud2\n"
    ".size _start,.-_start\n");
#elif defined(__aarch64__)
__asm__(
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "mov x0,sp\n"
    "bl drop_network_capabilities_and_exec\n"
    "brk #0\n"
    ".size _start,.-_start\n");
#endif
