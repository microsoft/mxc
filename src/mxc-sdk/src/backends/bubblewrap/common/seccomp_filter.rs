// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds Bubblewrap's always-on address-family seccomp filter.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};

#[cfg(target_os = "linux")]
use nix::fcntl::{fcntl, FcntlArg};

use crate::bwrap_common::bwrap_command::COMMAND_TAIL;

const BPF_LD_W_ABS: u16 = 0x20;
#[cfg(any(target_arch = "x86_64", test))]
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARG0_LOW_OFFSET: u32 = 16;

#[cfg(target_os = "linux")]
const FIRST_NON_STDIO_FD: i32 = 3;

#[cfg(any(target_arch = "x86_64", test))]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(any(target_arch = "x86_64", test))]
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
#[cfg(any(target_arch = "aarch64", test))]
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
#[cfg(any(target_arch = "aarch64", test))]
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
#[cfg(any(target_arch = "x86_64", test))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(any(target_arch = "x86_64", test))]
const X86_64_SOCKET: u32 = 41;
#[cfg(any(target_arch = "x86_64", test))]
const X86_64_SOCKETPAIR: u32 = 53;
#[cfg(any(target_arch = "x86_64", test))]
const I386_SOCKETCALL: u32 = 102;
#[cfg(any(target_arch = "x86_64", test))]
const I386_SOCKET: u32 = 359;
#[cfg(any(target_arch = "x86_64", test))]
const I386_SOCKETPAIR: u32 = 360;
#[cfg(any(target_arch = "x86_64", test))]
const SOCKETCALL_SOCKET: u32 = 1;
#[cfg(any(target_arch = "x86_64", test))]
const SOCKETCALL_SOCKETPAIR: u32 = 8;
#[cfg(any(target_arch = "aarch64", test))]
const AARCH64_SOCKET: u32 = 198;
#[cfg(any(target_arch = "aarch64", test))]
const AARCH64_SOCKETPAIR: u32 = 199;
#[cfg(any(target_arch = "aarch64", test))]
const ARM_SOCKET: u32 = 281;
#[cfg(any(target_arch = "aarch64", test))]
const ARM_SOCKETPAIR: u32 = 288;

const IO_URING_SETUP: u32 = 425;
const IO_URING_ENTER: u32 = 426;
const IO_URING_REGISTER: u32 = 427;
const IO_URING_SYSCALLS: [u32; 3] = [IO_URING_SETUP, IO_URING_ENTER, IO_URING_REGISTER];

const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const AF_NETLINK: u32 = 16;
const ALLOWED_FAMILIES: [u32; 4] = [AF_UNIX, AF_INET, AF_INET6, AF_NETLINK];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Instruction {
    code: u16,
    jump_if_true: u8,
    jump_if_false: u8,
    value: u32,
}

impl Instruction {
    const fn statement(code: u16, value: u32) -> Self {
        Self {
            code,
            jump_if_true: 0,
            jump_if_false: 0,
            value,
        }
    }

    const fn jump(code: u16, value: u32) -> Self {
        Self {
            code,
            jump_if_true: 0,
            jump_if_false: 0,
            value,
        }
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.code.to_ne_bytes());
        output.push(self.jump_if_true);
        output.push(self.jump_if_false);
        output.extend_from_slice(&self.value.to_ne_bytes());
    }
}

#[derive(Clone, Copy)]
enum NativeArchitecture {
    #[cfg(any(target_arch = "x86_64", test))]
    X86_64,
    #[cfg(any(target_arch = "aarch64", test))]
    Aarch64,
}

#[cfg(target_os = "linux")]
pub(crate) fn create_file() -> Result<File, String> {
    let program = native_program()?;
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for instruction in program {
        instruction.encode(&mut bytes);
    }

    let mut file = tempfile::tempfile()
        .map_err(|error| format!("Bubblewrap: failed to create seccomp filter file: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("Bubblewrap: failed to write seccomp filter: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Bubblewrap: failed to rewind seccomp filter: {error}"))?;
    above_stdio(file)
}

// The child's stdio is mapped onto descriptors 0-2 before `pre_exec` runs, so
// a filter left on one of those numbers is replaced before bwrap reads it.
#[cfg(target_os = "linux")]
fn above_stdio(file: File) -> Result<File, String> {
    let fd = fcntl(
        file.as_raw_fd(),
        FcntlArg::F_DUPFD_CLOEXEC(FIRST_NON_STDIO_FD),
    )
    .map_err(|error| format!("Bubblewrap: failed to move seccomp filter descriptor: {error}"))?;

    // SAFETY: `fcntl` returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn add_bwrap_args(args: &mut Vec<String>, fd: i32) -> Result<(), String> {
    let command_index = args
        .len()
        .checked_sub(COMMAND_TAIL.len() + 1)
        .filter(|&index| args[index..index + COMMAND_TAIL.len()] == COMMAND_TAIL)
        .ok_or_else(|| {
            "Bubblewrap: cannot install the seccomp filter because the command tail is malformed"
                .to_string()
        })?;
    reject_conflicting_options(&args[..command_index])?;
    args.splice(
        command_index..command_index,
        ["--seccomp".to_string(), fd.to_string()],
    );
    Ok(())
}

fn reject_conflicting_options(args: &[String]) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if matches!(option, "--seccomp" | "--add-seccomp-fd") {
            return Err(
                "Bubblewrap: cannot combine the address-family filter with another seccomp option"
                    .to_string(),
            );
        }
        let operands = match option {
            "--unshare-user" | "--unshare-pid" | "--unshare-ipc" | "--unshare-uts"
            | "--die-with-parent" | "--unshare-net" | "--clearenv" | "--new-session" => 0,
            "--dev" | "--proc" | "--tmpfs" | "--chdir" | "--userns" | "--info-fd"
            | "--block-fd" => 1,
            "--ro-bind-try" | "--symlink" | "--bind" | "--ro-bind" | "--setenv" => 2,
            _ => {
                return Err(format!(
                    "Bubblewrap: cannot install the seccomp filter after unknown option {option}"
                ));
            }
        };
        index = index
            .checked_add(operands + 1)
            .filter(|next| *next <= args.len())
            .ok_or_else(|| {
                format!("Bubblewrap: option {option} is missing one or more operands")
            })?;
    }
    Ok(())
}

pub(crate) fn unsupported_architecture(architecture: &str) -> Option<String> {
    (!matches!(architecture, "x86_64" | "aarch64")).then(|| architecture.to_string())
}

#[cfg(target_os = "linux")]
fn native_program() -> Result<Vec<Instruction>, String> {
    if let Some(architecture) = unsupported_architecture(std::env::consts::ARCH) {
        return Err(format!(
            "Bubblewrap: seccomp address-family filtering is unsupported on {architecture}"
        ));
    }

    #[cfg(target_arch = "x86_64")]
    {
        Ok(build_program(NativeArchitecture::X86_64))
    }

    #[cfg(target_arch = "aarch64")]
    {
        Ok(build_program(NativeArchitecture::Aarch64))
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        unreachable!("unsupported architectures return before program construction")
    }
}

fn build_program(architecture: NativeArchitecture) -> Vec<Instruction> {
    match architecture {
        #[cfg(any(target_arch = "x86_64", test))]
        NativeArchitecture::X86_64 => build_x86_program(),
        #[cfg(any(target_arch = "aarch64", test))]
        NativeArchitecture::Aarch64 => build_aarch64_program(),
    }
}

#[cfg(any(target_arch = "x86_64", test))]
fn build_x86_program() -> Vec<Instruction> {
    let mut program = vec![Instruction::statement(
        BPF_LD_W_ABS,
        SECCOMP_DATA_ARCH_OFFSET,
    )];
    let x86_64_arch_check = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64));
    let i386_arch_check = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, AUDIT_ARCH_I386));
    program.push(Instruction::statement(BPF_RET_K, errno(ENOSYS)));

    let x86_64_start = program.len();
    set_true_target(&mut program, x86_64_arch_check, x86_64_start);
    program.extend([
        Instruction::statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        Instruction::statement(BPF_ALU_AND_K, !X32_SYSCALL_BIT),
    ]);
    let x86_64_socket = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, X86_64_SOCKET));
    let x86_64_socketpair = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, X86_64_SOCKETPAIR));
    let mut io_uring_checks = push_io_uring_checks(&mut program);
    program.push(Instruction::statement(BPF_RET_K, SECCOMP_RET_ALLOW));

    let i386_start = program.len();
    set_true_target(&mut program, i386_arch_check, i386_start);
    program.push(Instruction::statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    let i386_socket = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, I386_SOCKET));
    let i386_socketpair = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, I386_SOCKETPAIR));
    let i386_socketcall = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, I386_SOCKETCALL));
    io_uring_checks.extend(push_io_uring_checks(&mut program));
    program.push(Instruction::statement(BPF_RET_K, SECCOMP_RET_ALLOW));

    let socketcall_check = program.len();
    set_true_target(&mut program, i386_socketcall, socketcall_check);

    // i386 socketcall hides the family behind a pointer, so creation subcalls
    // must be denied as a unit.
    program.push(Instruction::statement(
        BPF_LD_W_ABS,
        SECCOMP_DATA_ARG0_LOW_OFFSET,
    ));
    program.push(Instruction::jump(BPF_JMP_JEQ_K, SOCKETCALL_SOCKET));
    let socketcall_socket = program.len() - 1;
    program.push(Instruction::jump(BPF_JMP_JEQ_K, SOCKETCALL_SOCKETPAIR));
    let socketcall_socketpair = program.len() - 1;
    program.push(Instruction::statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    let deny_socketcall_creation = program.len();
    program.push(Instruction::statement(BPF_RET_K, errno(EPERM)));
    set_true_target(&mut program, socketcall_socket, deny_socketcall_creation);
    set_true_target(
        &mut program,
        socketcall_socketpair,
        deny_socketcall_creation,
    );

    let family_check = append_family_filter(&mut program);
    for socket_check in [
        x86_64_socket,
        x86_64_socketpair,
        i386_socket,
        i386_socketpair,
    ] {
        set_true_target(&mut program, socket_check, family_check);
    }
    append_io_uring_denial(&mut program, &io_uring_checks);

    program
}

#[cfg(any(target_arch = "aarch64", test))]
fn build_aarch64_program() -> Vec<Instruction> {
    let mut program = vec![Instruction::statement(
        BPF_LD_W_ABS,
        SECCOMP_DATA_ARCH_OFFSET,
    )];
    let aarch64_arch_check = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, AUDIT_ARCH_AARCH64));
    let arm_arch_check = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, AUDIT_ARCH_ARM));
    program.push(Instruction::statement(BPF_RET_K, errno(ENOSYS)));

    let aarch64_start = program.len();
    set_true_target(&mut program, aarch64_arch_check, aarch64_start);
    program.push(Instruction::statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    let aarch64_socket = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, AARCH64_SOCKET));
    let aarch64_socketpair = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, AARCH64_SOCKETPAIR));
    let mut io_uring_checks = push_io_uring_checks(&mut program);
    program.push(Instruction::statement(BPF_RET_K, SECCOMP_RET_ALLOW));

    let arm_start = program.len();
    set_true_target(&mut program, arm_arch_check, arm_start);
    program.push(Instruction::statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    let arm_socket = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, ARM_SOCKET));
    let arm_socketpair = program.len();
    program.push(Instruction::jump(BPF_JMP_JEQ_K, ARM_SOCKETPAIR));
    io_uring_checks.extend(push_io_uring_checks(&mut program));
    program.push(Instruction::statement(BPF_RET_K, SECCOMP_RET_ALLOW));

    let family_check = append_family_filter(&mut program);
    for socket_check in [
        aarch64_socket,
        aarch64_socketpair,
        arm_socket,
        arm_socketpair,
    ] {
        set_true_target(&mut program, socket_check, family_check);
    }
    append_io_uring_denial(&mut program, &io_uring_checks);

    program
}

// io_uring creates sockets from shared-memory requests that seccomp cannot
// inspect, so the address-family policy holds only if rings cannot be used.
fn push_io_uring_checks(program: &mut Vec<Instruction>) -> Vec<usize> {
    IO_URING_SYSCALLS
        .into_iter()
        .map(|number| {
            let index = program.len();
            program.push(Instruction::jump(BPF_JMP_JEQ_K, number));
            index
        })
        .collect()
}

fn append_io_uring_denial(program: &mut Vec<Instruction>, checks: &[usize]) {
    let deny = program.len();
    program.push(Instruction::statement(BPF_RET_K, errno(ENOSYS)));
    for &check in checks {
        set_true_target(program, check, deny);
    }
}

fn append_family_filter(program: &mut Vec<Instruction>) -> usize {
    let family_check = program.len();

    // The kernel reads the family as a 32-bit int and ignores the upper half
    // of the argument register.
    program.push(Instruction::statement(
        BPF_LD_W_ABS,
        SECCOMP_DATA_ARG0_LOW_OFFSET,
    ));
    let family_jumps: Vec<usize> = ALLOWED_FAMILIES
        .into_iter()
        .map(|family| {
            let index = program.len();
            program.push(Instruction::jump(BPF_JMP_JEQ_K, family));
            index
        })
        .collect();
    program.push(Instruction::statement(BPF_RET_K, errno(EPERM)));
    let allow = program.len();
    program.push(Instruction::statement(BPF_RET_K, SECCOMP_RET_ALLOW));

    for family_jump in family_jumps {
        set_true_target(program, family_jump, allow);
    }

    family_check
}

fn set_true_target(program: &mut [Instruction], source: usize, target: usize) {
    program[source].jump_if_true = u8::try_from(target - source - 1)
        .expect("seccomp filter jump must fit in an 8-bit cBPF offset");
}

const fn errno(value: u32) -> u32 {
    SECCOMP_RET_ERRNO | value
}

#[cfg(test)]
mod tests {
    use super::*;

    const AF_PACKET: u64 = 17;
    const AF_VSOCK: u64 = 40;

    #[derive(Clone, Copy)]
    struct SeccompData {
        number: u32,
        architecture: u32,
        args: [u64; 6],
    }

    fn evaluate(program: &[Instruction], data: SeccompData) -> u32 {
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;

        loop {
            let instruction = program[pc];
            match instruction.code {
                BPF_LD_W_ABS => {
                    accumulator = load_word(data, instruction.value);
                    pc += 1;
                }
                BPF_ALU_AND_K => {
                    accumulator &= instruction.value;
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    let jump = if accumulator == instruction.value {
                        instruction.jump_if_true
                    } else {
                        instruction.jump_if_false
                    };
                    pc += usize::from(jump) + 1;
                }
                BPF_RET_K => return instruction.value,
                code => panic!("unsupported cBPF instruction {code:#x}"),
            }
        }
    }

    fn load_word(data: SeccompData, offset: u32) -> u32 {
        match offset {
            SECCOMP_DATA_NR_OFFSET => data.number,
            SECCOMP_DATA_ARCH_OFFSET => data.architecture,
            SECCOMP_DATA_ARG0_LOW_OFFSET => data.args[0] as u32,
            _ => panic!("unsupported seccomp_data offset {offset}"),
        }
    }

    fn result(native: NativeArchitecture, audit: u32, number: u32, first_argument: u64) -> u32 {
        evaluate(
            &build_program(native),
            SeccompData {
                number,
                architecture: audit,
                args: [first_argument, 0, 0, 0, 0, 0],
            },
        )
    }

    #[test]
    fn allows_required_socket_families() {
        for (native, audit, socket, socketpair) in [
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X86_64_SOCKET,
                X86_64_SOCKETPAIR,
            ),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT | X86_64_SOCKET,
                X32_SYSCALL_BIT | X86_64_SOCKETPAIR,
            ),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_I386,
                I386_SOCKET,
                I386_SOCKETPAIR,
            ),
            (
                NativeArchitecture::Aarch64,
                AUDIT_ARCH_AARCH64,
                AARCH64_SOCKET,
                AARCH64_SOCKETPAIR,
            ),
            (
                NativeArchitecture::Aarch64,
                AUDIT_ARCH_ARM,
                ARM_SOCKET,
                ARM_SOCKETPAIR,
            ),
        ] {
            for number in [socket, socketpair] {
                for family in ALLOWED_FAMILIES {
                    assert_eq!(
                        result(native, audit, number, u64::from(family)),
                        SECCOMP_RET_ALLOW,
                        "family {family} should be allowed for syscall {number} on arch {audit:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn denies_vsock_for_socketpair() {
        for (native, audit, socketpair) in [
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X86_64_SOCKETPAIR,
            ),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT | X86_64_SOCKETPAIR,
            ),
            (NativeArchitecture::X86_64, AUDIT_ARCH_I386, I386_SOCKETPAIR),
            (
                NativeArchitecture::Aarch64,
                AUDIT_ARCH_AARCH64,
                AARCH64_SOCKETPAIR,
            ),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_ARM, ARM_SOCKETPAIR),
        ] {
            assert_eq!(result(native, audit, socketpair, AF_VSOCK), errno(EPERM));
        }
    }

    #[test]
    fn denies_vsock_packet_and_unknown_families() {
        for (native, audit, socket) in [
            (NativeArchitecture::X86_64, AUDIT_ARCH_X86_64, X86_64_SOCKET),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT | X86_64_SOCKET,
            ),
            (NativeArchitecture::X86_64, AUDIT_ARCH_I386, I386_SOCKET),
            (
                NativeArchitecture::Aarch64,
                AUDIT_ARCH_AARCH64,
                AARCH64_SOCKET,
            ),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_ARM, ARM_SOCKET),
        ] {
            for family in [AF_VSOCK, AF_PACKET, 0xffff] {
                assert_eq!(
                    result(native, audit, socket, family),
                    errno(EPERM),
                    "family {family} should be denied on arch {audit:#x}"
                );
            }
        }
    }

    #[test]
    fn allows_unfiltered_syscalls() {
        for (native, audit, number) in [
            (NativeArchitecture::X86_64, AUDIT_ARCH_X86_64, 0),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT,
            ),
            (NativeArchitecture::X86_64, AUDIT_ARCH_I386, 3),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_AARCH64, 63),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_ARM, 3),
        ] {
            assert_eq!(result(native, audit, number, AF_VSOCK), SECCOMP_RET_ALLOW);
        }
    }

    #[test]
    fn rejects_foreign_architectures() {
        for (native, foreign) in [
            (NativeArchitecture::X86_64, AUDIT_ARCH_AARCH64),
            (NativeArchitecture::X86_64, AUDIT_ARCH_ARM),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_X86_64),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_I386),
        ] {
            assert_eq!(result(native, foreign, 0, 0), errno(ENOSYS));
        }
    }

    #[test]
    fn filters_x32_socket_syscalls_without_rejecting_the_abi() {
        assert_eq!(
            result(
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT | X86_64_SOCKET,
                AF_VSOCK,
            ),
            errno(EPERM)
        );
        assert_eq!(
            result(
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT,
                AF_VSOCK,
            ),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn filters_i386_direct_socket_syscalls() {
        assert_eq!(
            result(
                NativeArchitecture::X86_64,
                AUDIT_ARCH_I386,
                I386_SOCKET,
                AF_VSOCK,
            ),
            errno(EPERM)
        );
        assert_eq!(
            result(
                NativeArchitecture::X86_64,
                AUDIT_ARCH_I386,
                I386_SOCKET,
                u64::from(AF_INET),
            ),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn denies_io_uring_on_every_supported_abi() {
        for (native, audit, bit) in [
            (NativeArchitecture::X86_64, AUDIT_ARCH_X86_64, 0),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT,
            ),
            (NativeArchitecture::X86_64, AUDIT_ARCH_I386, 0),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_AARCH64, 0),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_ARM, 0),
        ] {
            for number in IO_URING_SYSCALLS {
                assert_eq!(
                    result(native, audit, bit | number, 0),
                    errno(ENOSYS),
                    "io_uring syscall {number} should be denied on arch {audit:#x}"
                );
            }
            for neighbor in [IO_URING_SETUP - 1, IO_URING_REGISTER + 1] {
                assert_eq!(
                    result(native, audit, bit | neighbor, 0),
                    SECCOMP_RET_ALLOW,
                    "syscall {neighbor} should stay allowed on arch {audit:#x}"
                );
            }
        }
    }

    #[test]
    fn denies_i386_socketcall_creation_subcalls() {
        for subcall in [SOCKETCALL_SOCKET, SOCKETCALL_SOCKETPAIR] {
            assert_eq!(
                result(
                    NativeArchitecture::X86_64,
                    AUDIT_ARCH_I386,
                    I386_SOCKETCALL,
                    u64::from(subcall),
                ),
                errno(EPERM)
            );
        }
        assert_eq!(
            result(
                NativeArchitecture::X86_64,
                AUDIT_ARCH_I386,
                I386_SOCKETCALL,
                2,
            ),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn ignores_the_family_upper_word() {
        for (native, audit, socket) in [
            (NativeArchitecture::X86_64, AUDIT_ARCH_X86_64, X86_64_SOCKET),
            (
                NativeArchitecture::X86_64,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT | X86_64_SOCKET,
            ),
            (NativeArchitecture::X86_64, AUDIT_ARCH_I386, I386_SOCKET),
            (
                NativeArchitecture::Aarch64,
                AUDIT_ARCH_AARCH64,
                AARCH64_SOCKET,
            ),
            (NativeArchitecture::Aarch64, AUDIT_ARCH_ARM, ARM_SOCKET),
        ] {
            for family in [u64::from(AF_UNIX), u64::from(AF_INET6), AF_VSOCK, AF_PACKET] {
                let expected = result(native, audit, socket, family);
                for upper in [1_u64, 0xffff_ffff] {
                    assert_eq!(
                        result(native, audit, socket, (upper << 32) | family),
                        expected,
                        "upper word {upper:#x} changed the verdict for family {family} on arch {audit:#x}"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn moves_the_filter_descriptor_above_stdio() {
        const NO_LOW_DESCRIPTOR: i32 = 2;

        // SAFETY: The child makes only async-signal-safe calls before `_exit`,
        // so it takes no lock another test thread held across the fork.
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            // SAFETY: The child owns its copy of descriptor 0.
            let code = unsafe {
                libc::close(0);
                let low = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if low == 0 {
                    match above_stdio(File::from_raw_fd(low)) {
                        Ok(moved) if moved.as_raw_fd() >= FIRST_NON_STDIO_FD => 0,
                        _ => 1,
                    }
                } else {
                    NO_LOW_DESCRIPTOR
                }
            };

            // SAFETY: The forked child exits here without returning into the
            // test harness.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;

        // SAFETY: `child` is this test's own forked process.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child, "waitpid failed");
        assert!(libc::WIFEXITED(status), "child did not exit: {status:#x}");
        match libc::WEXITSTATUS(status) {
            0 => {}
            NO_LOW_DESCRIPTOR => panic!("the child could not place a file on descriptor 0"),
            code => panic!("the filter stayed on a stdio descriptor (child exit {code})"),
        }
    }

    #[test]
    fn encodes_packed_sock_filter_records() {
        let program = build_program(NativeArchitecture::X86_64);
        let mut bytes = Vec::new();
        for instruction in &program {
            instruction.encode(&mut bytes);
        }
        assert_eq!(bytes.len(), program.len() * 8);
    }

    #[test]
    fn supports_only_architectures_with_generated_filters() {
        assert_eq!(unsupported_architecture("x86_64"), None);
        assert_eq!(unsupported_architecture("aarch64"), None);
        assert_eq!(
            unsupported_architecture("riscv64"),
            Some("riscv64".to_string())
        );
    }

    #[test]
    fn inserts_seccomp_before_the_workload_command() {
        let mut args = vec![
            "--clearenv".to_string(),
            "--".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            "echo hello".to_string(),
        ];
        add_bwrap_args(&mut args, 17).expect("valid bwrap arguments");
        assert_eq!(
            args,
            [
                "--clearenv",
                "--seccomp",
                "17",
                "--",
                "sh",
                "-c",
                "echo hello"
            ]
        );
    }

    #[test]
    fn rejects_malformed_bwrap_arguments() {
        let mut args = vec!["--clearenv".to_string(), "echo hello".to_string()];
        assert!(add_bwrap_args(&mut args, 17).is_err());
    }

    #[test]
    fn rejects_conflicting_seccomp_arguments() {
        for option in ["--seccomp", "--add-seccomp-fd"] {
            let mut args = vec![
                option.to_string(),
                "23".to_string(),
                "--".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "echo hello".to_string(),
            ];
            assert!(add_bwrap_args(&mut args, 17).is_err());
        }
    }

    #[test]
    fn ignores_seccomp_words_in_option_operands_and_the_script() {
        let mut args = vec![
            "--setenv".to_string(),
            "FIRST".to_string(),
            "--seccomp".to_string(),
            "--chdir".to_string(),
            "--add-seccomp-fd".to_string(),
            "--".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            "printf '%s' --seccomp".to_string(),
        ];
        add_bwrap_args(&mut args, 17).expect("seccomp words in operands are not options");
        assert_eq!(&args[5..7], ["--seccomp", "17"]);
    }

    #[test]
    fn rejects_unknown_or_incomplete_generated_options() {
        for mut args in [
            vec![
                "--future-option".to_string(),
                "--".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "echo hello".to_string(),
            ],
            vec![
                "--setenv".to_string(),
                "NAME".to_string(),
                "--".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "echo hello".to_string(),
            ],
        ] {
            assert!(add_bwrap_args(&mut args, 17).is_err());
        }
    }

    #[test]
    fn accepts_the_cli_new_session_option() {
        let mut args = vec![
            "--new-session".to_string(),
            "--clearenv".to_string(),
            "--".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            "echo hello".to_string(),
        ];
        add_bwrap_args(&mut args, 17).expect("--new-session takes no operand");
        assert_eq!(&args[2..4], ["--seccomp", "17"]);
    }
}
