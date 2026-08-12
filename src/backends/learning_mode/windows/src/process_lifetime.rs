// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reconciliation between OS-attested job membership and kernel process events.

use std::collections::HashMap;

use learning_mode_core::{AnalyzeError, ProcessLifetime};

/// Maximum number of process generations accepted for one guarded capture.
pub const MAX_JOB_PROCESS_LIFETIMES: usize = 4096;

/// One process generation attested by a job notification and retained handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobProcessMembership {
    /// Process identifier reported by the job object.
    pub pid: u32,
    /// Exact creation time read from a retained process handle.
    pub creation_filetime: u64,
    /// Exact exit time read from the same retained process handle.
    pub exit_filetime: u64,
    /// Ordered position of `JOB_OBJECT_MSG_NEW_PROCESS`.
    pub start_sequence: usize,
    /// FILETIME when the guardian received the new-process message.
    pub start_observed_filetime: u64,
    /// Ordered position of the exit notification, when the port delivered one.
    pub end_sequence: Option<usize>,
    /// FILETIME when the guardian received the exit-process or active-zero message.
    pub end_observed_filetime: u64,
}

/// Bounded job membership evidence captured by the elevated guardian.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobMembershipSnapshot {
    /// Exact root generation attested from the duplicated process handle.
    pub root_process: ProcessLifetime,
    /// FILETIME immediately before the job was associated with the completion port.
    pub attached_filetime: u64,
    /// FILETIME when `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` was received.
    pub completed_filetime: u64,
    /// Kernel accounting count for all process generations ever assigned to the job.
    pub total_processes: u32,
    /// Number of ordered PID-bearing completion-port notifications retained.
    pub notification_count: usize,
    /// Completed descendant generations attested by job notifications.
    pub processes: Vec<JobProcessMembership>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelProcessLifetime {
    pub(crate) lifetime: ProcessLifetime,
    pub(crate) start_order: usize,
    pub(crate) end_order: usize,
}

/// Reconciles job membership evidence with complete kernel process generations.
///
/// Every generation has exact creation and exit times from a retained process
/// handle whose job membership the guardian verified. The ETL must contain the
/// same exact start/end pair for each descendant.
pub(crate) fn reconcile_job_membership(
    membership: &JobMembershipSnapshot,
    kernel_lifetimes: &[KernelProcessLifetime],
) -> Result<Vec<ProcessLifetime>, AnalyzeError> {
    validate_membership(membership)?;

    let mut members_by_pid = HashMap::<u32, Vec<(usize, JobProcessMembership)>>::new();
    for (index, process) in membership.processes.iter().copied().enumerate() {
        members_by_pid
            .entry(process.pid)
            .or_default()
            .push((index, process));
    }
    let mut lifetimes_by_pid = HashMap::<u32, Vec<(usize, KernelProcessLifetime)>>::new();
    for (index, lifetime) in kernel_lifetimes.iter().copied().enumerate() {
        lifetimes_by_pid
            .entry(lifetime.lifetime.pid)
            .or_default()
            .push((index, lifetime));
    }

    let mut selected = vec![None; membership.processes.len()];
    for (pid, members) in members_by_pid {
        let lifetimes = lifetimes_by_pid.remove(&pid).unwrap_or_default();
        let matches = unique_monotonic_matches(membership, pid, &members, &lifetimes)?;
        for ((member_index, _), lifetime_index) in members.into_iter().zip(matches) {
            selected[member_index] = Some(lifetimes[lifetime_index]);
        }
    }

    let mut ordered_events = Vec::with_capacity(membership.notification_count);
    for (index, process) in membership.processes.iter().enumerate() {
        let (_, lifetime) = selected[index].ok_or_else(|| {
            AnalyzeError::Decode(format!(
                "missing reconciled kernel generation for job-attested PID {}",
                process.pid
            ))
        })?;
        ordered_events.push((process.start_sequence, lifetime.start_order));
        if let Some(end_sequence) = process.end_sequence {
            ordered_events.push((end_sequence, lifetime.end_order));
        }
    }
    ordered_events.sort_unstable_by_key(|(membership_order, _)| *membership_order);
    if ordered_events
        .windows(2)
        .any(|events| events[0].1 >= events[1].1)
    {
        return Err(AnalyzeError::Decode(
            "job membership order disagrees with kernel process lifecycle order".to_string(),
        ));
    }

    let mut selected = selected
        .into_iter()
        .map(|selected| {
            selected
                .map(|(_, lifetime)| lifetime)
                .ok_or_else(|| AnalyzeError::Decode("incomplete reconciliation".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    selected.sort_unstable_by_key(|lifetime| lifetime.start_order);
    let mut reconciled = Vec::with_capacity(selected.len() + 1);
    reconciled.push(membership.root_process);
    reconciled.extend(selected.into_iter().map(|lifetime| lifetime.lifetime));
    reconciled.sort_unstable_by_key(|lifetime| lifetime.start_filetime);
    Ok(reconciled)
}

fn validate_membership(membership: &JobMembershipSnapshot) -> Result<(), AnalyzeError> {
    if membership.root_process.pid == 0
        || membership.root_process.end_filetime < membership.root_process.start_filetime
    {
        return Err(AnalyzeError::Decode(
            "guarded sandbox root process generation is invalid".to_string(),
        ));
    }
    let retained_processes = membership.processes.len() + 1;
    if retained_processes > MAX_JOB_PROCESS_LIFETIMES {
        return Err(AnalyzeError::Decode(format!(
            "guarded sandbox job exceeded the {MAX_JOB_PROCESS_LIFETIMES}-process limit"
        )));
    }
    if u32::try_from(retained_processes).ok() != Some(membership.total_processes) {
        return Err(AnalyzeError::Decode(format!(
            "guarded sandbox job accounting reported {} process generation(s), but {} unique \
             generation(s) were retained",
            membership.total_processes, retained_processes
        )));
    }
    if membership.completed_filetime < membership.attached_filetime {
        return Err(AnalyzeError::Decode(
            "guarded sandbox job completion predates job attachment".to_string(),
        ));
    }
    if membership.root_process.end_filetime > membership.completed_filetime {
        return Err(AnalyzeError::Decode(
            "guarded sandbox root exit follows job completion".to_string(),
        ));
    }

    let mut sequences = Vec::with_capacity(membership.notification_count);
    for process in &membership.processes {
        sequences.push(process.start_sequence);
        if let Some(end_sequence) = process.end_sequence {
            if end_sequence <= process.start_sequence {
                return Err(AnalyzeError::Decode(format!(
                    "job-attested PID {} has an exit notification before its start notification",
                    process.pid
                )));
            }
            sequences.push(end_sequence);
        }
    }
    sequences.sort_unstable();
    if sequences.len() != membership.notification_count {
        return Err(AnalyzeError::Decode(
            "guarded sandbox job notification count is inconsistent".to_string(),
        ));
    }
    if sequences
        .iter()
        .copied()
        .enumerate()
        .any(|(expected, actual)| expected != actual)
    {
        return Err(AnalyzeError::Decode(
            "guarded sandbox job membership notification order is incomplete".to_string(),
        ));
    }
    Ok(())
}

fn unique_monotonic_matches(
    membership: &JobMembershipSnapshot,
    pid: u32,
    members: &[(usize, JobProcessMembership)],
    lifetimes: &[(usize, KernelProcessLifetime)],
) -> Result<Vec<usize>, AnalyzeError> {
    let member_count = members.len();
    let lifetime_count = lifetimes.len();
    let width = lifetime_count + 1;
    let mut ways = vec![0u8; (member_count + 1) * width];
    ways[..width].fill(1);

    for member_index in 1..=member_count {
        for lifetime_index in 1..=lifetime_count {
            let without = ways[member_index * width + lifetime_index - 1];
            let with = if generation_matches(
                membership,
                members[member_index - 1].1,
                lifetimes[lifetime_index - 1].1,
            ) {
                ways[(member_index - 1) * width + lifetime_index - 1]
            } else {
                0
            };
            ways[member_index * width + lifetime_index] = without.saturating_add(with).min(2);
        }
    }

    match ways[member_count * width + lifetime_count] {
        0 => {
            return Err(AnalyzeError::Decode(format!(
                "missing exact kernel process generation for job-attested PID {pid}"
            )))
        }
        2.. => {
            return Err(AnalyzeError::Decode(format!(
                "ambiguous kernel process generations for job-attested PID {pid}"
            )))
        }
        _ => {}
    }

    let mut matches = Vec::with_capacity(member_count);
    let mut member_index = member_count;
    let mut lifetime_index = lifetime_count;
    while member_index > 0 {
        if lifetime_index == 0 {
            return Err(AnalyzeError::Decode(format!(
                "missing exact kernel process generation for job-attested PID {pid}"
            )));
        }
        let without = ways[member_index * width + lifetime_index - 1];
        let can_take = generation_matches(
            membership,
            members[member_index - 1].1,
            lifetimes[lifetime_index - 1].1,
        ) && ways[(member_index - 1) * width + lifetime_index - 1] == 1;
        if without == 0 && can_take {
            matches.push(lifetime_index - 1);
            member_index -= 1;
            lifetime_index -= 1;
        } else {
            lifetime_index -= 1;
        }
    }
    matches.reverse();
    Ok(matches)
}

fn generation_matches(
    membership: &JobMembershipSnapshot,
    process: JobProcessMembership,
    kernel: KernelProcessLifetime,
) -> bool {
    let lifetime = kernel.lifetime;
    lifetime.pid == process.pid
        && lifetime.start_filetime == process.creation_filetime
        && lifetime.end_filetime == process.exit_filetime
        && lifetime.end_filetime >= membership.attached_filetime
        && lifetime.start_filetime <= membership.completed_filetime
        && lifetime.end_filetime <= membership.completed_filetime
        && lifetime.start_filetime <= process.start_observed_filetime
        && lifetime.end_filetime <= process.end_observed_filetime
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(pid: u32, start: u64, end: u64) -> JobProcessMembership {
        JobProcessMembership {
            pid,
            creation_filetime: start,
            exit_filetime: end,
            start_sequence: 0,
            start_observed_filetime: end + 30,
            end_sequence: Some(1),
            end_observed_filetime: end + 40,
        }
    }

    fn snapshot(process: JobProcessMembership) -> JobMembershipSnapshot {
        JobMembershipSnapshot {
            root_process: ProcessLifetime {
                pid: 7,
                start_filetime: 90,
                end_filetime: 180,
            },
            attached_filetime: 100,
            completed_filetime: 200,
            total_processes: 2,
            notification_count: 2,
            processes: vec![process],
        }
    }

    fn kernel(pid: u32, start: u64, end: u64, order: usize) -> KernelProcessLifetime {
        KernelProcessLifetime {
            lifetime: ProcessLifetime {
                pid,
                start_filetime: start,
                end_filetime: end,
            },
            start_order: order,
            end_order: order + 1,
        }
    }

    #[test]
    fn short_lived_process_that_exited_before_notification_is_reconciled() {
        let membership = snapshot(member(42, 110, 120));
        let lifetimes = reconcile_job_membership(&membership, &[kernel(42, 110, 120, 0)])
            .expect("short-lived process should reconcile from sealed ETL");

        assert_eq!(
            lifetimes,
            vec![
                ProcessLifetime {
                    pid: 7,
                    start_filetime: 90,
                    end_filetime: 180,
                },
                ProcessLifetime {
                    pid: 42,
                    start_filetime: 110,
                    end_filetime: 120,
                }
            ]
        );
    }

    #[test]
    fn pid_reuse_selects_only_generation_inside_attested_window() {
        let membership = snapshot(member(42, 110, 120));
        let kernel_lifetimes = [
            kernel(42, 10, 20, 0),
            kernel(42, 110, 120, 2),
            kernel(42, 210, 220, 4),
        ];

        let lifetimes = reconcile_job_membership(&membership, &kernel_lifetimes)
            .expect("the attested generation should be unique");

        assert_eq!(
            lifetimes,
            vec![membership.root_process, kernel_lifetimes[1].lifetime]
        );
    }

    #[test]
    fn repeated_job_pid_maps_to_distinct_ordered_generations() {
        let membership = JobMembershipSnapshot {
            root_process: ProcessLifetime {
                pid: 7,
                start_filetime: 90,
                end_filetime: 280,
            },
            attached_filetime: 100,
            completed_filetime: 300,
            total_processes: 3,
            notification_count: 4,
            processes: vec![
                JobProcessMembership {
                    pid: 42,
                    creation_filetime: 110,
                    exit_filetime: 120,
                    start_sequence: 0,
                    start_observed_filetime: 150,
                    end_sequence: Some(1),
                    end_observed_filetime: 160,
                },
                JobProcessMembership {
                    pid: 42,
                    creation_filetime: 210,
                    exit_filetime: 220,
                    start_sequence: 2,
                    start_observed_filetime: 250,
                    end_sequence: Some(3),
                    end_observed_filetime: 260,
                },
            ],
        };
        let kernel_lifetimes = [kernel(42, 110, 120, 0), kernel(42, 210, 220, 2)];

        let lifetimes = reconcile_job_membership(&membership, &kernel_lifetimes)
            .expect("both PID generations should reconcile in order");

        assert_eq!(
            lifetimes,
            std::iter::once(membership.root_process)
                .chain(kernel_lifetimes.iter().map(|kernel| kernel.lifetime))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn handle_attestation_excludes_other_generations_in_the_same_window() {
        let membership = snapshot(member(42, 110, 120));
        let lifetimes = reconcile_job_membership(
            &membership,
            &[kernel(42, 90, 105, 0), kernel(42, 110, 120, 2)],
        )
        .expect("the exact handle-attested generation should be selected");

        assert_eq!(
            lifetimes,
            vec![
                membership.root_process,
                ProcessLifetime {
                    pid: 42,
                    start_filetime: 110,
                    end_filetime: 120,
                },
            ]
        );
    }

    #[test]
    fn missing_generation_fails_closed() {
        let error = reconcile_job_membership(&snapshot(member(42, 110, 120)), &[])
            .expect_err("missing generation must fail");

        assert!(error.to_string().contains("missing exact"));
    }

    #[test]
    fn membership_limit_is_enforced() {
        let processes = (0..=MAX_JOB_PROCESS_LIFETIMES)
            .map(|index| JobProcessMembership {
                pid: index as u32,
                creation_filetime: 110,
                exit_filetime: 120,
                start_sequence: index * 2,
                start_observed_filetime: 150,
                end_sequence: Some(index * 2 + 1),
                end_observed_filetime: 160,
            })
            .collect();
        let membership = JobMembershipSnapshot {
            root_process: ProcessLifetime {
                pid: u32::MAX,
                start_filetime: 90,
                end_filetime: 190,
            },
            attached_filetime: 100,
            completed_filetime: 200,
            total_processes: (MAX_JOB_PROCESS_LIFETIMES + 2) as u32,
            notification_count: (MAX_JOB_PROCESS_LIFETIMES + 1) * 2,
            processes,
        };

        let error =
            reconcile_job_membership(&membership, &[]).expect_err("oversized membership must fail");

        assert!(error.to_string().contains("4096"));
    }

    #[test]
    fn attested_root_does_not_require_an_etl_start_event() {
        let membership = JobMembershipSnapshot {
            root_process: ProcessLifetime {
                pid: 42,
                start_filetime: 90,
                end_filetime: 180,
            },
            attached_filetime: 100,
            completed_filetime: 200,
            total_processes: 1,
            notification_count: 0,
            processes: Vec::new(),
        };

        let lifetimes = reconcile_job_membership(&membership, &[])
            .expect("the handle-attested root must reconcile without ETL lifecycle events");

        assert_eq!(lifetimes, vec![membership.root_process]);
    }

    #[test]
    fn job_accounting_mismatch_fails_closed() {
        let mut membership = snapshot(member(42, 110, 120));
        membership.total_processes = 3;

        let error = reconcile_job_membership(&membership, &[kernel(42, 110, 120, 0)])
            .expect_err("lost process notifications must fail closed");

        assert!(error.to_string().contains("accounting"));
    }
}
