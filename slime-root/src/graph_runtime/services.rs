use super::*;
use slime_proto::syscall_abi::io_resource_labels;

/// Serve the declared root mechanisms used by the component graph.
///
/// The IPC layer bounds the raw envelope; this dispatcher assigns meaning only
/// to labels owned by a surviving mechanism and refuses every other label.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_instance_graph(
    generation: &Generation<'_>,
    launched: &mut LaunchedInstances,
    endpoint: sel4::cap::Endpoint,
    console_endpoint: sel4::cap::Endpoint,
    tasks: &mut TaskTable<MAX_TASKS>,
    windows: &mut WindowTable<MAX_WINDOW_ENTRIES>,
    buffers: &mut SharedBufferTable,
    clock_service: &mut clock::ClockService,
    wait_set_service: &mut wait_set::WaitSetService,
    scheduling_service: &mut scheduling::SchedulingService,
    scheduling_policy: Option<&boot_contracts::scheduling_class::SchedulingClass<'_>>,
    lifecycle_service: &mut lifecycle::LifecycleService,
    lifecycle_policy: Option<&boot_contracts::lifecycle_policy::LifecyclePolicy<'_>>,
    timer_adapter: &mut PhysicalTimerAdapter,
    allocator: &mut ObjectAllocator,
    scratch: &ScratchPage,
    io_service: &mut IoResourceService,
    io_authority: &mut platform::AuthorityInventory,
    // The fabric graph's declared `capabilitySlots` ceiling, or 0 when this
    // generation declares no graph (C8.13.3). Passed in rather than re-decoded
    // per request: the graph object is admission's, and the dispatch loop
    // needs one number from it.
    fabric_capability_slots: u32,
    // The block devices, needed here only by the selector variant's promotion
    // path. Component block traffic reaches the console thread, which owns
    // the tables (B43), so the service loop no longer touches them.
    // Interned directory scopes. Derive is the only writer and stays here,
    // because it also writes the caller's capability table, which this loop
    // writes on `cap_drop` and on a spawn's result (B45).
    scopes: &mut directory::ScopeTable,
    // The admitted adaptive policy, absent on a plane that declares none.
    // Growth and spawn both need it: one to charge an entitlement, the other
    // to bind a child's incarnation before the child is published.
    mut adaptive: Option<&mut super::adaptive::AdaptivePolicy<'_>>,
    #[cfg(slime_boot_selector)] block_devices: &mut device::BlockDevices,
    #[cfg(slime_boot_selector)] boot_runtime: &mut boot_selector::BootRuntime,
) {
    policy::report_memory_census(allocator, tasks, 0);
    let report_backing =
        generation.boot_action == boot_contracts::generation::BootAction::PrivateMemory;
    if report_backing {
        allocator.report_backing_snapshot("initial");
    }
    let mut terminations = supervision::Terminations::new();
    let mut retirements = supervision::Retirements::new();
    let mut cleanup_timer_armed = false;
    let mut healthy_emitted = false;

    slime_root::diagnostic_println!(
        "SLIME_ROOT allocator baseline live_slots={} live_objects={} live_bytes={} allocation_descriptor_capacity={} extent_descriptor_capacity={}",
        allocator.live_slots(),
        allocator.live_objects(),
        allocator.live_bytes(),
        allocator.allocation_descriptor_capacity(),
        allocator.extent_descriptor_capacity(),
    );
    let mut live = tasks.len();
    let mut unsupported = 0;
    let mut buffers_served = 0;
    let mut loans_served = 0;
    let mut spawns = 0;
    let mut drops = 0;
    let mut reclaimed_slots = 0;
    let mut iterations = 0;
    // Product is a resident graph, not a bounded verification workload. Its
    // idle components poll explicit non-blocking capabilities, so ordinary
    // healthy operation keeps producing root requests for the product's whole
    // lifetime. Finite planes retain the request bound as a livelock watchdog;
    // a generation may raise it through its authenticated arrival ceiling, and
    // admission has refused one on a product generation.
    let declared_ceiling = crate::generation::graph_arrival_ceiling(generation);
    let iteration_limit = (generation.boot_action
        != boot_contracts::generation::BootAction::Product)
        .then(|| declared_ceiling.unwrap_or(MAX_GRAPH_ITERATIONS));
    if let Some(ceiling) = declared_ceiling {
        slime_root::diagnostic_println!("SLIME_GRAPH arrival-ceiling={}", ceiling);
    }
    let required = (0..generation.instance_count())
        .filter(|index| {
            generation.instance(*index).is_ok_and(|instance| {
                instance.autostart && instance.health == InstanceHealth::Required
            })
        })
        .count();
    let mut completed_required = [false; generation::MAX_ADMITTED_INSTANCES];
    // Resident instances never complete, so a graph holding a live resident
    // required instance certifies once every bounded required instance has
    // completed, with the residents still counted live.
    let mut resident_instances = [false; generation::MAX_ADMITTED_INSTANCES];
    for (index, resident) in resident_instances
        .iter_mut()
        .enumerate()
        .take(generation.instance_count())
    {
        *resident = crate::generation::instance_lifetime(generation, index) == Lifetime::Resident;
    }
    let resident_required = (0..generation.instance_count())
        .filter(|index| {
            resident_instances[*index]
                && generation.instance(*index).is_ok_and(|instance| {
                    instance.autostart && instance.health == InstanceHealth::Required
                })
        })
        .count();
    let mut resident_certified = false;
    // The last thing rendered before the loop blocks in `seL4_Recv`. Without
    // it, a graph whose components never send is indistinguishable on the
    // panel from one that crashed on entry: both leave `COMPONENTS RUNNING`
    // as the final line. `SERVING` says the dispatcher reached its receive.
    //
    // SAFETY: the console dispatcher is running by now but never renders, so
    // this is still the only writer, and this runs once before the loop.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        crate::framebuffer::with_panel(allocator, |panel, allocator| {
            let _ = crate::boot_record::render_stage(panel, allocator, "SERVING - AWAITING GRAPH");
        });
    }
    while iteration_limit.is_none_or(|limit| iterations < limit) {
        for id in retirements.tasks().into_iter().flatten() {
            retirements.retry(id, |phase| match phase {
                supervision::RetirementPhase::Suspend => {
                    tasks.get(id).is_some_and(|task| task.suspend().is_ok())
                }
                supervision::RetirementPhase::Io => {
                    match io_resource::reclaim_driver(
                        io_service,
                        io_authority,
                        allocator,
                        tasks,
                        id,
                    ) {
                        Ok(()) => true,
                        Err(error) => {
                            slime_root::diagnostic_println!(
                                "SLIME_IO reclaim pending task={} error={error:?}",
                                id.0
                            );
                            false
                        }
                    }
                }
                supervision::RetirementPhase::Buffers => tasks
                    .get(id)
                    .map(|task| VSpaceCap(task.vspace.vspace.bits() as usize))
                    .is_some_and(|vspace| reclaim_dead_task(buffers, allocator, id, vspace)),
                supervision::RetirementPhase::Arena => {
                    if reclaim_task_objects(
                        generation,
                        launched,
                        tasks,
                        allocator,
                        adaptive.as_deref_mut(),
                        &mut reclaimed_slots,
                        id,
                    ) {
                        windows.release(id);
                        true
                    } else {
                        false
                    }
                }
            });
        }
        if !retirements.is_empty() || cleanup_timer_armed {
            let now = timer_adapter
                .monotonic_now()
                .unwrap_or_else(|error| fatal!("SLIME_GRAPH FAIL cleanup clock error={error:?}"));
            let programming = if retirements.is_empty() {
                clock_service.cancel_cleanup_retry(now)
            } else {
                clock_service.arm_cleanup_retry(now, (timer_adapter.frequency_hz() / 100).max(1))
            }
            .unwrap_or_else(|error| fatal!("SLIME_GRAPH FAIL cleanup timer error={error:?}"));
            apply_deadline_programming(timer_adapter, programming).unwrap_or_else(|error| {
                fatal!("SLIME_GRAPH FAIL cleanup timer programming error={error:?}")
            });
            cleanup_timer_armed = !retirements.is_empty();
        }
        // Checked here rather than after dispatch: the last bounded instance's
        // retirement completes on a cleanup-timer wake, and a resident instance
        // that is merely running sends the root nothing that would reach the
        // post-dispatch check.
        if resident_required != 0
            && healthy_emitted
            && !resident_certified
            && retirements.is_empty()
            && let (live_required, completed) =
                required_accounting(generation, tasks, &completed_required)
            && live_required == resident_required
            && completed + resident_required == required
        {
            slime_root::diagnostic_println!(
                "SLIME_GRAPH HEALTHY generation={} required={} live={} completed={} failed=0",
                generation.number,
                required,
                live_required,
                completed,
            );
            resident_certified = true;
        }
        if live == 0 && retirements.is_empty() {
            slime_root::diagnostic_println!(
                "SLIME_ROOT allocator quiescent live_slots={} live_objects={} live_bytes={}",
                allocator.live_slots(),
                allocator.live_objects(),
                allocator.live_bytes(),
            );
            break;
        }
        // Through `recv_request` rather than a hand-rolled register read, so the
        // bound `graph.rs` documents is the bound the loop enforces: a message
        // longer than the fast registers, or one carrying real seL4 extra-caps,
        // is refused here instead of being silently truncated. Slime capability
        // transfer is by logical slot number in the payload; the transport never
        // moves a seL4 capability, and this is what makes that checkable.
        sel4::with_ipc_buffer_mut(|buffer| {
            buffer.set_recv_slot(
                &sel4::init_thread::slot::CNODE
                    .cap()
                    .absolute_cptr(sel4::cap::Unspecified::from_bits(task::CHILD_SLOT_RECEIVE)),
            );
        });
        // Timer Notifications are deliberately outside the component-request
        // progress budget: aborting after a valid expiry would misdiagnose
        // timer traffic as a wedged graph. Per-holder and aggregate timer
        // quotas bound the work performed by each wake.
        let reception = ipc::recv_request(endpoint);
        let (info, badge) = (reception.info, reception.badge);
        if badge == timer_adapter.signal_badge() {
            // A bound-Notification delivery writes the badge register only;
            // message-info registers retain unrelated state and are not a
            // valid request-shape discriminator on this path.
            service_clock_source(clock_service, timer_adapter);
            continue;
        }
        iterations = iterations.saturating_add(1);
        if iteration_limit.is_none() && iterations == RESIDENT_CHECKPOINT_ITERATIONS {
            slime_root::diagnostic_println!(
                "SLIME_GRAPH resident checkpoint live={live} iterations={iterations}"
            );
        }
        let Some((id, arrival)) = TaskId::from_badge(badge) else {
            slime_root::diagnostic_println!(
                "SLIME_GRAPH unbadged arrival badge={badge:#x} rejected"
            );
            ipc::reply(Response::error(IpcError::InvalidOperation));
            continue;
        };
        if tasks.get(id).is_none() || retirements.contains(id) {
            slime_root::diagnostic_println!("SLIME_GRAPH unknown task badge={badge:#x} rejected");
            ipc::reply(Response::error(IpcError::InvalidOperation));
            continue;
        }
        if arrival == Arrival::Fault {
            let decoded_fault = fault::decode_fault(&info);
            if let Some(instance_index) = tasks.get(id).and_then(|task| task.instance)
                && let Ok(instance) = generation.instance(instance_index)
                && instance.health == InstanceHealth::Required
            {
                match decoded_fault {
                    Ok(detail) => fatal!(
                        "SLIME_GRAPH FAIL required instance {} fault kind={:?} instruction={:?} address={:?}",
                        instance.name,
                        detail.kind,
                        detail.instruction,
                        detail.address,
                    ),
                    Err(error) => fatal!(
                        "SLIME_GRAPH FAIL required instance {} fault error={error:?}",
                        instance.name,
                    ),
                }
            }
            let reason = match decoded_fault {
                Ok(detail) => {
                    slime_root::diagnostic_println!(
                        "SLIME_GRAPH component fault task={} kind={:?} address={:?}",
                        id.0,
                        detail.kind,
                        detail.address,
                    );
                    // A non-required component faulting does not end the boot,
                    // but it can leave the graph never certified healthy — and
                    // on a machine with no serial port the line above is
                    // invisible, so the panel would simply stop at
                    // `COMPONENTS RUNNING` with no reason given.
                    //
                    // SAFETY: the service loop owns the panel; the console
                    // dispatcher never renders.
                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        crate::framebuffer::with_panel(allocator, |panel, allocator| {
                            let _ = crate::boot_record::render_stage(
                                panel,
                                allocator,
                                "COMPONENT FAULTED",
                            );
                        });
                    }
                    detail.kind.reason_code()
                }
                Err(error) => {
                    slime_root::diagnostic_println!(
                        "SLIME_GRAPH fault undecodable task={} error={error:?}",
                        id.0
                    );
                    // SAFETY: as above.
                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        crate::framebuffer::with_panel(allocator, |panel, allocator| {
                            let _ = crate::boot_record::render_stage(
                                panel,
                                allocator,
                                "COMPONENT FAULT UNDECODABLE",
                            );
                        });
                    }
                    u64::MAX
                }
            };
            record_termination(
                &mut terminations,
                tasks,
                id,
                supervision::Termination::Fault(reason),
            );
            if let Some(task) = tasks.get(id) {
                let _ = task.suspend();
            }
            // C9.2: wake every waiter whose declared supervision source names
            // this task, *before* its own row is dropped, so a supervisor
            // learns of a peer's death through the source it registered rather
            // than by timing out. Signalled while the authority tables are
            // still intact, because the wake is gated on the waiter's slot
            // still holding a handle naming this task.
            signal_declared_death(wait_set_service, tasks, id);
            drop_task_clock(clock_service, timer_adapter, id);
            // C9.3: a class row keyed by a dead task would let a later task at
            // the same table index inherit its band. `TaskId` is never reused,
            // so this is bookkeeping rather than a correctness fix, but a table
            // that grows for the boot's lifetime is the shape a bounded root
            // should not have.
            scheduling_service.release(id);
            // C9.4: record *why* this task ended before its per-task row goes,
            // so `RESTART_ADMIT` can refuse a cause the policy does not name.
            // The instance row survives; only the task state is released.
            if let Some((instance, recorded)) =
                lifecycle_service.record_termination(id, lifecycle::Terminal::Fault)
            {
                slime_root::diagnostic_println!(
                    "SLIME_LIFECYCLE terminated task={} instance={instance} cause={}",
                    id.0,
                    recorded.name(),
                );
            }
            lifecycle_service.release(id);
            if !retirements.insert(id) {
                return fatal!("SLIME_GRAPH FAIL pending retirement capacity task={}", id.0);
            }
            live -= 1;
            continue;
        }

        let request = match reception.request {
            Ok(request) => request,
            Err(error) => {
                slime_root::diagnostic_println!(
                    "SLIME_GRAPH request rejected task={} label={} error={error:?}",
                    id.0,
                    info.label()
                );
                ipc::reply(Response::error(error));
                continue;
            }
        };
        let Some(instance) = launched.instance_for_task(id) else {
            ipc::reply(Response::error(IpcError::BadCapability));
            continue;
        };
        let Some(required_service) = ipc::service_for_root_label(request.label) else {
            slime_root::diagnostic_println!(
                "SLIME_GRAPH unsupported service task={} label={} result={} caller_survives=1",
                id.0,
                request.label,
                IpcError::UnsupportedOperation.slime_status(),
            );
            unsupported += 1;
            ipc::reply(Response::error(IpcError::UnsupportedOperation));
            continue;
        };
        let (label, words) = (request.label, request.mrs);
        if ipc::clock_request_len(label).is_some_and(|expected| request.len != expected) {
            slime_root::diagnostic_println!(
                "SLIME_CLOCK malformed task={} label={label} words={} expected={:?}",
                id.0,
                request.len,
                ipc::clock_request_len(label),
            );
            ipc::reply(Response::error(IpcError::InvalidLength));
            continue;
        }
        if ipc::scheduling_request_len(label).is_some_and(|expected| request.len != expected) {
            slime_root::diagnostic_println!(
                "SLIME_SCHED malformed task={} label={label} words={} expected={:?}",
                id.0,
                request.len,
                ipc::scheduling_request_len(label),
            );
            ipc::reply(Response::error(IpcError::InvalidLength));
            continue;
        }
        if ipc::lifecycle_request_len(label).is_some_and(|expected| request.len != expected) {
            slime_root::diagnostic_println!(
                "SLIME_LIFECYCLE malformed task={} label={label} words={} expected={:?}",
                id.0,
                request.len,
                ipc::lifecycle_request_len(label),
            );
            ipc::reply(Response::error(IpcError::InvalidLength));
            continue;
        }
        if ipc::io_resource_request_len(label).is_some_and(|expected| request.len != expected) {
            ipc::reply(Response::error(IpcError::InvalidLength));
            continue;
        }
        let authorized = generation
            .instance_has_service(instance, required_service)
            .unwrap_or(false);
        if !authorized {
            slime_root::diagnostic_println!(
                "SLIME_GRAPH service refused task={} label={} class=undeclared",
                id.0,
                request.label,
            );
            ipc::reply(Response::error(IpcError::BadCapability));
            continue;
        }

        if matches!(
            label,
            io_resource_labels::BIND
                | io_resource_labels::MAP_MMIO
                | io_resource_labels::MMIO_READ32
                | io_resource_labels::MMIO_WRITE32
                | io_resource_labels::DMA_MAP
                | io_resource_labels::DMA_RELEASE
                | io_resource_labels::QUEUE_MAP
                | io_resource_labels::IRQ_ACK
                | io_resource_labels::REQUEST_BEGIN
                | io_resource_labels::REQUEST_SETTLE
        ) {
            ipc::reply(serve_io_resource(
                io_service,
                io_authority,
                allocator,
                buffers,
                tasks,
                id,
                slime_root::io_resource::DriverId(u64::from(id.0)),
                label,
                &words,
            ));
            continue;
        }
        match label {
            // M6.3: the three directory operations (P5.4.3).
            //
            // Mechanism, not policy. What a directory *contains* is a
            // filesystem component's business, built over the object store;
            // what the root owns is the unforgeable part — a shared namespace
            // root, scoped views that derivation may only narrow, and an atomic
            // M6.4: one scripted key event, gated on an `Input` capability.
            directory_labels::DERIVE => {
                ipc::reply(directory::serve_directory_derive(
                    tasks,
                    scopes,
                    windows.bound(id, descriptor_thread(words[1])),
                    scratch,
                    id,
                    &words,
                ));
            }
            // P5.4.2c: sectors, mediated.
            //
            // The root owns the driver because it owns the device untyped and
            // the DMA frames; what it does *not* own is any policy about what
            // the sectors mean. This arm authenticates the caller's capability,
            // checks the operation against its rights, and hands the request to
            // the driver. Partitioning, the object store, generations, and
            // recovery all sit above it in userspace, exactly as they do on the
            // oracle.
            // A clean exit is a send, not a call: the task is suspended rather
            // than replied to.
            lifecycle_labels::EXIT => {
                let status = words[0] as i64;
                slime_root::diagnostic_println!(
                    "SLIME_GRAPH component exit task={} status={status}",
                    id.0
                );
                // As with faults: a non-required component exiting non-zero
                // leaves the graph uncertified without ending the boot, and
                // the line above reaches nothing on a serial-less machine.
                //
                // SAFETY: the service loop owns the panel.
                #[cfg(target_arch = "x86_64")]
                if status != 0 {
                    unsafe {
                        crate::framebuffer::with_panel(allocator, |panel, allocator| {
                            let _ = crate::boot_record::render_stage(
                                panel,
                                allocator,
                                "COMPONENT EXITED NONZERO",
                            );
                        });
                    }
                }
                // A resident instance runs for the life of its graph, so its
                // exit is never completion, whatever the status. A required one
                // ends the graph; an optional one is recorded unhealthy, which is
                // the outcome its supervisor observes instead of a clean exit.
                let exiting = tasks.get(id).and_then(|task| task.instance);
                let resident = exiting.is_some_and(|index| {
                    crate::generation::instance_lifetime(generation, index) == Lifetime::Resident
                });
                if resident
                    && let Some(instance_index) = exiting
                    && let Ok(instance) = generation.instance(instance_index)
                {
                    if instance.health == InstanceHealth::Required {
                        fatal!(
                            "SLIME_GRAPH FAIL resident instance {} exit status={status}",
                            instance.name
                        )
                    }
                    slime_root::diagnostic_println!(
                        "SLIME_GRAPH resident exit instance={} status={status} recorded=unhealthy",
                        instance.name
                    );
                }
                if status != 0
                    && let Some(instance_index) = exiting
                    && let Ok(instance) = generation.instance(instance_index)
                    && instance.health == InstanceHealth::Required
                {
                    fatal!(
                        "SLIME_GRAPH FAIL required instance {} exit status={status}",
                        instance.name
                    )
                }
                if status == 0
                    && !resident
                    && let Some(instance_index) = exiting
                    && generation
                        .instance(instance_index)
                        .is_ok_and(|instance| instance.health == InstanceHealth::Required)
                    && let Some(completed) = completed_required.get_mut(instance_index)
                {
                    *completed = true;
                }
                record_termination(
                    &mut terminations,
                    tasks,
                    id,
                    if resident {
                        supervision::Termination::Unhealthy
                    } else {
                        supervision::Termination::Exit(status)
                    },
                );
                if let Some(task) = tasks.get(id) {
                    let _ = task.suspend();
                }
                // C9.2, on the same ordering as the fault path above: an
                // orderly exit is a peer death too, and a supervisor that only
                // learned of faults would still have to poll for the common case.
                signal_declared_death(wait_set_service, tasks, id);
                drop_task_clock(clock_service, timer_adapter, id);
                // C9.3, on the fault path's rule: an orderly exit retires its
                // class row too.
                scheduling_service.release(id);
                // C9.4, on the fault path's rule: an orderly exit is a terminal
                // cause a restart policy may or may not name, and the two must
                // be distinguishable rather than collapsed into "it died".
                // The *recorded* cause is printed, not `Exit`: a component that
                // declared itself unhealthy exits immediately afterwards, so this
                // path runs for a death already recorded as `unhealthy`, and
                // printing the argument would put a second, contradictory
                // root-attributed line in the transcript (found by review).
                let terminal = if resident {
                    lifecycle::Terminal::Unhealthy
                } else {
                    lifecycle::Terminal::Exit
                };
                if let Some((instance, recorded)) =
                    lifecycle_service.record_termination(id, terminal)
                {
                    slime_root::diagnostic_println!(
                        "SLIME_LIFECYCLE terminated task={} instance={instance} cause={}",
                        id.0,
                        recorded.name(),
                    );
                }
                lifecycle_service.release(id);
                if !retirements.insert(id) {
                    return fatal!("SLIME_GRAPH FAIL pending retirement capacity task={}", id.0);
                }
                live -= 1;
            }
            // Spawn the executable a declared grant named. The slot resolves
            // through the caller's own table, so a component can start exactly
            // the executables its generation granted it and nothing else — an
            // ungranted slot resolves to nothing and is refused.
            //
            // The child's capabilities are derived copies of the parent's, each
            // narrowed to rights the parent already holds, installed at slots
            // `0..n` in the order the parent declared them. That numbering is
            // the whole distribution mechanism: a component addresses its first
            // spawn grant as slot 0, which is why `console.rs` and
            // `launch_context::CONTEXT_SLOT` read 0.
            spawn_labels::SPAWN => {
                let response = serve_spawn(
                    &mut retirements,
                    generation,
                    launched,
                    tasks,
                    windows,
                    buffers,
                    clock_service,
                    wait_set_service,
                    scheduling_service,
                    scheduling_policy,
                    lifecycle_service,
                    lifecycle_policy,
                    timer_adapter,
                    io_service,
                    io_authority,
                    allocator,
                    scratch,
                    endpoint,
                    console_endpoint,
                    id,
                    &words,
                    &mut spawns,
                    adaptive.as_deref_mut(),
                );
                if response.result >= 0 {
                    live += 1;
                }
                ipc::reply(response);
            }
            // Collect a child's outcome through the handle its spawn returned.
            //
            // Named through a capability, never through a task id: a component
            // can only learn the fate of a child it started, and only while it
            // still holds the handle. The record outlives the child itself —
            // see `supervision.rs` — because the answer is owed after the task
            // and its whole table are gone.
            supervision_labels::STATUS => {
                let response = serve_supervision_status(tasks, &terminations, id, &words);
                ipc::reply(response);
            }
            // Release a capability the caller holds.
            //
            // `spawn_or_fail` drops each supervision handle as soon as the
            // spawn returns, so a graph that launches many children does not
            // exhaust its own table on handles it never waits on. Dropping is
            // unconditional on rights: giving up authority needs none, and a
            // slot holding nothing is refused so a component cannot use the
            // answer to probe its table.
            capability_table_labels::DROP => {
                let slot = words[0] as u32;
                let dropped = tasks.authority_mut(id).and_then(|table| {
                    let capability = table.get(slot)?;
                    table.drop_slot(slot).then_some(capability)
                });
                ipc::reply(if dropped.is_some() {
                    drops += 1;
                    Response::success(0, 0)
                } else {
                    Response::error(IpcError::BadCapability)
                });
            }
            // C8.13.3: the caller's own live child-CSpace occupancy, in both
            // spaces its slots are counted in.
            //
            // `declared` is the space `capabilitySlots` bounds: the component's
            // own logical numbering from 0, which the builder budgets as
            // `FABRIC_FIRST_CONTROL_SLOT + control endpoints + buffers` and
            // which `fabric_graph_is_satisfiable` validates against
            // `graph::MAX_TASK_CAPS`. It is credited, because every install
            // into it is a root operation.
            //
            // `populated` is the physical CNode, whose bound is its own
            // capacity. It is a census rather than a counter, because a
            // component moves capabilities inside its own CSpace on paths the
            // root never sees -- `receive_native` moves a transferred Endpoint
            // out of the receive slot into the transfer region -- so a count
            // the root merely accumulated would be a count of what the root
            // did, not of what the CNode holds.
            //
            // The two are reported separately and each is checked against its
            // own bound. A logical index of 3 lives at physical slot 36, so
            // comparing either count to the other's ceiling would compare
            // quantities from different spaces.
            //
            // Self-scoped exactly as `SHARED BUFFER OCCUPANCY` is: the CSpace
            // counted belongs to `id`, which the badge authenticated, and the
            // operand word is ignored. There is no task argument to forge.
            //
            // The reply carries only facts about that CSpace and deliberately
            // not the graph's declared `capabilitySlots`. That limit is
            // generation-wide rather than per-holder, so shipping it would
            // disclose a graph fact to every caller of a self-scoped query,
            // including a component the graph grants nothing. The root keeps it
            // and reports a breach on serial instead; the gates read the
            // ceiling from the fixture, which is also what keeps the two from
            // disagreeing.
            capability_table_labels::OCCUPANCY => {
                let ceiling = fabric_capability_slots;
                let response = match tasks.get_mut(id) {
                    Some(task) => {
                        let capacity = cspace::capacity_of(task.cnode_size_bits);
                        match task.recount_cspace() {
                            Ok(populated) => {
                                // The peak is the root's, not a caller's: every
                                // install and release into declared space is a
                                // root operation, so between any two queries
                                // the count moves where only the root can see
                                // it. A component sampling twice would report
                                // the higher of two snapshots rather than the
                                // run's high-water mark.
                                let (declared, declared_peak) = task.declared_slots_occupied();
                                // A breach is reported, not refused: the slots
                                // are already installed, and the root refusing
                                // to say so would hide the one fact the
                                // declaration exists to surface. Reported on
                                // the peak, since a ceiling a run passed
                                // through and came back under was still passed.
                                if cspace::breaches_ceiling(declared_peak, ceiling) {
                                    slime_root::diagnostic_println!(
                                        "SLIME_GRAPH cspace occupancy over-ceiling task={} declared_live={declared} declared_peak={declared_peak} declared_ceiling={ceiling}",
                                        id.0
                                    );
                                }
                                // The physical count has its own bound, and
                                // breaching it would mean the census found
                                // more slots full than the CNode has -- an
                                // impossibility worth naming rather than
                                // silently reporting.
                                if populated > capacity {
                                    slime_root::diagnostic_println!(
                                        "SLIME_GRAPH cspace occupancy over-capacity task={} populated={populated} capacity={capacity}",
                                        id.0
                                    );
                                }
                                Response::success(
                                    0,
                                    pack_slot_occupancy(declared, declared_peak, populated),
                                )
                            }
                            Err(error) => {
                                slime_root::diagnostic_println!(
                                    "SLIME_GRAPH cspace occupancy refused task={} error={error:?}",
                                    id.0
                                );
                                Response::error(IpcError::BadCapability)
                            }
                        }
                    }
                    None => Response::error(IpcError::BadCapability),
                };
                ipc::reply(response);
            }
            // CP2: which of the caller's own slots holds a named binding.
            //
            // Self-scoped exactly as the two `OCCUPANCY` operations are. The
            // request carries a binding *name* and no task argument, and the
            // instance resolved is the one the badge authenticated, so there is
            // no caller identity to forge. A name the caller's instance does not
            // bind answers `InvalidOperation` and never another instance's slot,
            // which is what makes this answerable for every component: a
            // component learns its own layout, which it already knew at compile
            // time, and nothing else.
            //
            // A task with no instance index — the fixture child — has no
            // manifest bindings at all, so it is refused rather than resolved
            // against instance 0.
            capability_table_labels::RESOLVE_BINDING => {
                let response = match words.get(1).copied() {
                    // Refused on the descriptor's own length, before the window is
                    // mapped and copied. `resolve_binding_slot` bounds the name
                    // too, but that is after a page map/copy/unmap cycle sized by
                    // the window rather than by the 64-byte name: an operation any
                    // component may invoke should not let a request the root will
                    // reject cost more than one the root will answer.
                    Some(transfer)
                        if transfer_window::descriptor_len(transfer) > ipc::MAX_BINDING_NAME =>
                    {
                        Response::error(IpcError::InvalidLength)
                    }
                    Some(transfer) => {
                        match transfer_window::read_staged_array(
                            windows.bound(id, descriptor_thread(transfer)),
                            transfer,
                            &words,
                            scratch,
                        ) {
                            Ok(frame) => {
                                let name = frame.bytes();
                                // `instance` is the one the dispatch loop already
                                // authenticated for the service-authority check,
                                // not a second derivation from `tasks`. The two
                                // agree today, but they are cleared in different
                                // order during reclamation, so reading the fact
                                // twice is a divergence waiting to happen.
                                match ipc::resolve_binding_slot(generation, instance, name) {
                                    Some(slot) => Response::success(slot as i64, 0),
                                    None => {
                                        slime_root::diagnostic_println!(
                                            "SLIME_GRAPH binding unresolved task={} instance={instance} len={}",
                                            id.0,
                                            name.len()
                                        );
                                        Response::error(IpcError::InvalidOperation)
                                    }
                                }
                            }
                            Err(error) => Response::error(error),
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            // B70's fabric-graph read, answered only to the instance the graph
            // names as its own fabric component.
            //
            // The refusal is uniform: a caller that is not the holder, and a
            // generation that embeds no graph, both answer `InvalidOperation`.
            // Distinguishing them would let any component learn whether a graph
            // is present, which is the first bit of the route set C8.8 exists to
            // withhold.
            capability_table_labels::GRAPH_READ => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows = [0u8; ipc::GRAPH_ROWS_PER_CALL * ipc::GRAPH_ROW_BYTES];
                        match ipc::read_graph_participants(generation, instance, cursor, &mut rows)
                        {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::GRAPH_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => {
                                        slime_root::diagnostic_println!(
                                            "SLIME_GRAPH graph read task={} instance={instance} cursor={cursor} rows={count}",
                                            id.0,
                                        );
                                        Response::success(count as i64, descriptor)
                                    }
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => {
                                slime_root::diagnostic_println!(
                                    "SLIME_GRAPH graph read refused task={} instance={instance}",
                                    id.0,
                                );
                                Response::error(IpcError::InvalidOperation)
                            }
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            capability_table_labels::NETWORK_DESTINATIONS_READ => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows = [0u8; ipc::NETWORK_DESTINATION_ROWS_PER_CALL
                            * ipc::NETWORK_DESTINATION_ROW_BYTES];
                        match ipc::read_network_destinations(
                            generation, instance, cursor, &mut rows,
                        ) {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::NETWORK_DESTINATION_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => Response::success(count as i64, descriptor),
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => Response::error(IpcError::InvalidOperation),
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            capability_table_labels::NETWORK_INTERFACE_READ => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows = [0u8; ipc::NETWORK_INTERFACE_ROWS_PER_CALL
                            * ipc::NETWORK_INTERFACE_ROW_BYTES];
                        match ipc::read_network_interface(generation, instance, cursor, &mut rows) {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::NETWORK_INTERFACE_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => Response::success(count as i64, descriptor),
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => Response::error(IpcError::InvalidOperation),
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            capability_table_labels::ENTROPY_AUTHORITY_READ => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows = [0u8; ipc::ENTROPY_AUTHORITY_ROWS_PER_CALL
                            * ipc::ENTROPY_AUTHORITY_ROW_BYTES];
                        match ipc::read_entropy_authority(generation, instance, cursor, &mut rows) {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::ENTROPY_AUTHORITY_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => Response::success(count as i64, descriptor),
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => Response::error(IpcError::InvalidOperation),
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            capability_table_labels::NETWORK_APPLICATION_READ => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows = [0u8; ipc::NETWORK_APPLICATION_ROWS_PER_CALL
                            * ipc::NETWORK_APPLICATION_ROW_BYTES];
                        match ipc::read_network_application(generation, instance, cursor, &mut rows)
                        {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::NETWORK_APPLICATION_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => Response::success(count as i64, descriptor),
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => Response::error(IpcError::InvalidOperation),
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            // B83's per-ring block authority, answered only to the declared
            // block driver.
            //
            // Paged like the IO4 destination table and gated the same way: the
            // root authenticates who may read the table and bounds the bytes,
            // and reads no block right itself. Refusing a write on a read-only
            // ring is the driver's decision, because that is device policy.
            capability_table_labels::BLOCK_RING_AUTHORITY_READ => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows = [0u8; ipc::BLOCK_RING_AUTHORITY_ROWS_PER_CALL
                            * ipc::BLOCK_RING_AUTHORITY_ROW_BYTES];
                        match ipc::read_block_ring_authority(
                            generation, instance, cursor, &mut rows,
                        ) {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::BLOCK_RING_AUTHORITY_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => Response::success(count as i64, descriptor),
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => Response::error(IpcError::InvalidOperation),
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            // C9.2's declared wake sources, answered only about the caller
            // itself.
            //
            // Paged through the transfer window exactly as `GRAPH_READ` is, and
            // for the same reason: one record is 64 bytes against a 64-byte
            // message bound, so it cannot travel in registers. `InvalidOperation`
            // means the generation declares no wait set at all; a waiter the
            // table does not name is answered zero records, because being
            // declared nothing and there being nothing to declare are different
            // facts and only the first is about this caller.
            lifecycle_labels::WAIT_SOURCES => {
                let cursor = words.first().copied().unwrap_or(0) as usize;
                let response = match words.get(2).copied() {
                    Some(transfer) => {
                        let mut rows =
                            [0u8; ipc::WAIT_SOURCE_ROWS_PER_CALL * ipc::WAIT_SOURCE_ROW_BYTES];
                        match ipc::read_wait_sources(generation, instance, cursor, &mut rows) {
                            Some(count) => {
                                let bytes = &rows[..count * ipc::WAIT_SOURCE_ROW_BYTES];
                                match transfer_window::write_staged_region(
                                    windows.bound(id, descriptor_thread(transfer)),
                                    bytes,
                                    scratch,
                                ) {
                                    Ok(descriptor) => {
                                        slime_root::diagnostic_println!(
                                            "SLIME_WAIT sources task={} instance={} cursor={cursor} rows={count}",
                                            id.0,
                                            generation
                                                .instance(instance)
                                                .map_or("?", |instance| instance.name),
                                        );
                                        Response::success(count as i64, descriptor)
                                    }
                                    Err(error) => Response::error(error),
                                }
                            }
                            None => {
                                slime_root::diagnostic_println!(
                                    "SLIME_WAIT sources absent task={} instance={}",
                                    id.0,
                                    generation
                                        .instance(instance)
                                        .map_or("?", |instance| instance.name),
                                );
                                Response::error(IpcError::InvalidOperation)
                            }
                        }
                    }
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            // C9.5's declared recording participation, answered only about the
            // caller itself.
            //
            // In registers rather than through the transfer window, unlike
            // `WAIT_SOURCES` above: a waiter has a *table* of sources, while an
            // instance has at most one recording entry, and its four reportable
            // facts fit in two words. The stream identity is deliberately not
            // among them — it is the generation's join key, and answering it
            // would tell a caller about a peer it may not name.
            //
            // Never refused for want of authority. An instance the resource does
            // not name is answered role `0`, which is what lets one component
            // image run in a generation that records it and one that does not.
            lifecycle_labels::RECORDING_SOURCES => {
                let response = match ipc::read_recording_entry(generation, instance) {
                    Some((role, capacity, deterministic)) => {
                        slime_root::diagnostic_println!(
                            "SLIME_RECORD entry task={} instance={} role={role} capacity={capacity} deterministic={}",
                            id.0,
                            generation
                                .instance(instance)
                                .map_or("?", |instance| instance.name),
                            deterministic as u8,
                        );
                        Response::success(
                            i64::from(role),
                            u64::from(capacity) | (u64::from(deterministic) << 32),
                        )
                    }
                    None => {
                        slime_root::diagnostic_println!(
                            "SLIME_RECORD entry absent task={} instance={}",
                            id.0,
                            generation
                                .instance(instance)
                                .map_or("?", |instance| instance.name),
                        );
                        Response::success(0, 0)
                    }
                };
                ipc::reply(response);
            }
            // The caller's own declared lifetime, answered only about the
            // caller itself and never refused: an instance the generation does
            // not name resident is bounded.
            lifecycle_labels::LIFETIME_READ => {
                let lifetime = ipc::read_lifetime(generation, instance);
                slime_root::diagnostic_println!(
                    "SLIME_GRAPH lifetime task={} instance={} lifetime={}",
                    id.0,
                    generation
                        .instance(instance)
                        .map_or("?", |instance| instance.name),
                    match lifetime {
                        Lifetime::Resident => "resident",
                        Lifetime::Bounded => "bounded",
                    },
                );
                ipc::reply(Response::success(i64::from(lifetime.id()), 0));
            }
            // The graph index for a route the caller names by identity (B70).
            capability_table_labels::GRAPH_ROUTE_INDEX => {
                let response = match words.get(1).copied() {
                    Some(transfer) if transfer_window::descriptor_len(transfer) == 32 => {
                        match transfer_window::read_staged_array(
                            windows.bound(id, descriptor_thread(transfer)),
                            transfer,
                            &words,
                            scratch,
                        ) {
                            Ok(frame) => match <[u8; 32]>::try_from(frame.bytes()) {
                                Ok(identity) => match ipc::route_index_for(generation, &identity) {
                                    Some(index) => Response::success(index as i64, 0),
                                    None => Response::error(IpcError::InvalidOperation),
                                },
                                Err(_) => Response::error(IpcError::InvalidLength),
                            },
                            Err(error) => Response::error(error),
                        }
                    }
                    Some(_) => Response::error(IpcError::InvalidLength),
                    None => Response::error(IpcError::InvalidLength),
                };
                ipc::reply(response);
            }
            // One scalar from the authenticated fabric-graph header (B70).
            //
            // Table cardinalities stay holder-only. Schema-declared runtime
            // limits are also available to participants with a visible graph
            // row, so independently built workers can admit against the same
            // generation bounds. Every other field/caller is refused.
            capability_table_labels::GRAPH_QUERY => {
                let response = match words
                    .first()
                    .copied()
                    .and_then(|field| u32::try_from(field).ok())
                {
                    Some(field) => match ipc::graph_query(generation, instance, field) {
                        Some(value) => Response::success(value as i64, 0),
                        None => Response::error(IpcError::InvalidOperation),
                    },
                    None => Response::error(IpcError::InvalidOperation),
                };
                ipc::reply(response);
            }
            // Which composition this generation declares (B70).
            //
            // Unscoped, joining `GRAPH_ROUTE_INDEX` above rather than the
            // badge-scoped operations. The two are unscoped for different
            // reasons and the difference is the argument: 39 answers a fold
            // over bytes the caller supplied and so confirms something the
            // asker already held, while this reads no operand at all and
            // answers a property of the one generation the caller is already
            // executing inside. There is no per-caller answer to leak and
            // nothing a caller could learn about another; it names no route,
            // component, slot or capability, so unlike `GRAPH_READ` it
            // discloses no graph shape.
            //
            // Gated on lifecycle, not the capability table its label namespace
            // belongs to. `ipc::service_for_root_label` records why: an
            // operation every instance must be able to ask needs the one
            // service every instance declares.
            //
            // No operand is read. The request carries none, and ignoring the
            // word rather than validating it is what the two `OCCUPANCY`
            // operations already do for the same reason: there is nothing for
            // a caller to get wrong, so a length check would refuse requests
            // that are correct.
            //
            // The frozen numeric id, never the source spelling. `main`'s
            // bootstrap argument already carries exactly this number, so a
            // component asking here and a component reading its startup
            // argument decode one encoding rather than two.
            capability_table_labels::BOOT_ACTION => {
                ipc::reply(Response::success(generation.boot_action.id() as i64, 0));
            }
            // The live-child budget this generation declares for the caller's
            // own executable (B70).
            //
            // Self-scoped by badge, like the two `OCCUPANCY` operations: the
            // executable read is the authenticated instance's, so the request
            // carries no operand and names nobody. `spawn-service` sized its
            // live-child table and checked every request's `client_budget`
            // against a constant its build script parsed out of one manifest,
            // and `dango` stated the same number from its own copy of that
            // parse; this is the number both now ask for, so neither image is
            // tied to a generation.
            //
            // Nothing new is disclosed: `spawner_budget` already reads this
            // record to bound `serve_spawn`, so a caller learns the ceiling it
            // is about to be admitted against.
            //
            // No operand is read, for the reason `BOOT_ACTION` above records:
            // there is nothing for a caller to get wrong, so validating the
            // word would refuse correct requests.
            capability_table_labels::SPAWN_BUDGET => {
                let response = match ipc::spawn_budget(generation, instance) {
                    Some(budget) => Response::success(i64::from(budget), 0),
                    None => Response::error(IpcError::InvalidOperation),
                };
                ipc::reply(response);
            }
            // C10.1's task-private memory growth.
            //
            // Self-scoped by badge: the region grown and the VSpace it maps
            // into both come from the caller's own task record, so the request
            // carries a delta and no task argument and there is nothing to
            // forge. Gated on lifecycle rather than a capability service,
            // because a private heap is a property of being a task — a task
            // with no declared quota is refused by its zero ceiling, which is
            // a budget answer rather than an authority one.
            //
            // The answer is the page count *before* the growth, so an
            // allocator learns where its region ended without a second call,
            // and `delta = 0` is a pure size query that allocates nothing.
            lifecycle_labels::PRIVATE_MEMORY_GROW => {
                let delta = words[0] as usize;
                // An adaptive holder grows against its bound entitlement:
                // the guaranteed prefix from its reservation, the rest from
                // the pool, settled as one ledger transaction. On a plane
                // that carries a policy, a task the policy names no subject
                // for is refused on its absent entitlement rather than being
                // handed to the fixed path, whose window refusal would name
                // the symptom instead of the reason. Without a policy at all,
                // the fixed path is unchanged.
                let adaptive_response = match (adaptive.as_deref_mut(), tasks.private_binding(id)) {
                    (Some(policy), Some(binding)) => Some(serve_adaptive_growth(
                        generation, tasks, allocator, policy, binding, id, delta,
                    )),
                    (Some(_), None) if delta == 0 => {
                        let region = tasks
                            .get(id)
                            .map_or(private_memory::Region::DENIED, |task| task.private_memory);
                        Some(Response::success(
                            region.pages() as i64,
                            region.base() as sel4::Word,
                        ))
                    }
                    (Some(policy), None) => {
                        let instance = tasks
                            .get(id)
                            .and_then(|task| task.instance)
                            .and_then(|index| generation.instance(index).ok())
                            .map_or("", |instance| instance.name);
                        let pages = tasks.get(id).map_or(0, |task| task.private_memory.pages());
                        policy.refuse_unbound(id, instance, delta, pages);
                        Some(Response::error(IpcError::TransferFailed))
                    }
                    _ => None,
                };
                let response = match adaptive_response {
                    Some(response) => response,
                    None => match tasks.grow_private_memory(allocator, id, delta) {
                        Ok(previous) => {
                            // The growth's own record: what the task had, what it
                            // asked for, where the pages landed, and the root-wide
                            // total afterwards. A gate reads the base and the
                            // counts from here rather than from the component's
                            // self-report, because only the root knows what it
                            // actually mapped.
                            let region = tasks
                                .get(id)
                                .map(|task| task.private_memory)
                                .unwrap_or(private_memory::Region::DENIED);
                            slime_root::diagnostic_println!(
                                "SLIME_MEM grown task={} delta={delta} previous={previous} pages={} base={:#x} quota={} total={} large_frames={} base_frames={} leaf_tables={}",
                                id.0,
                                region.pages(),
                                region.base(),
                                region.quota(),
                                tasks.private_memory().total_pages(),
                                region.large_frames(),
                                region.base_frames(),
                                region.leaf_tables(),
                            );
                            // Primary is the previous page count; auxiliary is the
                            // window base. The base is answered rather than left
                            // for the caller to derive: it is the root that chose
                            // it, and a component recomputing the loader's
                            // arithmetic is the compile-time coupling B70 removed
                            // everywhere else. Zero pages means no region, and a
                            // denied region answers base zero, which is not a
                            // usable address on any child (`child_vspace` refuses a
                            // footprint starting at zero).
                            Response::success(previous as i64, region.base() as sel4::Word)
                        }
                        Err(task::TaskError::PrivateMemory(error)) => {
                            // The four causes are distinguished here, in the root's
                            // own record, and collapsed to one coarse status on the
                            // wire: a component learns that it cannot grow, not
                            // which of the root's predicates refused it.
                            slime_root::diagnostic_println!(
                                "SLIME_MEM refused task={} delta={delta} cause={} detail={error:?}",
                                id.0,
                                private_memory_cause(&error),
                            );
                            Response::error(IpcError::TransferFailed)
                        }
                        Err(error) => {
                            slime_root::diagnostic_println!(
                                "SLIME_MEM rejected task={} delta={delta} error={error:?}",
                                id.0
                            );
                            Response::error(IpcError::InvalidOperation)
                        }
                    },
                };
                ipc::reply(response);
            }
            capability_transfer_labels::EXPORT => {
                ipc::reply(serve_capability_export(
                    generation, launched, allocator, tasks, id, &words,
                ));
            }
            capability_transfer_labels::IMPORT => {
                ipc::reply(serve_capability_import(
                    allocator, tasks, generation, instance, id, &words,
                ));
            }
            capability_transfer_labels::EXPORT_CANCEL => {
                ipc::reply(serve_capability_cancel(allocator, tasks, id, &words));
            }
            capability_transfer_labels::EXPORT_FINALIZE => {
                ipc::reply(serve_capability_finalize(allocator, id, &words));
            }
            // B25: a second supervision handle naming a task the caller already
            // supervises.
            //
            // Each spawn returns exactly one handle, and neither route places it
            // twice — a spawn grant copies but must run before the child exists,
            // and `CapTransfer` moves. So a parent that must introduce one child
            // to two others could not, despite holding the authority.
            //
            // Authority is unchanged by construction: the new capability names
            // the same task, and its rights are the source's own, so this can
            // only ever produce a handle the caller could already have passed on.
            // `RIGHT_SUPERVISE` is required to ask, which is the same gate
            // `serve_supervision_status` gates a query behind.
            supervision_labels::DERIVE => {
                ipc::reply(serve_supervision_derive(tasks, id, &words));
            }
            // The shared-buffer plane, answered from the table that already
            // owns rights, quota, and frame accounting. `spawn-service` runs a
            // full create/map/write/seal/unmap/release cycle at startup and
            // exits non-zero if any step fails, so this is the operation set
            // that decides whether the declared graph reaches its service loop.
            shared_buffer_labels::CREATE => {
                let holder = HolderId(u64::from(id.0));
                // The caller's own request, both fields. `slot_with_flag` packs
                // the writability into bit 32 of the same word as the factory
                // slot, exactly as `SharedBufferMap` reads it — a region created
                // writable when its creator asked for read-only would carry
                // `BufferRights::WRITE`, so the root would be widening rights
                // past what was requested.
                let writable = words[0] >> 32 != 0;
                let pages = words[1] as usize;
                // B13: the factory the caller named, resolved before anything
                // is admitted. The grant authorizes the operation and the
                // budget bounds it — two independent gates, exactly as
                // `kernel/src/syscall/mod.rs::sys_shared_buffer_create` has
                // them. Until P5.3.3 this slot was discarded and the quota was
                // the only bound, which made authority to allocate follow from
                // a budget entry: ambient authority through the back door.
                let factory = tasks
                    .authority(id)
                    .and_then(|table| table.get((words[0] & 0xffff_ffff) as u32));
                let response = match factory {
                    Some(graph::CapabilityEntry::BufferFactory(capability))
                        if capability.rights.allows(RIGHT_BUFFER_CREATE) =>
                    {
                        match serve_buffer_create(buffers, allocator, holder, pages, writable) {
                            Ok(handle) => match tasks.authority_mut(id).and_then(|table| {
                                let slot = table.free_slot_from(1)?;
                                let rights = RIGHT_BUFFER_MAP
                                    | RIGHT_TRANSFER
                                    | if handle.rights.contains(shared_buffer::BufferRights::WRITE)
                                    {
                                        RIGHT_BUFFER_WRITE
                                    } else {
                                        0
                                    };
                                let capability =
                                    graph::CapabilityEntry::shared_buffer(handle, rights)?;
                                table.install(slot, capability).ok()?;
                                Some(slot)
                            }) {
                                Some(slot) => {
                                    buffers_served += 1;
                                    slime_root::diagnostic_println!(
                                        "SLIME_GRAPH buffer created task={} slot={slot} id={} pages={pages} writable={}",
                                        id.0,
                                        handle.id.0,
                                        u8::from(writable),
                                    );
                                    Response::success(i64::from(slot), handle.id.0)
                                }
                                None => {
                                    slime_root::diagnostic_println!(
                                        "SLIME_GRAPH buffer slot unavailable task={}",
                                        id.0
                                    );
                                    // As for `EndpointCreate` above:
                                    // `sys_shared_buffer_create` folds
                                    // `available_slots() >= 1` into its capability
                                    // check and answers `ERR_BAD_CAP`.
                                    Response::error(IpcError::BadCapability)
                                }
                            },
                            Err(error) => {
                                slime_root::diagnostic_println!(
                                    "SLIME_GRAPH buffer create refused task={} pages={pages} class={}",
                                    id.0,
                                    buffer_error_class(error),
                                );
                                Response::error(buffer_error_status(error))
                            }
                        }
                    }
                    _ => {
                        slime_root::diagnostic_println!(
                            "SLIME_GRAPH buffer create refused task={} class=ungranted",
                            id.0
                        );
                        Response::error(IpcError::BadCapability)
                    }
                };
                ipc::reply(response);
            }
            // The remaining shared-buffer operations act on a region this task
            // already holds, so they are answered against the same table.
            shared_buffer_labels::MAP => {
                let response = serve_buffer_lifecycle(
                    BufferLifecycleRequest::Map,
                    buffers,
                    allocator,
                    tasks,
                    id,
                    &words,
                    &mut buffers_served,
                );
                ipc::reply(response);
            }
            // The loan plane. A loan is the one authority this cutover moves
            // between components, and it is the narrow one: read-only over an
            // exact sealed subrange, bound to a receiver the lender named
            // through a capability, and settled exactly once.
            shared_buffer_labels::LOAN => {
                let response = serve_buffer_loan(
                    generation,
                    launched,
                    buffers,
                    allocator,
                    tasks,
                    id,
                    &words,
                    &mut loans_served,
                );
                ipc::reply(response);
            }
            shared_buffer_labels::LOAN_MAP => {
                let operation = LoanLifecycleRequest::Map;
                let response = serve_loan_lifecycle(
                    operation,
                    buffers,
                    allocator,
                    io_service,
                    io_authority,
                    tasks,
                    id,
                    &words,
                    &mut loans_served,
                );
                ipc::reply(response);
            }
            lifecycle_labels::UNHEALTHY => {
                // Two distinct meanings, and C9.4 separates them rather than
                // widening either.
                //
                // The *generation* half is unchanged: only a required instance
                // may mark this boot unhealthy, because that is a claim about
                // the whole generation's fitness and it spends a boot attempt.
                //
                // The *component* half is new, and it is C9.4's third terminal
                // cause. A component declaring itself broken is a cause a
                // restart policy may or may not name, and it must be
                // distinguishable from the plain exit that follows: the runtime's
                // `unhealthy()` exits immediately afterwards, so without this the
                // EXIT path would record `exit` and "it stopped" and "it said it
                // was broken" would be one observation. First-writer-wins in
                // `record_termination` makes this cause win over that exit.
                //
                // Recording it is scoped to a declared instance and nothing
                // more, because it names only the caller's own fate — there is
                // no subject operand and no peer to affect, exactly as
                // `EXIT`'s status word has none.
                let declared = launched.instance_for_task(id);
                let outcome = declared.and_then(|_| {
                    lifecycle_service.record_termination(id, lifecycle::Terminal::Unhealthy)
                });
                let recorded = outcome.is_some();
                if let Some((instance, cause)) = outcome {
                    slime_root::diagnostic_println!(
                        "SLIME_LIFECYCLE unhealthy task={} instance={instance} cause={}",
                        id.0,
                        cause.name(),
                    );
                }
                let boot_authorized = declared.is_some_and(|index| {
                    generation
                        .instance(index)
                        .is_ok_and(|instance| instance.health == InstanceHealth::Required)
                });
                let response = if !boot_authorized {
                    // A non-required instance recorded its cause and marked no
                    // boot: that is a success for what it asked, so answering an
                    // error would make a restartable component's own declaration
                    // read as a refusal. An instance the generation declares at
                    // all is still required — an undeclared caller reaches
                    // neither half and is refused.
                    if recorded {
                        Response::success(0, 0)
                    } else {
                        Response::error(IpcError::BadCapability)
                    }
                } else {
                    #[cfg(slime_boot_selector)]
                    {
                        match boot_runtime.mark_unhealthy() {
                            Ok(()) => {
                                slime_root::diagnostic_println!("SLIME_BOOT unhealthy");
                                Response::success(0, 0)
                            }
                            Err(error) => {
                                slime_root::diagnostic_println!(
                                    "SLIME_BOOT unhealthy refused error={error:?}"
                                );
                                Response::error(IpcError::InvalidOperation)
                            }
                        }
                    }
                    #[cfg(not(slime_boot_selector))]
                    {
                        // No selector to mark, but the cause is recorded, so this
                        // is the same success a non-required caller gets rather
                        // than the historical `-4`.
                        if recorded {
                            Response::success(0, 0)
                        } else {
                            Response::error(IpcError::InvalidOperation)
                        }
                    }
                };
                ipc::reply(response);
            }
            clock_labels::MONOTONIC_READ
            | clock_labels::TIMER_ARM
            | clock_labels::TIMER_CANCEL
            | clock_labels::SIMULATED_READ
            | clock_labels::SIMULATED_ADVANCE
            | clock_labels::RATE_READ => {
                let response =
                    serve_clock_request(clock_service, timer_adapter, id, label, words[0]);
                ipc::reply(response);
            }
            scheduling_labels::CLASS_READ | scheduling_labels::CLASS_PROMOTE => {
                let response = serve_scheduling_request(
                    scheduling_service,
                    scheduling_policy,
                    tasks,
                    id,
                    label,
                    &words,
                );
                ipc::reply(response);
            }
            lifecycle_labels::STATE_READ
            | lifecycle_labels::STATE_ADVANCE
            | supervision_labels::RESTART_ADMIT
            | supervision_labels::PARAMETER_READ
            | supervision_labels::PARAMETER_WRITE => {
                let response = serve_lifecycle_request(
                    lifecycle_service,
                    lifecycle_policy,
                    generation,
                    tasks,
                    timer_adapter,
                    id,
                    label,
                    &words,
                );
                ipc::reply(response);
            }
            shared_buffer_labels::UNMAP
            | shared_buffer_labels::SEAL
            | shared_buffer_labels::RELEASE => {
                let operation = match label {
                    shared_buffer_labels::UNMAP => BufferLifecycleRequest::Unmap,
                    shared_buffer_labels::SEAL => BufferLifecycleRequest::Seal,
                    shared_buffer_labels::RELEASE => BufferLifecycleRequest::Release,
                    _ => unreachable!(),
                };
                let response = serve_buffer_lifecycle(
                    operation,
                    buffers,
                    allocator,
                    tasks,
                    id,
                    &words,
                    &mut buffers_served,
                );
                ipc::reply(response);
            }
            shared_buffer_labels::RETURN | shared_buffer_labels::REVOKE => {
                let operation = if label == shared_buffer_labels::RETURN {
                    LoanLifecycleRequest::Return
                } else {
                    LoanLifecycleRequest::Revoke
                };
                let response = serve_loan_lifecycle(
                    operation,
                    buffers,
                    allocator,
                    io_service,
                    io_authority,
                    tasks,
                    id,
                    &words,
                    &mut loans_served,
                );
                ipc::reply(response);
            }
            // C8.13.1: the caller's own live shared-buffer occupancy.
            //
            // Read-only, and self-scoped by construction rather than by a
            // check: `holder` is derived from `id`, which the endpoint badge
            // authenticated, exactly as `CREATE` above derives it. The request
            // carries no holder argument, so there is nothing for a caller to
            // forge and no other holder it can name -- the same reason
            // `serve_buffer_lifecycle` needs no "is this yours" test.
            //
            // An undeclared holder is denied the way every other
            // shared-buffer operation already denies it: through the
            // table-held quota, which answers `HolderQuota::DENY` for a holder
            // the generation's `sharedBufferBudget` does not name. A zero
            // ceiling is refused rather than answered with four zeros,
            // because "you hold nothing" and "you may hold nothing" are
            // different facts and only the second is authority.
            shared_buffer_labels::OCCUPANCY => {
                let holder = HolderId(u64::from(id.0));
                let quota = buffers.quota(holder);
                let response = if quota == HolderQuota::DENY {
                    slime_root::diagnostic_println!(
                        "SLIME_GRAPH buffer occupancy refused task={} class=ungranted",
                        id.0
                    );
                    Response::error(IpcError::BadCapability)
                } else {
                    // No marker and no `buffers_served` bump: this is a
                    // read-only query a broker issues once per sweep, so a
                    // line per answer would flood serial and drown the markers
                    // gates read, and counting it would inflate a mutation
                    // count other planes assert against.
                    Response::success(0, pack_occupancy(buffers.holder_occupancy(holder)))
                };
                ipc::reply(response);
            }
            _ => {
                unsupported += 1;
                slime_root::diagnostic_println!(
                    "SLIME_GRAPH unsupported service task={} label={} result={} caller_survives=1",
                    id.0,
                    label,
                    IpcError::UnsupportedOperation.slime_status(),
                );
                ipc::reply(Response::error(IpcError::UnsupportedOperation));
            }
        }
        if required != 0 && retirements.is_empty() {
            let mut live_required = 0;
            let mut completed = 0;
            for instance_index in 0..generation.instance_count() {
                let Ok(instance) = generation.instance(instance_index) else {
                    continue;
                };
                if !instance.autostart || instance.health != InstanceHealth::Required {
                    continue;
                }
                if completed_required
                    .get(instance_index)
                    .copied()
                    .unwrap_or(false)
                {
                    completed += 1;
                    continue;
                }
                if tasks
                    .tasks()
                    .any(|task| task.instance == Some(instance_index))
                {
                    live_required += 1;
                }
            }
            if live_required + completed == required && (!healthy_emitted || live_required == 0) {
                #[cfg(slime_boot_selector)]
                if !healthy_emitted && boot_runtime.running_pending() {
                    let device = block_devices
                        .get_mut(0)
                        .unwrap_or_else(|| fatal!("boot promotion has no boot device"));
                    match boot_runtime.confirm(device) {
                        Ok(()) => slime_root::diagnostic_println!("SLIME_BOOT promoted"),
                        Err(error) => fatal!("boot promotion rejected: {error:?}"),
                    }
                }
                if completed == 0 {
                    let digest = generation.identity;
                    slime_root::diagnostic_println!(
                        "SLIME_GRAPH healthy generation={} instances={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} required={} live={} idle={} failed=0",
                        generation.number,
                        digest[0],
                        digest[1],
                        digest[2],
                        digest[3],
                        digest[4],
                        digest[5],
                        digest[6],
                        digest[7],
                        required,
                        live_required,
                        live_required,
                    );
                    #[cfg(any(slime_physical_target, slime_framework13_ai300))]
                    slime_root::diagnostic_println!(
                        "SLIME_ROOT READY target_profile={}",
                        crate::TARGET_PROFILE
                    );
                    // The same facts on the panel, for the machine whose only
                    // channel it is. Rendered after the serial markers so a
                    // display failure cannot suppress the chain an emulated
                    // plane reads, and reported rather than fatal: the graph is
                    // healthy either way, and a root that killed itself over a
                    // display would be less observable, not more.
                    // SAFETY: the service loop is the root's only thread here
                    // and this runs once, on the healthy edge.
                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        crate::framebuffer::with_panel(allocator, |panel, allocator| {
                            let rendered = crate::boot_record::render_ready(
                                panel,
                                allocator,
                                crate::TARGET_PROFILE,
                                generation.number,
                                &generation.identity,
                            )
                            .and_then(|()| crate::boot_record::render_idle(panel, allocator));
                            match rendered {
                                Ok(()) => {
                                    slime_root::diagnostic_println!("SLIME_DISPLAY ready rendered")
                                }
                                Err(error) => {
                                    slime_root::diagnostic_println!(
                                        "SLIME_DISPLAY ready failed {error:?}"
                                    )
                                }
                            }
                        });
                    }
                } else if live_required == 0 {
                    // Emitted after the accounting summary below: the QEMU
                    // gates stop reading at this terminal certification.
                } else {
                    slime_root::diagnostic_println!(
                        "SLIME_GRAPH HEALTHY generation={} required={} live={} completed={} failed=0",
                        generation.number,
                        required,
                        live_required,
                        completed,
                    );
                    resident_certified |= resident_required != 0
                        && live_required == resident_required
                        && completed + resident_required == required;
                }
                healthy_emitted = true;
            }
        }
    }
    // A finite plane whose declared success state is every required task
    // parked forever never reaches `live == 0`, so it can run this loop out
    // once certified. That is reported for the plane-specific observer to
    // adjudicate. Product has no request limit: its authenticated action
    // declares a resident service graph, and reaching an arbitrary request
    // count must not stop its root dispatcher.
    if iteration_limit == Some(iterations) && live != 0 {
        if !healthy_emitted {
            fatal!("SLIME_GRAPH FAIL graph iterations exhausted live={live}")
        }
        slime_root::diagnostic_println!(
            "SLIME_GRAPH exhausted live={live} iterations={iterations} certified=1"
        );
    }
    diagnostic_once::report();
    slime_root::diagnostic_println!(
        "SLIME_GRAPH served live={live} unsupported={unsupported} buffers={buffers_served} windows={} tasks={}",
        windows.len(),
        tasks.len(),
    );
    // out of the table, which is what frees a parent's declared spawn budget and
    // what makes `CleanupRecord::revoke` run. Before P5.3.4 neither death path
    // reclaimed, so this would have read `tasks=N slots=0` on every boot — the
    // table full of dead entries and not one CSlot returned.
    slime_root::diagnostic_println!(
        "SLIME_GRAPH tasks reclaimed live={} slots={reclaimed_slots}",
        tasks.len(),
    );
    let exports = unsafe { &mut *ptr::addr_of_mut!(CAPABILITY_EXPORTS) };
    for slot in &mut exports.entries {
        let Some(export) = slot.take() else { continue };
        if export.finalized {
            exports.imported = exports.imported.saturating_add(1);
            cleanup_export_ticket(allocator, tasks, export);
        } else {
            *slot = Some(export);
        }
    }
    slime_root::diagnostic_println!(
        "SLIME_GRAPH native task_caps={} exports={} tickets={}",
        tasks.len(),
        exports.len(),
        exports.len(),
    );
    slime_root::diagnostic_println!(
        "SLIME_GRAPH capabilities exports={} imports={} cancels={} finalized={} outstanding={} tickets={}",
        exports.exported,
        exports.imported,
        exports.cancelled,
        exports.finalized,
        exports.len(),
        exports.len(),
    );
    slime_root::diagnostic_println!(
        "SLIME_GRAPH loans served={loans_served} loans={} mappings={} regions={} orphans={} quota={}",
        buffers.loan_count(),
        buffers.mapping_count(),
        buffers.live_count(),
        buffers.orphan_count(),
        buffers.quota_count(),
    );
    slime_root::diagnostic_println!(
        "SLIME_GRAPH spawns served={spawns} drops={drops} terminated={}",
        terminations.recorded(),
    );
    slime_root::diagnostic_println!(
        "SLIME_ROOT allocator live_slots={} free_slots={} live_objects={} live_bytes={} mapped_ram={} reusable_ram={} reusable_private_ram={} allocation_descriptors_free={} extent_descriptors_free={} slot_reuses={} extent_reuses={}",
        allocator.live_slots(),
        allocator.free_slots(),
        allocator.live_objects(),
        allocator.live_bytes(),
        tasks.private_memory().total_pages() * child_vspace::GRANULE_SIZE,
        allocator.reusable_extent_bytes(),
        allocator.reusable_private_extent_bytes(),
        allocator.allocation_descriptors_free(),
        allocator.extent_descriptors_free(),
        allocator.slots_reused(),
        allocator.extents_reused(),
    );
    if report_backing && tasks.is_empty() && retirements.is_empty() {
        allocator.report_backing_snapshot("final");
    }
    // The reconciled metadata state belongs before the terminal marker: the
    // plane gates stop reading at it.
    #[cfg(slime_metadata_lifecycle)]
    if tasks.is_empty() && retirements.is_empty() {
        allocator.report_metadata_census("final");
    }
    let completed = completed_required.iter().filter(|done| **done).count();
    if live == 0 && retirements.is_empty() && required != 0 && completed == required {
        slime_root::diagnostic_println!(
            "SLIME_GRAPH HEALTHY generation={} required={} live=0 completed={} failed=0",
            generation.number,
            required,
            completed,
        );
    }
}

/// Bytes one encoded spawn-grant record occupies in the caller's transfer
/// window: a slot word, then a rights word.
///
/// Generated from `contracts/syscall-abi/v1/schema.zt` and shared with
/// `components/runtime`'s encoder. Before B59 this was a second `16` here whose
/// doc comment claimed to match the transport's — a comment was the whole
/// enforcement mechanism for a record layout crossing the syscall boundary.
use slime_proto::syscall_abi::{
    GRANT_RECORD_BYTES as SPAWN_GRANT_RECORD_BYTES, GRANT_RIGHTS_OFFSET, GRANT_SLOT_OFFSET,
};
mod diagnostic_once;
pub(super) mod io_resource;
pub(super) use io_resource::{IoResourceService, install_driver};
use io_resource::{revoke_buffer_lease, serve_io_resource};
// B59: the capability-rights vocabulary is generated from
// `contracts/generation/v5/schema.zt`; these were local copies of the same
// bit numbering.
use boot_contracts::generation::{
    RIGHT_BUFFER_CREATE, RIGHT_BUFFER_MAP, RIGHT_BUFFER_WRITE, RIGHT_SPAWN, RIGHT_SUPERVISE,
};
use boot_contracts::instance_lifetime::Lifetime;

/// `(live, completed)` over the autostart required instances.
fn required_accounting(
    generation: &boot_contracts::generation::Generation<'_>,
    tasks: &TaskTable<MAX_TASKS>,
    completed_required: &[bool],
) -> (usize, usize) {
    let (mut live, mut completed) = (0, 0);
    for index in 0..generation.instance_count() {
        let Ok(instance) = generation.instance(index) else {
            continue;
        };
        if !instance.autostart || instance.health != InstanceHealth::Required {
            continue;
        }
        if completed_required.get(index).copied().unwrap_or(false) {
            completed += 1;
        } else if tasks.tasks().any(|task| task.instance == Some(index)) {
            live += 1;
        }
    }
    (live, completed)
}

/// Grants one spawn call may carry. **B15 is closed here.**
///
/// This is the retired kernel's bound, which it had not been until P5.5.1.
/// `sys_spawn` there reads the grant array straight out of caller memory,
/// limited only by `kernel/src/capability/mod.rs::MAX_CAPS` (64). Here the
/// array crosses the transfer window as a staged payload, and it used to be
/// read by `transfer_window::read_staged` — whose bound is
/// `ipc::MAX_MESSAGE_BYTES`, 64 *bytes*, or four records. Real x86 callers
/// already exceeded that: `init.rs::GENERATION_MANAGER_CAPS` and `dango_caps()`
/// are six grants each, `spawn-service.rs` builds up to five, and
/// `launch_fabric_graph` hands the fabric nine. Every one of them would have
/// been refused `ERR_INVALID_ARG` on the cutover where the oracle succeeds.
///
/// The fix is a second staged bound rather than a wider message:
/// [`transfer_window::MAX_STAGED_ARRAY_BYTES`] bounds an *array* staged through
/// a window, where `MAX_STAGED_BYTES` bounds a *message*. See that constant for
/// why the two must stay separate numbers. The component side needed no change
/// at all — `sel4_transport::spawn` already encoded into a
/// `MAX_SPAWN_GRANTS * GRANT_RECORD_BYTES` buffer and staged it into a
/// 4096-byte window; the refusal was entirely on this side.
/// Serve one adaptive holder's growth against its bound entitlement.
///
/// The guaranteed prefix is whatever the entitlement still promises this
/// incarnation; the remainder is drawn from the pool, and both settle as one
/// ledger transaction. The record is emitted from the root's own state after
/// the attempt — the region is read back rather than predicted — so a refusal
/// reports the holder's unchanged page count rather than the one it asked for.
/// A zero delta is a pure size query: it allocates nothing and is deliberately
/// not recorded as a growth.
fn serve_adaptive_growth(
    generation: &Generation<'_>,
    tasks: &mut TaskTable<MAX_TASKS>,
    allocator: &mut ObjectAllocator,
    policy: &mut super::adaptive::AdaptivePolicy<'_>,
    binding: task::PrivateBinding,
    id: TaskId,
    delta: usize,
) -> Response {
    let instance = tasks
        .get(id)
        .and_then(|task| task.instance)
        .and_then(|index| generation.instance(index).ok())
        .map_or("", |instance| instance.name);
    let previous_pages = tasks.get(id).map_or(0, |task| task.private_memory.pages());
    // What this entitlement still owes the holder, resolved before the
    // attempt: the split decides which lane the pages are mapped in, so it
    // must be the same number the transaction is priced against.
    let redeemable = policy.redeemable(&binding);
    let guaranteed = delta.min(redeemable);
    let outcome = (if delta == 0 {
        Ok(())
    } else {
        policy.reconcile_ownership(allocator)
    })
    .map_err(private_memory::elastic::ElasticGrowError::Policy)
    .and_then(|()| {
        tasks.grow_private_memory_adaptive(allocator, policy.ledger_mut(), id, delta, redeemable)
    });
    let region = tasks
        .get(id)
        .map_or(private_memory::Region::DENIED, |task| task.private_memory);
    if delta > 0 {
        match &outcome {
            Ok(previous) => policy.report_growth(
                id,
                instance,
                &binding,
                delta,
                *previous,
                region.pages(),
                guaranteed,
                region.base(),
                Ok(()),
            ),
            Err(error) => {
                policy.report_growth(
                    id,
                    instance,
                    &binding,
                    delta,
                    previous_pages,
                    region.pages(),
                    0,
                    region.base(),
                    Err(error),
                );
                policy.report_limit(allocator, id, instance, delta, error);
            }
        }
    }
    match outcome {
        // Primary is the page count before the growth, auxiliary the window
        // base, exactly as the fixed path answers.
        Ok(previous) => Response::success(previous as i64, region.base() as sel4::Word),
        Err(_) => Response::error(IpcError::TransferFailed),
    }
}

mod capability;
pub(super) mod policy;
pub(super) mod spawn;

use capability::*;
use policy::*;
use spawn::*;
