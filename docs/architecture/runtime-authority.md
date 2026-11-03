# Time, waiting, scheduling, and lifecycle

These mechanisms share one rule: generation data declares policy and authority;
`slime-root` enforces the small mechanism it owns; userspace decides what the
system should do.

## Clock and timers

`contracts/clock-authority/v2/` independently declares timer-use,
simulated-read, and simulated-advance authority per holder. Omission is denial.
Timer authority includes a live-timer quota and the Notification badge used for
expiry, so timer delivery joins the existing userspace wait path.

Reading the monotonic counter and its rate needs no authority
([decision](../decisions/ambient-clock-reads.md)). On AArch64,
`slime_rt::monotonic_read` and `monotonic_frequency` read `CNTPCT_EL0` and
`CNTFRQ_EL0` in the calling thread, and that counter is the one the root's
timers count. On RISC-V and x86_64 the root's clock is a device register, and
the root answers `CLOCK MONOTONIC READ` and `CLOCK RATE READ` for every task
through the `lifecycle` service. Generation right bit 26 is retired, and the
decoder refuses a v1 table.

`slime-root/src/clock.rs` serves the logical clock operations and
`slime-root/src/platform_timer.rs` owns the platform timer mechanism. The service
grants semantics, not exclusive register access. On current AArch64 profiles the
kernel enables EL0 physical counter and timer registers globally because the root
programs that timer from EL0; hostile native code could disrupt the timer
registers. Closing that wall requires a kernel/platform change, not a contract
claim.

Already-decided one-shot expiries must reach their declared badges even when a
later platform step or IRQ acknowledgement fails; cancellation delivers nothing
and termination reclaims live timers. Timer wakes do not consume the bounded
component-request iteration count, and absent authority remains distinguishable
from malformed requests.

The root prints `SLIME_CLOCK served` once per task and label and `SLIME_CLOCK
refused` once per task, label and class; it prints a payload DMA line and its
frame lines once per direction. Each later occurrence is counted, and one
`SLIME_ROOT diagnostic repeats clock_served=N clock_refused=N io_device_read=N
io_device_write=N` line precedes `SLIME_GRAPH served`. Under QEMU TCG every UART
byte is a trapped write on the one CPU, so a line per operation stalled the whole
graph. The key tables hold 256 entries each; a full table prints the line, so a
key is never hidden (`slime-root/src/graph_runtime/services/diagnostic_once.rs`).

## Console records

The console dispatcher prints each component write as one record, and a root
line can be printed between two records. A component therefore writes each
line in one call. Rust components build a dynamic line in
`slime_rt::console_line::Line` and submit it with `emit`; a fixed line is one
byte literal that ends in a newline. C components write through
`slime_line_write`, which collects bytes until a newline, and call
`slime_line_flush` for a partial line such as a prompt or an echoed key. The C
runtime's `slime_debug_write` sends up to 1024 bytes as one record through the
thread's transfer window, so a C line is no longer split into 16-byte
messages. `scripts/lib/console_lines.py` refuses any other form in tracked
component sources.

A `Line` that overflows its capacity or is not UTF-8 is dropped whole rather
than printed in part. The console relay component therefore no longer forwards
a non-UTF-8 message to the root's refusal path.

## Wait sets

Wait sets are userspace, implemented by `components/runtime/src/wait_set.rs`
over one seL4 Notification plus explicit endpoint drains. The generation's
`contracts/wait-set/v2/` resource maps badge bits to source kind and the waiter's
own drain slot. The root exposes only a self-scoped read of those declared
entries and signals declared timer or supervision badges. Version 2 adds the
`device` kind: a driver's completion signal, sent through a declared peer binding
on the waiter's Notification and, like a timer, naming no drain slot, because the
waiter reads device state it already owns.
The waiter cannot derive this mapping itself: peer badges come from the
signaller's slot, while timer badges are independent contract data. Each badge
belongs to exactly one source; a supervision wake requires the waiter's declared
slot still to hold authority over the terminated task and adds no authority.

Notification badges coalesce, so they mean readiness, not event counts. A waiter
drains every ready source. Simultaneous bits dispatch in ascending badge order;
that tie rule is contract data and makes the same readiness produce the same
sequence across boots. A waiter may register at most nine sources, matching the
widest admitted fabric wait set.
Duplicate or undeclared badges and over-budget dispatch are refused without
poisoning the waiter; an unnamed instance has no sources. Fixed source tables
and badge deduplication bound the ready queue without allocation or a root-owned
wait set, ready queue, or source registry.

## Scheduling class

`contracts/scheduling-class/v1/` declares three assignable classes — foreground,
normal, and best-effort — and maps each to an exact seL4 TCB priority. It may also
declare a spawner-to-child promotion edge with a ceiling. The promotion right
rides on the child's supervision capability; self-promotion and promotion of a
non-owned task are refused.
Promotion above the declared ceiling or to the distinct `undeclared` class is
refused without changing class. Class and explicit thread priorities must agree,
including inherited worker priorities; an unnamed instance retains the root's
child priority rather than being reported as normal.

A class controls ordering only. The pinned kernels use `KernelIsMCS OFF`, so no
CPU time budget or period exists to charge. Generation schedule records must keep
`budget_us` and `period_us` zero; both readers reject nonzero values. Conserved
CPU accounts are not a current capability.
Higher-class progress must not depend on denying a best-effort worker all CPU.

## Lifecycle and supervised restart

`contracts/lifecycle-policy/v1/` declares the admitted transition graph,
per-instance restart causes and attempt bounds, backoff, health dependencies,
and parameter read/write authority. `slime-root/src/lifecycle.rs` and the task/
supervision mechanisms record terminal state, enforce transitions and restart
admission, and reclaim the old task. They do not decide to restart it.

A userspace supervisor holds the supervision capability, waits through the clock
service, chooses whether policy calls for another launch, and spawns a fresh
instance. Attempts survive task identities, backoff is checked against the
monotonic clock rather than a spin count, and exhaustion enters the declared
terminal state. Fresh construction prevents stale capabilities, mappings, and
resource charges from surviving a restart.
Parameter values and the last terminal cause also persist per instance;
task identities are never reused, and a replacement derives its
lifecycle entry state, class, and quota from the generation. The root refuses
first spawn until health dependencies reach their declared states, refuses early
or exhausted restart attempts, and leaves state unchanged on an undeclared
transition.

Parameter read and write are independent holder-to-subject authorities; omission
denies even self-access, and absent authority is distinguishable from an unset
key. Predecessor handles are refused after replacement.

The currently reachable terminal causes are exit, fault, and declared
unhealthiness. Timeout and native-endpoint peer-death are not declared causes
because no current mechanism produces them.
These terminal causes remain distinguishable.

## Declared instance lifetime

`contracts/instance-lifetime/v1/` names the instances a composition declares
`resident`. Every other instance is `bounded`. The component spec carries the
default, and a placement or instance record overrides it, as `health` does. The
root treats a resident instance's exit as a failure, never as completion:

- A resident required instance that exits, with any status, ends the graph.
- A resident optional instance that exits is recorded as unhealthy, which is
  the outcome its supervisor reads.
- A resident instance never counts as completed, so a graph holding a live
  resident required instance certifies with it counted live.

A component reads its own lifetime through `LIFECYCLE LIFETIME READ`
(`slime_rt::lifetime()`). No operation stops a resident instance on purpose,
so a composition that shuts an instance down declares it bounded. The rationale
is in [the decision record](../decisions/instance-lifetime.md).

## Graph arrival ceiling

The root's graph service loop counts component arrivals. In a finite plane it
stops after 131072 of them, as a livelock watchdog. A product generation has no
ceiling, because its resident graph keeps producing arrivals for its whole life.

A finite plane that needs a longer run declares `graphArrivalCeiling` in its
system spec. The builder carries it as the `contracts/graph-arrival-ceiling/v1`
resource object, and only when it is declared:

- A declared ceiling is above 131072 and at most 2^30 arrivals.
- Admission refuses a malformed ceiling, a second ceiling, and a ceiling on a
  product generation.
- The root serves the declared count and prints `SLIME_GRAPH
  arrival-ceiling=N` before it serves. A generation that declares no ceiling
  prints nothing new and keeps 131072.

## Recording and determinism

`contracts/recording-policy/v1/` binds declared record/replay participants to one
bounded stream. Admission joins that policy with the generation's complete
rights classification. A deterministic participant cannot hold an unrecorded
input authority except for the exact declared grant carrying its recording.
The same restriction applies to imported authority at runtime, not only launch
admission; missing or unbound recording grants and unnecessary recorder
exemptions are refused, and rights joins include executable grants.

Clock reads, timer expiries, lifecycle transitions, outputs, and fabric traffic
share one typed trace order; every right has an explicit determinism
classification. The bounded, allocation-free replay stream is validated whole
before exposing input, refusing truncation, reordering, excess capacity, and
arbitrary terminal-flagged resource records as stream openers.

Replay compares typed outputs, recorded reads, lifecycle transitions, and timer
identities field by field; hardware instants are recorded, range-checked inputs,
not cross-boot output-equality requirements. A refused step leaves its cursor
unchanged, and replay never falls back to live clock access.

Determinism is therefore a composition claim under declared inputs and limits.
It is not a scheduler guarantee and does not imply CPU quantity isolation.

## Robot runtime outcomes

The `sel4-robot-runtime` plane produces each call outcome through one
designated request, so no outcome depends on scheduling. The actuator refuses a
command above its declared range, never answers the command `4242`, whose
deadline the broker then expires, and holds the command `4243` without
applying or answering it. The controller withdraws that held request right
behind it, so the broker always forwards the cancellation and the actuator
settles it. An actuator that answered the request on receipt would race the
reply against the cancellation, and the broker would settle the withdrawal
itself whenever the reply won.

## Proposed MCS decision

[`../decisions/mcs-cpu-budgets.md`](../decisions/mcs-cpu-budgets.md) retains the
MCS choice as **proposed**. Current operation remains non-MCS. Enabling MCS is not
a configuration flip: it changes reply handling, adds Reply and scheduling-
context objects, needs per-thread reservation/account ownership and aggregate
admission, and has target-specific assurance consequences.

## Verification

- `just clock_authority_check`
- `just wait_set_check`
- `just scheduling_class_check`
- `just lifecycle_restart_check`
- `just robot_runtime_check`
- `just robot_withdrawn_check`
- `just sel4_gate_control_check` for missing/reordered/failure controls
- `just console_lines_check`
