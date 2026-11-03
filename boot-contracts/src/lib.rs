#![no_std]

// `gpt` is the one module needing a heap: a GPT entry table is device-sized and
// read into a `Vec`. Both it and `alloc` are behind the `gpt` feature, because
// components link this crate with **no allocator at all** — declaring
// `extern crate alloc` unconditionally fails every component binary with "no
// global memory allocator found". Callers that want GPT validation opt in and
// bring their own allocator.
#[cfg(feature = "gpt")]
extern crate alloc;

pub mod block_authority;
pub mod boot_layout;
pub mod bootstate;
pub mod clock_authority;
pub mod component_image;
pub mod component_runtime_abi;
pub mod crc32;
pub mod entropy_authority;
pub mod fabric_graph;
pub mod generation;
#[cfg(feature = "gpt")]
pub mod gpt;
pub mod graph_arrival_ceiling;
pub mod instance_lifetime;
pub mod io_resource;
pub mod kernel_image;
pub mod lifecycle_policy;
pub mod network_application;
pub mod network_destination;
pub mod network_interface;
pub mod normalized_interface_schemas;
#[cfg(feature = "gpt")]
pub mod object_store;
pub mod private_memory_budget;
pub mod private_memory_policy;
pub mod recording_policy;
pub mod recovery;
pub mod release;
pub mod scheduling_class;
pub mod sha256;
pub mod shared_buffer_budget;
pub mod store_disk;
pub mod stream_history;
pub mod target_profile;
pub mod trace;
pub mod transfer;
pub mod wait_set;
