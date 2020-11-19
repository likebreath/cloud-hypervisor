// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]
mod rand_crosvm;

use libfuzzer_sys::fuzz_target;
use rand::{Rng, RngCore};
use rand_crosvm::FuzzRng;
use std::mem::size_of;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vm_virtio::{DescriptorChain, Queue};

const MAX_QUEUE_SIZE: u16 = 256;
const MEM_SIZE: u64 = 1024 * 1024;

thread_local! {
    static GUEST_MEM: GuestMemoryMmap = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap();
}

// These are taken from the virtio spec and can be used as a reference for the size calculations in
// the fuzzer.
#[repr(C, packed)]
struct virtq_desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
struct virtq_avail {
    flags: u16,
    idx: u16,
    ring: [u16; MAX_QUEUE_SIZE as usize],
    used_event: u16,
}

#[repr(C, packed)]
struct virtq_used_elem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
struct virtq_used {
    flags: u16,
    idx: u16,
    ring: [virtq_used_elem; MAX_QUEUE_SIZE as usize],
    avail_event: u16,
}

fuzz_target!(|data: &[u8]| {
    let mut q = Queue::new(MAX_QUEUE_SIZE);
    let mut rng = FuzzRng::new(data);
    q.size = rng.gen();
    q.ready = true;

    // For each of {desc_table,avail_ring,used_ring} generate a random address that includes enough
    // space to hold the relevant struct with the largest possible queue size.
    let max_table_size = MAX_QUEUE_SIZE as u64 * size_of::<virtq_desc>() as u64;
    q.desc_table = GuestAddress(rng.gen_range(0, MEM_SIZE - max_table_size));
    q.avail_ring = GuestAddress(rng.gen_range(0, MEM_SIZE - size_of::<virtq_avail>() as u64));
    q.used_ring = GuestAddress(rng.gen_range(0, MEM_SIZE - size_of::<virtq_used>() as u64));

    GUEST_MEM.with(|mem| {
        if !q.is_valid(mem) {
            return;
        }

        // First zero out all of the memory.
        let buf: [u8; MEM_SIZE as usize] = [0; MEM_SIZE as usize];
        mem.write_slice(&buf[..], GuestAddress(0)).unwrap();

        // Fill in the descriptor table.
        let queue_size = q.size as usize;
        let mut buf = vec![0u8; queue_size * size_of::<virtq_desc>()];

        rng.fill_bytes(&mut buf[..]);
        mem.write_slice(&buf[..], q.desc_table).unwrap();

        // Fill in the available ring. See the definition of virtq_avail above for the source of
        // these numbers.
        let avail_size = 4 + (queue_size * 2) + 2;
        buf.resize(avail_size, 0);
        rng.fill_bytes(&mut buf[..]);
        mem.write_slice(&buf[..], q.avail_ring).unwrap();

        // Fill in the used ring. See the definition of virtq_used above for the source of
        // these numbers.
        let used_size = 4 + (queue_size * size_of::<virtq_used_elem>()) + 2;
        buf.resize(used_size, 0);
        rng.fill_bytes(&mut buf[..]);
        mem.write_slice(&buf[..], q.used_ring).unwrap();

        let mut used_desc_heads = [(0, 0); MAX_QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in q.iter(&mem) {
            let idx = avail_desc.index;
            let total = avail_desc
                .into_iter()
                .filter(DescriptorChain::is_write_only)
                .try_fold(0u32, |sum, cur| sum.checked_add(cur.len));
            if let Some(len) = total {
                used_desc_heads[used_count] = (idx, len);
            } else {
                used_desc_heads[used_count] = (idx, 0);
            }
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            q.add_used(&mem, desc_index, len);
        }
    });
});
