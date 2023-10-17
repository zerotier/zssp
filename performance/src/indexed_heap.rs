/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

/// A generational index into an `IndexedBinaryHeap`.
/// Used to perform direct interactions with specific items contained within the binary heap.
/// It will remain valid for as long as its associated item remains in the heap.
///
/// When it becomes invalid, functions which take one of these as input will safely return `None`.
///
/// This index must only be used with the `IndexedBinaryHeap` that it originates from.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct BinaryHeapIndex(usize, u64);

const RESERVED_MARKER: u64 = 1;
const EMPTY_MARKER: u64 = 0;

/// A simple Priority Queue built from a binary heap and a generational array.
/// Entries in the queue are accessed and updated by their generational index.
/// This allows for extremely simple memory management and fast queue updates.
pub struct IndexedBinaryHeap<T, P> {
    generation: u64,
    free_list_head: usize,
    data: Vec<(T, P, usize)>,
    map: Vec<(usize, u64)>,
}

#[allow(unused)]
impl<T, P: Ord> IndexedBinaryHeap<T, P> {
    /// Create a new, empty binary heap.
    pub fn new() -> Self {
        Self {
            generation: 1,
            free_list_head: usize::MAX,
            data: Vec::new(),
            map: Vec::new(),
        }
    }
    /// Create a new binary heap with the specified capacity.
    /// This reduces memory usage if you know ahead of time how
    /// many items will be pushed onto the binary heap.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            generation: 1,
            free_list_head: usize::MAX,
            data: Vec::with_capacity(capacity),
            map: Vec::with_capacity(capacity),
        }
    }
    /// Returns a reference the the highest priority item currently held within the heap,
    /// or `None` if the heap is empty.
    /// Also returns a reference to that item's priority, and that item's index in the heap.
    ///
    /// Amortized runtime: O(1).
    pub fn peek(&self) -> Option<(&T, &P, BinaryHeapIndex)> {
        self.data
            .first()
            .map(|entry| (&entry.0, &entry.1, BinaryHeapIndex(entry.2, self.map[entry.2].1)))
    }
    /// Returns a mutable reference the the highest priority item currently held within the heap,
    /// or `None` if the heap is empty.
    /// Also returns a reference to that item's priority, and that item's index in the heap.
    ///
    /// Amortized runtime: O(1).
    pub fn peek_mut(&mut self) -> Option<(&mut T, &P, BinaryHeapIndex)> {
        self.data
            .first_mut()
            .map(|entry| (&mut entry.0, &entry.1, BinaryHeapIndex(entry.2, self.map[entry.2].1)))
    }
    fn swap(&mut self, a: usize, b: usize) {
        self.map[self.data[a].2].0 = b;
        self.map[self.data[b].2].0 = a;
        self.data.swap(a, b);
    }
    fn bubble_down(&mut self, mut parent_idx: usize) {
        loop {
            let child0_idx = parent_idx * 2 + 1;
            let child1_idx = child0_idx + 1;
            if child0_idx < self.data.len() {
                let largest_child = if child1_idx < self.data.len() && self.data[child1_idx].1 > self.data[child0_idx].1
                {
                    child1_idx
                } else {
                    child0_idx
                };
                if self.data[largest_child].1 > self.data[parent_idx].1 {
                    self.swap(parent_idx, largest_child);
                    parent_idx = largest_child;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
    fn bubble_up(&mut self, mut child_idx: usize) {
        while child_idx > 0 {
            let parent_idx = (child_idx - 1) / 2;
            if self.data[child_idx].1 > self.data[parent_idx].1 {
                self.swap(parent_idx, child_idx);
                child_idx = parent_idx;
            } else {
                break;
            }
        }
    }
    fn remove_idx(&mut self, data_idx: usize) -> (T, P) {
        self.swap(data_idx, self.data.len() - 1);
        let ret = self.data.pop().unwrap();
        self.map[ret.2] = (self.free_list_head, EMPTY_MARKER);
        self.free_list_head = ret.2;

        self.bubble_down(data_idx);

        (ret.0, ret.1)
    }
    fn deref_index(&self, idx: BinaryHeapIndex) -> Option<usize> {
        (idx.0 < self.map.len() && self.map[idx.0].1 == idx.1).then(|| self.map[idx.0].0)
    }
    /// Pop off the current top item of the binary heap, removing it from the heap.
    /// Returns the item and its priority.
    ///
    /// Amortized runtime: O(log(n)).
    pub fn pop(&mut self) -> Option<(T, P)> {
        (!self.data.is_empty()).then(|| self.remove_idx(0))
    }
    /// Add an item to the queue with the specified priority.
    /// Returns the index at which this item was stored.
    /// It can be used to update this item and its priority in the future.
    ///
    /// Amortized runtime: O(log(n)).
    pub fn push(&mut self, item: T, priority: P) -> BinaryHeapIndex {
        let idx = self.reserve_index();
        self.push_reserved(idx, item, priority);
        idx
    }
    /// Reserve a generational index into the heap.
    /// This index will be empty and not have an associated item until `push_reserved` is called.
    ///
    /// This is useful in situations where you want to create a double link. Similar to `Arc::new_cyclic`,
    /// except without the need for a closure since a `BinaryHeapIndex` is safe to handle uninitialized.
    ///
    /// If the index is dropped without having been associated with a queue item, it will be leaked,
    /// causing the queue to consume a few bytes more of memory than it should.
    ///
    /// Amortized runtime: O(1).
    pub fn reserve_index(&mut self) -> BinaryHeapIndex {
        self.generation += 1;
        if self.free_list_head != usize::MAX {
            let pre_head = self.free_list_head;
            self.free_list_head = self.map[pre_head].0;
            self.map[pre_head] = (0, RESERVED_MARKER);
            BinaryHeapIndex(pre_head, self.generation)
        } else {
            self.map.push((0, RESERVED_MARKER));
            BinaryHeapIndex(self.map.len() - 1, self.generation)
        }
    }
    /// Add an item to the queue with the specific reserved index.
    /// If this index already has an associated item this will return false.
    ///
    /// Use `reserve_index` to create a reserved index.
    ///
    /// Amortized runtime: O(log(n)).
    pub fn push_reserved(&mut self, idx: BinaryHeapIndex, item: T, priority: P) -> bool {
        if idx.0 < self.map.len() && self.map[idx.0].1 == RESERVED_MARKER {
            let data_idx = self.data.len();
            self.map[idx.0] = (data_idx, idx.1);

            self.data.push((item, priority, idx.0));
            self.bubble_up(data_idx);
            true
        } else {
            false
        }
    }
    /// Change the priority of the item stored at the given index of the binary heap.
    /// Returns the item's previous priority, or `None` if the item does not exist in the heap.
    ///
    /// Amortized runtime: O(log(n)).
    pub fn change_priority(&mut self, idx: BinaryHeapIndex, new_priority: P) -> Option<P> {
        self.deref_index(idx).map(|data_idx| {
            let c = if self.data[data_idx].1 < new_priority {
                1
            } else if self.data[data_idx].1 > new_priority {
                2
            } else {
                3
            };
            let old_priority = std::mem::replace(&mut self.data[data_idx].1, new_priority);
            if c == 1 {
                self.bubble_up(data_idx);
            } else if c == 2 {
                self.bubble_down(data_idx);
            }
            old_priority
        })
    }
    /// Change the item stored at the given index of the binary heap.
    /// Returns previously stored item, or `None` if it does not exist in the heap.
    ///
    /// Amortized runtime: O(1).
    pub fn change_item(&mut self, idx: BinaryHeapIndex, new_item: T) -> Option<T> {
        self.deref_index(idx)
            .map(|data_idx| std::mem::replace(&mut self.data[data_idx].0, new_item))
    }
    /// If the given index maps to an item in the heap, this function will return a reference
    /// to that item and its priority.
    ///
    /// Amortized runtime: O(1).
    pub fn get(&self, idx: BinaryHeapIndex) -> Option<(&T, &P)> {
        self.deref_index(idx)
            .map(|data_idx| (&self.data[data_idx].0, &self.data[data_idx].1))
    }
    /// If the given index maps to an item in the heap, this function will return a mutable reference
    /// to that item and an immutable reference to its priority.
    ///
    /// Amortized runtime: O(1).
    pub fn get_mut(&mut self, idx: BinaryHeapIndex) -> Option<(&mut T, &P)> {
        self.deref_index(idx).map(|data_idx| {
            let entry = &mut self.data[data_idx];
            (&mut entry.0, &entry.1)
        })
    }
    /// Remove this index and its associated item from the queue, returning the item if it exists.
    /// This can also be used to remove reserved indices from the queue.
    ///
    /// Amortized runtime: O(log(n)).
    pub fn remove(&mut self, idx: BinaryHeapIndex) -> Option<(T, P)> {
        if idx.0 < self.map.len() {
            if self.map[idx.0].1 == RESERVED_MARKER {
                self.map[idx.0] = (self.free_list_head, EMPTY_MARKER);
                self.free_list_head = idx.0;
                None
            } else if self.map[idx.0].1 == idx.1 {
                Some(self.remove_idx(self.map[idx.0].0))
            } else {
                None
            }
        } else {
            None
        }
    }
    /// Completely empty the binary heap of all items.
    ///
    /// This has no effect on the allocated capacity of the heap.
    pub fn clear(&mut self) {
        self.free_list_head = usize::MAX;
        self.map.clear();
        self.data.clear();
    }
}

#[test]
fn test() {
    let mut queue = IndexedBinaryHeap::new();
    let r0 = queue.push(1234, 1234);
    for i in 0..100 {
        queue.push(2 * i, 2 * i);
    }
    let r1 = queue.push(1234, 12);
    assert_eq!(queue.remove(r0), Some((1234, 1234)));
    for i in (0..100).rev() {
        queue.push(2 * i + 1, 2 * i + 1);
    }
    assert_eq!(queue.change_priority(r1, 1234), Some(12));
    assert_eq!(queue.remove(r0), None);
    let mut last = usize::MAX;
    while let Some((i, j)) = queue.pop() {
        assert_eq!(i, j);
        assert!(i <= last);
        last = i;
    }
}
