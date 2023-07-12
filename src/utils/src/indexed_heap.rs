#[derive(Eq, PartialEq, Hash, Clone, Copy)]
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

impl<T, P: Ord> IndexedBinaryHeap<T, P> {
    pub fn new() -> Self {
        Self {
            generation: 1,
            free_list_head: usize::MAX,
            data: Vec::new(),
            map: Vec::new(),
        }
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            generation: 1,
            free_list_head: usize::MAX,
            data: Vec::with_capacity(capacity),
            map: Vec::with_capacity(capacity),
        }
    }
    pub fn peek(&self) -> Option<(&T, &P, BinaryHeapIndex)> {
        self.data
            .first()
            .map(|entry| (&entry.0, &entry.1, BinaryHeapIndex(entry.2, self.map[entry.2].1)))
    }
    pub fn peek_mut(&mut self) -> Option<(&mut T, &P, BinaryHeapIndex)> {
        self.data
            .first_mut()
            .map(|entry| (&mut entry.0, &entry.1, BinaryHeapIndex(entry.2, self.map[entry.2].1)))
    }
    #[inline]
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
                let largest_child = if child1_idx < self.data.len() && self.data[child1_idx].1 > self.data[child0_idx].1 {
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
    pub fn pop(&mut self) -> Option<(T, P)> {
        (self.data.len() > 0).then(|| self.remove_idx(0))
    }
    /// Add an item to the queue and get back a generational index which allows for quick updating
    /// of this item and its priority.
    pub fn push(&mut self, item: T, priority: P) -> BinaryHeapIndex {
        let idx = self.reserve_index();
        self.push_reserved(idx, item, priority);
        idx
    }
    /// Reserve a generational index. It will not have an associated item until
    /// `push_reserved` is called.
    /// If the index is dropped without having been associated with a queue item it will be leaked,
    /// causing the queue to consume a few bytes more of memory than it should.
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
    pub fn change_item(&mut self, idx: BinaryHeapIndex, new_item: T) -> Option<T> {
        self.deref_index(idx)
            .map(|data_idx| std::mem::replace(&mut self.data[data_idx].0, new_item))
    }
    pub fn get(&self, idx: BinaryHeapIndex) -> Option<(&T, &P)> {
        self.deref_index(idx).map(|data_idx| (&self.data[data_idx].0, &self.data[data_idx].1))
    }
    pub fn get_mut(&mut self, idx: BinaryHeapIndex) -> Option<(&mut T, &P)> {
        self.deref_index(idx).map(|data_idx| {
            let entry = &mut self.data[data_idx];
            (&mut entry.0, &entry.1)
        })
    }
    /// Remove this index and its associated item from the queue, returning the item if it exists.
    /// This can also be used to remove reserved indices from the queue.
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
