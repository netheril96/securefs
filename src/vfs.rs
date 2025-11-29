use std::sync::Arc;

use parking_lot::Mutex;

pub trait GenericHandle {
    fn get_lookup_count(&self) -> u64;
    fn increment_lookup_count(&self) -> u64;
    fn decrement_lookup_count(&self) -> u64;

    fn is_dir(&self) -> bool;
    fn is_regular_file(&self) -> bool;
    fn is_symlink(&self) -> bool;
}

pub trait GenericTable<H: GenericHandle> {
    fn lookup(&self, number: u64) -> Option<Arc<H>>;
    fn lookup_or_init(&self, number: u64) -> Arc<H>;
    fn notify_no_more_reference(&self, number: u64);
    fn cleanup(&self);
}

pub struct INodeTable<INode: GenericHandle + Default> {
    root_ino: u64,
    root: Arc<INode>,
    seed: u64,
    shards: Vec<Mutex<lru::LruCache<u64, Arc<INode>>>>,
}

impl<INode: GenericHandle + Default> INodeTable<INode> {
    pub fn new(root_ino: u64, seed: u64, num_shards: usize, root: Arc<INode>) -> Self {
        let mut v = Self {
            root_ino,
            seed,
            shards: Vec::with_capacity(num_shards),
            root,
        };
        for _ in 0..num_shards {
            v.shards.push(lru::LruCache::unbounded().into());
        }
        v
    }

    fn get_shard(&self, number: u64) -> &Mutex<lru::LruCache<u64, Arc<INode>>> {
        &self.shards[((number ^ self.seed) % self.shards.len() as u64) as usize]
    }
}

impl<INode: GenericHandle + Default> GenericTable<INode> for INodeTable<INode> {
    fn lookup(&self, number: u64) -> Option<Arc<INode>> {
        if number == self.root_ino {
            self.root.clone().into()
        } else {
            self.get_shard(number).lock().get(&number).cloned()
        }
    }

    fn lookup_or_init(&self, number: u64) -> Arc<INode> {
        if number == self.root_ino {
            self.root.clone()
        } else {
            self.get_shard(number)
                .lock()
                .get_or_insert(number, Default::default)
                .clone()
        }
    }

    fn notify_no_more_reference(&self, number: u64) {
        if number == self.root_ino {
            return;
        }
        self.get_shard(number).lock().demote(&number);
    }

    fn cleanup(&self) {
        for shard in &self.shards {
            if let Some(mut shard) = shard.try_lock() {
                for _ in 0..100 {
                    if let Some((k, v)) = shard.peek_lru().map(|(k, v)| (*k, v.clone())) {
                        if v.get_lookup_count() == 0 {
                            shard.pop_lru();
                            break;
                        } else {
                            shard.promote(&k);
                        }
                    }
                }
            }
        }
    }
}
