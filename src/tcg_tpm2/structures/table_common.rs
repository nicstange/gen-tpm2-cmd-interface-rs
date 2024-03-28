// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// Info common to all TCG TPM2 Part2 "Structures" tables
use super::deps::{ConfigDeps, ConfigDepsDisjunction};
use super::string_transformer::StringTransformer;
use bitflags::bitflags;
use std::borrow;
use std::cmp;

#[derive(Clone, Debug)]
pub struct CommonStructuresTableInfo {
    pub deps: ConfigDeps,
}

impl CommonStructuresTableInfo {
    pub(in super::super) fn new() -> Self {
        Self {
            deps: ConfigDeps::new(),
        }
    }

    pub(super) fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let deps = self.deps.transform_strings(repl);
        Self { deps }
    }
}

bitflags! {
    pub struct ClosureDepsFlags: u32 {
        const PUBLIC_DEFINITION = 0x01;
        const PRIVATE_DEFINITION = 0x02;
        const ANY_DEFINITION = Self::PUBLIC_DEFINITION.bits | Self::PRIVATE_DEFINITION.bits;

        const EXTERN_UNMARSHAL = 0x04;
        const INTERN_UNMARSHAL = 0x08;
        const ANY_UNMARSHAL = Self::EXTERN_UNMARSHAL.bits | Self::INTERN_UNMARSHAL.bits;

        const EXTERN_MARSHAL = 0x10;
        const INTERN_MARSHAL = 0x20;
        const ANY_MARSHAL = Self::EXTERN_MARSHAL.bits | Self::INTERN_MARSHAL.bits;

        const ANY_UNMARSHAL_OR_MARSHAL = Self::ANY_UNMARSHAL.bits | Self::ANY_MARSHAL.bits;

        const EXTERN_TRY_CLONE = 0x40;
        const INTERN_TRY_CLONE = 0x80;
        const ANY_TRY_CLONE = Self::EXTERN_TRY_CLONE.bits | Self::INTERN_TRY_CLONE.bits;

        const EXTERN_INTO_BUFS_OWNER = 0x100;
        const INTERN_INTO_BUFS_OWNER = 0x200;
        const ANY_INTO_BUFS_OWNER = Self::EXTERN_INTO_BUFS_OWNER.bits | Self::INTERN_INTO_BUFS_OWNER.bits;

        const EXTERN_SIZE = 0x400;
        const INTERN_SIZE = 0x800;
        const ANY_SIZE = Self::EXTERN_SIZE.bits | Self::INTERN_SIZE.bits;

        const EXTERN_MAX_SIZE = 0x1000;
        const INTERN_MAX_SIZE = 0x2000;
        const ANY_MAX_SIZE = Self::EXTERN_MAX_SIZE.bits | Self::INTERN_MAX_SIZE.bits;
    }
}

#[derive(Clone, Debug)]
struct ClosureDepEntry {
    config: ConfigDeps,
    closure_deps: ClosureDepsFlags,
}

impl ClosureDepEntry {
    fn new(config: borrow::Cow<ConfigDeps>, closure_deps: ClosureDepsFlags) -> Self {
        Self {
            config: config.into_owned(),
            closure_deps,
        }
    }
}

// A mapping from configurations (in the form of ConfigDeps) to dependencies
// from the resp. closure. The representation is normalized in that closure
// dependencies are recorded at the more generic ConfigDeps, if possible.  That
// is, if both a more and a less generic ConfigDeps (as defined by partial_cmp
// returning Ordering::Less) need some closure dependency, it is only recorded
// at the more generic one, because the latter implies the former anyway.
#[derive(Clone, Debug)]
pub struct ClosureDeps {
    deps: Vec<ClosureDepEntry>,
}

impl ClosureDeps {
    pub fn empty() -> Self {
        Self { deps: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }

    fn index_by_config_len(&self, config_len: usize) -> usize {
        // The deps are sorted by their configs' length (number of config
        // dependencies in the conjunction). This way, potentially more
        // restrictive ones (potentially comparing as Ordering::Less) will come
        // later in the series.
        self.deps.partition_point(|e| e.config.len() < config_len)
    }

    pub fn insert(
        &mut self,
        config: borrow::Cow<ConfigDeps>,
        closure_deps: ClosureDepsFlags,
    ) -> bool {
        let step0_result = self.insert_step0(&config, closure_deps);
        self.insert_step1(config, step0_result)
    }

    fn prune_implied_flags(
        mut flags: ClosureDepsFlags,
        existing: ClosureDepsFlags,
    ) -> ClosureDepsFlags {
        flags.remove(existing);

        // If more generic flags are already present, prune the less generic ones.
        if existing.intersects(ClosureDepsFlags::PUBLIC_DEFINITION) {
            flags.remove(ClosureDepsFlags::PRIVATE_DEFINITION);
        }
        if existing.intersects(ClosureDepsFlags::EXTERN_UNMARSHAL) {
            flags.remove(ClosureDepsFlags::INTERN_UNMARSHAL);
        }
        if existing.intersects(ClosureDepsFlags::EXTERN_MARSHAL) {
            flags.remove(ClosureDepsFlags::INTERN_MARSHAL);
        }
        if existing.intersects(ClosureDepsFlags::EXTERN_TRY_CLONE) {
            flags.remove(ClosureDepsFlags::INTERN_TRY_CLONE);
        }
        if existing.intersects(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER) {
            flags.remove(ClosureDepsFlags::INTERN_INTO_BUFS_OWNER);
        }
        if existing.intersects(ClosureDepsFlags::EXTERN_SIZE) {
            flags.remove(ClosureDepsFlags::INTERN_SIZE);
        }
        if existing.intersects(ClosureDepsFlags::EXTERN_MAX_SIZE) {
            flags.remove(ClosureDepsFlags::INTERN_MAX_SIZE);
        }

        flags
    }

    fn check_clear_flags(clear: ClosureDepsFlags, set: ClosureDepsFlags) {
        // See prune_implied_flags(): the replacement of less generic by more
        // generic counterparts cannot be undone. All is fine if
        // the less generic flag is being explictly (re)enabled anyway.
        if clear.intersects(ClosureDepsFlags::PUBLIC_DEFINITION)
            && !set.intersects(ClosureDepsFlags::PRIVATE_DEFINITION)
        {
            assert!(clear.intersects(ClosureDepsFlags::PRIVATE_DEFINITION));
        }
        if clear.intersects(ClosureDepsFlags::EXTERN_UNMARSHAL)
            && !set.intersects(ClosureDepsFlags::INTERN_UNMARSHAL)
        {
            assert!(clear.intersects(ClosureDepsFlags::INTERN_UNMARSHAL));
        }
        if clear.intersects(ClosureDepsFlags::EXTERN_MARSHAL)
            && !set.intersects(ClosureDepsFlags::INTERN_MARSHAL)
        {
            assert!(clear.intersects(ClosureDepsFlags::INTERN_MARSHAL));
        }
        if clear.intersects(ClosureDepsFlags::EXTERN_TRY_CLONE)
            && !set.intersects(ClosureDepsFlags::INTERN_TRY_CLONE)
        {
            assert!(clear.intersects(ClosureDepsFlags::INTERN_TRY_CLONE));
        }
        if clear.intersects(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER)
            && !set.intersects(ClosureDepsFlags::INTERN_INTO_BUFS_OWNER)
        {
            assert!(clear.intersects(ClosureDepsFlags::INTERN_INTO_BUFS_OWNER));
        }
        if clear.intersects(ClosureDepsFlags::EXTERN_SIZE)
            && !set.intersects(ClosureDepsFlags::INTERN_SIZE)
        {
            assert!(clear.intersects(ClosureDepsFlags::INTERN_SIZE));
        }
        if clear.intersects(ClosureDepsFlags::EXTERN_MAX_SIZE)
            && !set.intersects(ClosureDepsFlags::INTERN_MAX_SIZE)
        {
            assert!(clear.intersects(ClosureDepsFlags::INTERN_MAX_SIZE));
        }
    }

    // Insertion is divided into one non-mutating step and a subsequent mutating
    // step, enabling COW behavior inbetween if needed.
    fn insert_step0(
        &self,
        config: &ConfigDeps,
        mut closure_deps: ClosureDepsFlags,
    ) -> (ClosureDepsFlags, usize, Option<usize>) {
        // First remove all flags which are already set in any of the existing,
        // more generic entries.
        let i = self.index_by_config_len(config.len() + 1);
        let mut i_config_match = None;
        let mut j = i;
        while !closure_deps.is_empty() && j > 0 {
            j -= 1;
            let existing = &self.deps[j];
            let cmp = (*config).partial_cmp(&existing.config);
            match cmp {
                Some(cmp::Ordering::Less) => (),
                Some(cmp::Ordering::Equal) => i_config_match = Some(j),
                Some(cmp::Ordering::Greater) | None => continue,
            };

            // config is more restrictive, i.e. config implies existing.config.
            // Strip of the closure_deps flags already present in existing.
            closure_deps = Self::prune_implied_flags(closure_deps, existing.closure_deps);
        }

        (closure_deps, i, i_config_match)
    }

    fn insert_step1(
        &mut self,
        config: borrow::Cow<ConfigDeps>,
        step0_result: (ClosureDepsFlags, usize, Option<usize>),
    ) -> bool {
        let (closure_deps, i, i_config_match) = step0_result;

        if closure_deps.is_empty() {
            return false;
        }

        // Conversely, in analogy to the filtering of the provided closure_deps
        // flags in step0, clear the remaining, to be inserted flags from all
        // existing, less generic config entries.
        let mut j = i;
        while j < self.deps.len() {
            let existing = &mut self.deps[j];
            if existing.config < *config {
                existing.closure_deps =
                    Self::prune_implied_flags(existing.closure_deps, closure_deps);
                if existing.closure_deps.is_empty() {
                    self.deps.remove(j);
                    continue;
                }
            }
            j += 1;
        }

        if let Some(i_config_match) = i_config_match {
            let existing = &mut self.deps[i_config_match];
            existing.closure_deps = Self::prune_implied_flags(existing.closure_deps, closure_deps);
            existing.closure_deps.insert(closure_deps);
        } else {
            self.deps
                .insert(i, ClosureDepEntry::new(config, closure_deps));
        }

        true
    }

    // Propagate closure dependencies on a container type to some of its members.
    pub fn propagate_from(&mut self, container_deps: borrow::Cow<Self>) -> bool {
        fn massage_closure_deps_flags(flags: &mut ClosureDepsFlags) {
            if flags.intersects(ClosureDepsFlags::EXTERN_UNMARSHAL) {
                flags.remove(ClosureDepsFlags::EXTERN_UNMARSHAL);
                flags.insert(ClosureDepsFlags::INTERN_UNMARSHAL);
            }

            if flags.intersects(ClosureDepsFlags::EXTERN_MARSHAL) {
                flags.remove(ClosureDepsFlags::EXTERN_MARSHAL);
                flags.insert(ClosureDepsFlags::INTERN_MARSHAL);
            }

            if flags.intersects(ClosureDepsFlags::EXTERN_TRY_CLONE) {
                flags.remove(ClosureDepsFlags::EXTERN_TRY_CLONE);
                flags.insert(ClosureDepsFlags::INTERN_TRY_CLONE);
            }

            if flags.intersects(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER) {
                flags.remove(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER);
                flags.insert(ClosureDepsFlags::INTERN_INTO_BUFS_OWNER);
            }

            if flags.intersects(ClosureDepsFlags::EXTERN_SIZE) {
                flags.remove(ClosureDepsFlags::EXTERN_SIZE);
                flags.insert(ClosureDepsFlags::INTERN_SIZE);
            }

            if flags.intersects(ClosureDepsFlags::EXTERN_MAX_SIZE) {
                flags.remove(ClosureDepsFlags::EXTERN_MAX_SIZE);
                flags.insert(ClosureDepsFlags::INTERN_MAX_SIZE);
            }
        }
        let mut updated = false;
        match container_deps {
            borrow::Cow::Borrowed(container_deps) => {
                for dep in container_deps.deps.iter() {
                    let mut closure_deps = dep.closure_deps;
                    massage_closure_deps_flags(&mut closure_deps);
                    updated |= self.insert(borrow::Cow::Borrowed(&dep.config), closure_deps);
                }
            }
            borrow::Cow::Owned(mut container_deps) => {
                for dep in container_deps.deps.drain(..) {
                    let mut closure_deps = dep.closure_deps;
                    massage_closure_deps_flags(&mut closure_deps);
                    updated |= self.insert(borrow::Cow::Owned(dep.config), closure_deps);
                }
            }
        };
        updated
    }

    pub fn merge_from(&mut self, container_deps: borrow::Cow<Self>) -> bool {
        let mut updated = false;
        match container_deps {
            borrow::Cow::Borrowed(container_deps) => {
                for dep in container_deps.deps.iter() {
                    updated |= self.insert(borrow::Cow::Borrowed(&dep.config), dep.closure_deps);
                }
            }
            borrow::Cow::Owned(mut container_deps) => {
                for dep in container_deps.deps.drain(..) {
                    updated |= self.insert(borrow::Cow::Owned(dep.config), dep.closure_deps);
                }
            }
        };
        updated
    }

    pub fn union<'a>(&'a self, other: &'a Self) -> borrow::Cow<'a, Self> {
        let mut deps = borrow::Cow::Borrowed(self);
        for dep in other.deps.iter() {
            let step0_result = deps.insert_step0(&dep.config, dep.closure_deps);
            if !step0_result.0.is_empty() {
                deps.to_mut()
                    .insert_step1(borrow::Cow::Borrowed(&dep.config), step0_result);
            }
        }
        deps
    }

    // Further restrict each closure dependency's entry associated config to limit.
    pub fn limit_config_scopes(&self, limit: &ConfigDeps) -> borrow::Cow<ClosureDeps> {
        if self.are_all_configs_limited(limit) {
            return borrow::Cow::Borrowed(self);
        }

        // If two configs in the list had been relatively ordered (via partial_cmp())
        // before, so will they be after limiting all configs by the same limit.
        // However, items that had *not* been comparable before, might become so
        // after, namely if the now lesser item had not included some config dep
        // (in the former set) of the now greater item.
        let mut deps = Self::empty();
        for dep in self.deps.iter() {
            let mut config_deps = dep.config.clone();
            config_deps.merge_from(limit);
            deps.insert(borrow::Cow::Owned(config_deps), dep.closure_deps);
        }
        borrow::Cow::Owned(deps)
    }

    pub fn are_all_configs_limited(&self, limit: &ConfigDeps) -> bool {
        if limit.is_empty() {
            return true;
        }
        for dep in self.deps.iter() {
            if !matches!(
                dep.config.partial_cmp(limit),
                Some(cmp::Ordering::Less | cmp::Ordering::Equal)
            ) {
                return false;
            }
        }
        true
    }

    fn are_all_flags_set_for_config(&self, mut i: usize, mut set: ClosureDepsFlags) -> bool {
        let config = &self.deps[i];
        set = Self::prune_implied_flags(set, config.closure_deps);
        let config = &config.config;
        while !set.is_empty() && i > 0 {
            i -= 1;
            let entry = &self.deps[i];
            if !matches!(
                config.partial_cmp(&entry.config),
                Some(cmp::Ordering::Less | cmp::Ordering::Equal)
            ) {
                continue;
            }
            set = Self::prune_implied_flags(set, entry.closure_deps);
        }
        set.is_empty()
    }

    pub fn mod_all_closure_deps(
        &self,
        set: ClosureDepsFlags,
        clear: ClosureDepsFlags,
    ) -> borrow::Cow<Self> {
        assert!(!set.intersects(clear));
        Self::check_clear_flags(clear, set);
        let mut need_update = false;
        for i in 0..self.deps.len() {
            if self.deps[i].closure_deps.intersects(clear)
                || !self.are_all_flags_set_for_config(i, set)
            {
                need_update = true;
                break;
            }
        }
        if !need_update {
            return borrow::Cow::Borrowed(self);
        }

        let mut deps = Self::empty();
        for dep in self.deps.iter() {
            let mut dep = dep.clone();
            dep.closure_deps.insert(set);
            dep.closure_deps.remove(clear);
            if dep.closure_deps.is_empty() {
                continue;
            }
            deps.deps.push(dep);
        }

        borrow::Cow::Owned(deps)
    }

    pub fn mod_all_closure_deps_set_cond(
        &self,
        condition: ClosureDepsFlags,
        set: ClosureDepsFlags,
    ) -> borrow::Cow<Self> {
        let mut need_update = false;
        for i in 0..self.deps.len() {
            if self.deps[i].closure_deps.intersects(condition)
                && !self.are_all_flags_set_for_config(i, set)
            {
                need_update = true;
                break;
            }
        }
        if !need_update {
            return borrow::Cow::Borrowed(self);
        }

        let mut deps = Self::empty();
        for dep in self.deps.iter() {
            let mut dep = dep.clone();
            if dep.closure_deps.intersects(condition) {
                dep.closure_deps.insert(set);
            }
            deps.deps.push(dep);
        }
        borrow::Cow::Owned(deps)
    }

    pub fn transform_all_closure_deps(
        &self,
        mask: ClosureDepsFlags,
        repl: ClosureDepsFlags,
    ) -> borrow::Cow<Self> {
        Self::check_clear_flags(mask, repl);
        let mut need_update = false;
        for i in 0..self.deps.len() {
            if self.deps[i].closure_deps.intersects(mask) {
                need_update = true;
                break;
            }
        }
        if !need_update {
            return borrow::Cow::Borrowed(self);
        }

        let mut deps = Self::empty();
        for dep in self.deps.iter() {
            let mut dep = dep.clone();
            if dep.closure_deps.intersects(mask) {
                dep.closure_deps.remove(mask);
                dep.closure_deps.insert(repl);
            }
            deps.deps.push(dep);
        }
        borrow::Cow::Owned(deps)
    }

    pub fn collect_config_deps(&self, mask: ClosureDepsFlags) -> ConfigDepsDisjunction {
        let mut result = ConfigDepsDisjunction::empty();
        for dep in self.deps.iter() {
            if dep.closure_deps.intersects(mask) {
                result.insert(borrow::Cow::Borrowed(&dep.config));
            }
        }
        result
    }

    pub fn any(&self, mask: ClosureDepsFlags) -> bool {
        for dep in self.deps.iter() {
            if dep.closure_deps.intersects(mask) {
                return true;
            }
        }
        false
    }
}
