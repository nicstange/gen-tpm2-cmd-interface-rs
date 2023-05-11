// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;
use std::cmp;
use std::slice;

use super::string_transformer::StringTransformer;

// A list of dependencies, usually on algorithm availability, like "ecc" or
// "rsa".  It is meant as a conjunction, i.e. all listed features must be
// enabled for the ConfigDeps to be satisified.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfigDeps {
    pub deps: Vec<String>,
}

impl ConfigDeps {
    pub fn new() -> Self {
        Self { deps: Vec::new() }
    }

    pub fn add(&mut self, dep: borrow::Cow<str>) -> bool {
        let trimmed = dep.trim();
        if trimmed.is_empty() {
            return false;
        }

        let dep = if trimmed.len() != dep.len() {
            trimmed.to_ascii_lowercase()
        } else {
            let mut dep = dep.into_owned();
            dep.make_ascii_lowercase();
            dep
        };

        match self.deps.binary_search(&dep) {
            Err(pos) => {
                self.deps.insert(pos, dep);
                true
            }
            Ok(_) => false,
        }
    }

    pub fn merge_from(&mut self, other: &ConfigDeps) -> bool {
        let mut updated = false;

        for dep in other.deps.iter() {
            updated |= self.add(borrow::Cow::from(dep));
        }
        updated
    }

    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }

    pub fn is_unconditional_true(&self) -> bool {
        self.is_empty()
    }

    pub fn contains(&self, dep: &str) -> bool {
        let mut dep = borrow::Cow::from(dep);
        if dep.chars().any(|c| c.is_ascii_uppercase()) {
            dep.to_mut().make_ascii_lowercase();
        }
        self.deps.iter().any(|d| d == dep.as_ref())
    }

    pub(super) fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let mut deps = Self::new();
        for dep in self.deps.iter().map(|dep| repl.transform(dep)) {
            deps.add(dep);
        }
        deps
    }

    pub fn iter_raw(&self) -> slice::Iter<String> {
        self.deps.iter()
    }

    pub fn iter(&self) -> ConfigDepsIterator {
        ConfigDepsIterator {
            it: self.iter_raw(),
        }
    }

    pub fn len(&self) -> usize {
        self.deps.len()
    }

    pub fn conflicts_with(&self, other: &ConfigDeps) -> bool {
        for (neg, dep) in self.iter() {
            for (other_neg, other_dep) in other.iter() {
                if dep == other_dep && neg != other_neg {
                    return true;
                }
            }
        }
        false
    }

    pub fn factor_by(&mut self, other: &ConfigDeps) -> bool {
        let mut updated = false;
        // Retain only those deps which are not in other.
        let mut j = 0;
        for dep in std::mem::take(&mut self.deps).drain(..) {
            while j < other.deps.len() && other.deps[j] < dep {
                j += 1;
            }
            if j < other.deps.len() && other.deps[j] == dep {
                updated = true;
                j += 1;
            } else {
                self.deps.push(dep);
            }
        }
        updated
    }

    pub fn factor_by_common_of(&self, other: &ConfigDepsDisjunction) -> borrow::Cow<Self> {
        let (common_other, _) = other.factor();
        if common_other.is_empty() {
            return borrow::Cow::Borrowed(self);
        }

        let mut deps = self.clone();
        deps.factor_by(&common_other);
        borrow::Cow::Owned(deps)
    }

    fn alpha_cmp(&self, other: &ConfigDeps) -> cmp::Ordering {
        let self_len = self.deps.len();
        let other_len = other.deps.len();
        for i in 0..cmp::min(self_len, other_len) {
            let c = self.deps[i].cmp(&other.deps[i]);
            match c {
                cmp::Ordering::Equal => (),
                _ => return c,
            };
        }

        self_len.cmp(&other_len)
    }

    pub fn is_implied_by(&self, other: &ConfigDeps) -> bool {
        match self.partial_cmp(other) {
            Some(cmp::Ordering::Less) => false,
            Some(cmp::Ordering::Equal) => true,
            Some(cmp::Ordering::Greater) => true,
            None => false,
        }
    }
}

pub struct ConfigDepsIterator<'a> {
    it: slice::Iter<'a, String>,
}

impl<'a> Iterator for ConfigDepsIterator<'a> {
    type Item = (bool, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        match self.it.next() {
            Some(dep) => match dep.strip_prefix('!') {
                Some(dep) => Some((true, dep.trim_start())),
                None => Some((false, dep.as_str())),
            },
            None => None,
        }
    }
}

impl cmp::PartialOrd for ConfigDeps {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        // A conjunction of dependencies compares less than another if it is more strict,
        // i.e. if the set of satisfying configurations is a subset of the one corresponding
        // to other.
        let mut result = cmp::Ordering::Equal;
        let mut i = 0;
        let mut j = 0;
        loop {
            if i == self.deps.len() {
                if j == other.deps.len() {
                    return Some(result);
                } else {
                    // other has some deps remaining, their conjunction can only be more strict, if anything.
                    match result {
                        cmp::Ordering::Greater | cmp::Ordering::Equal => {
                            return Some(cmp::Ordering::Greater)
                        }
                        _ => return None,
                    };
                }
            } else if j == other.deps.len() {
                // self has some deps remaining, their conjunction can only be more strict, if anything.
                match result {
                    cmp::Ordering::Less | cmp::Ordering::Equal => return Some(cmp::Ordering::Less),
                    _ => return None,
                };
            }

            // The deps are sorted alphabetically.
            match self.deps[i].cmp(&other.deps[j]) {
                cmp::Ordering::Equal => {
                    i += 1;
                    j += 1;
                }
                cmp::Ordering::Less => {
                    // other does not include (require) self.deps[i], self is stricter, if anything.
                    if result == cmp::Ordering::Greater {
                        return None;
                    }
                    result = cmp::Ordering::Less;
                    i += 1;
                }
                cmp::Ordering::Greater => {
                    // self does not include (require) other.deps[j], other is stricter, if anything.
                    if result == cmp::Ordering::Less {
                        return None;
                    }
                    result = cmp::Ordering::Greater;
                    j += 1;
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfigDepsDisjunction {
    pub deps: Vec<ConfigDeps>,
}

impl ConfigDepsDisjunction {
    pub fn empty() -> Self {
        Self { deps: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }

    pub fn is_unconditional_true(&self) -> bool {
        self.deps.len() == 1 && self.deps[0].is_empty()
    }

    fn index_by_config_len(&self, config_len: usize) -> usize {
        // The deps are sorted by their configs' length (number of config
        // dependencies in the conjunction). This way, potentially more
        // restrictive ones (potentially comparing as Ordering::Less) will come
        // later in the series.
        self.deps.partition_point(|c| c.len() < config_len)
    }

    // Insertion is divided into one non-mutating step and a subsequent mutating
    // step, enabling COW behavior inbetween if needed.
    fn insert_step0(&self, config: &ConfigDeps) -> Option<(usize, usize)> {
        // Check if there is a more generic existing config implying the config to be added already.
        let i = self.index_by_config_len(config.len() + 1);
        let mut insertion_point = i;
        let mut j = i;
        while j > 0 {
            j -= 1;
            let existing = &self.deps[j];
            let cmp = (*config).partial_cmp(existing);
            match cmp {
                Some(cmp::Ordering::Less) | Some(cmp::Ordering::Equal) => {
                    // config is more restrictive, i.e. config implies existing.
                    return None;
                }
                Some(cmp::Ordering::Greater) => unreachable!(),
                None => {
                    // Conjunctions of equal length are to be sorted alphabetically.
                    if existing.len() == config.len() {
                        if let cmp::Ordering::Less = config.alpha_cmp(existing) {
                            insertion_point = j;
                        }
                    }
                }
            };
        }

        Some((i, insertion_point))
    }

    fn insert_step1(
        &mut self,
        config: borrow::Cow<ConfigDeps>,
        step0_result: Option<(usize, usize)>,
    ) -> bool {
        let (i, insertion_point) = match step0_result {
            Some((i, insertion_point)) => (i, insertion_point),
            None => {
                return false;
            }
        };

        // Conversely, in analogy to the search from step0, prune all existing, less generic
        // configs from the list.
        let mut j = i;
        while j < self.deps.len() {
            let existing = &self.deps[j];
            if existing < &config {
                self.deps.remove(j);
                continue;
            }
            j += 1;
        }
        self.deps.insert(insertion_point, config.into_owned());
        true
    }

    pub fn insert(&mut self, config: borrow::Cow<ConfigDeps>) -> bool {
        let step0_result = self.insert_step0(&config);
        self.insert_step1(config, step0_result)
    }

    pub fn merge_from(&mut self, other: &Self) {
        for dep in other.deps.iter() {
            self.insert(borrow::Cow::Borrowed(dep));
        }
    }

    pub fn factor(&self) -> (ConfigDeps, borrow::Cow<Self>) {
        let mut common = ConfigDeps::new();
        if self.deps.is_empty() {
            return (common, borrow::Cow::Borrowed(self));
        }

        for dep in self.deps[0].deps.iter() {
            if self.deps[1..].iter().all(|deps| deps.contains(dep)) {
                common.add(borrow::Cow::Borrowed(dep));
            }
        }

        let mut factored = Self::empty();
        for dep in self.deps.iter() {
            let mut dep = dep.clone();
            dep.factor_by(&common);
            factored.insert(borrow::Cow::Owned(dep));
        }

        (common, borrow::Cow::Owned(factored))
    }

    pub fn factor_by_common_of(&mut self, other: &Self) {
        let (common_other, _) = other.factor();

        if common_other.is_empty() {
            return;
        }

        let mut deps = std::mem::take(&mut self.deps);
        while let Some(mut conjunction) = deps.pop() {
            conjunction.factor_by(&common_other);
            self.insert(borrow::Cow::Owned(conjunction));
        }
    }

    pub fn limit_by(&mut self, limit: &ConfigDeps) {
        if limit.is_unconditional_true() {
            return;
        }
        let mut deps = std::mem::take(&mut self.deps);
        while let Some(mut conjunction) = deps.pop() {
            conjunction.merge_from(limit);
            self.insert(borrow::Cow::Owned(conjunction));
        }
    }

    pub fn is_implied_by(&self, other: &ConfigDepsDisjunction) -> bool {
        match self.partial_cmp(other) {
            Some(cmp::Ordering::Less) => false,
            Some(cmp::Ordering::Equal) => true,
            Some(cmp::Ordering::Greater) => true,
            None => false,
        }
    }
}

impl cmp::PartialOrd for ConfigDepsDisjunction {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        // A disjunction of dependency conjunctions compares less than another
        // if it is more strict, i.e. if the set of satisfying configurations is
        // a subset of the one corresponding to other.
        let mut result = cmp::Ordering::Equal;

        for dep in self.deps.iter() {
            let ordering = other
                .deps
                .iter()
                .find_map(|other_dep| dep.partial_cmp(other_dep));
            match ordering {
                Some(ordering) => {
                    match ordering {
                        cmp::Ordering::Less => {
                            result = cmp::Ordering::Less;
                        }
                        cmp::Ordering::Equal => (),
                        cmp::Ordering::Greater => {
                            if result == cmp::Ordering::Less {
                                return None;
                            }
                            result = cmp::Ordering::Greater;
                            break;
                        }
                    };
                }
                None => return None,
            };
        }

        match result {
            cmp::Ordering::Less => Some(result),
            cmp::Ordering::Equal => {
                if self.deps.len() < other.deps.len() {
                    Some(cmp::Ordering::Less)
                } else {
                    assert_eq!(self.deps.len(), other.deps.len());
                    Some(cmp::Ordering::Equal)
                }
            }
            cmp::Ordering::Greater => {
                for other_dep in other.deps.iter() {
                    let ordering = self.deps.iter().find_map(|dep| dep.partial_cmp(other_dep));
                    match ordering {
                        Some(ordering) => {
                            if let cmp::Ordering::Less = ordering {
                                return None;
                            }
                        }
                        None => {
                            return None;
                        }
                    };
                }
                Some(cmp::Ordering::Greater)
            }
        }
    }
}
