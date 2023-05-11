// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// Algorithms extracted from the TCG TPM2 Part 2 "Structures" TPM_ALG_ID table
// and !ALG macro expansion helpers.

use super::deps::ConfigDeps;
use super::string_transformer::StringTransformer;
use regex::Regex;
use std::borrow;
use std::cmp;
use std::io;
use std::ops::Deref;
use std::slice;
use std::str;

#[repr(u16)]
enum AlgoFlag {
    Asymmetric = 0x01,
    Symmetric = 0x02,
    Hash = 0x04,
    Sign = 0x08,
    AnonSign = 0x10,
    Encrypt = 0x20,
    Method = 0x40,
    Object = 0x80,
    XOF = 0x100, // "Extensible Output Function"
    SHBS = 0x200, // "Stateful Hash-Based Signature"
}

impl TryFrom<char> for AlgoFlag {
    type Error = ();

    fn try_from(c: char) -> Result<Self, Self::Error> {
        match c {
            'A' | 'a' => Ok(Self::Asymmetric),
            'S' | 's' => Ok(Self::Symmetric),
            'H' | 'h' => Ok(Self::Hash),
            'X' | 'x' => Ok(Self::Sign),
            'N' | 'n' => Ok(Self::AnonSign),
            'E' | 'e' => Ok(Self::Encrypt),
            'M' | 'm' => Ok(Self::Method),
            'O' | 'o' => Ok(Self::Object),
            'Z' | 'z' => Ok(Self::XOF),
            'C' | 'c' => Ok(Self::SHBS),
            _ => Err(()),
        }
    }
}

// Algorithm flags as defined in TCG TPM2 part 2 "Structures",
// Table 8 "Legend for TPM_ALG_ID Table"
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct AlgoFlags {
    flags: u8,
}

impl AlgoFlags {
    fn is_set(&self, flag: AlgoFlag) -> bool {
        self.flags & flag as u8 != 0
    }
}

impl PartialOrd<AlgoFlags> for AlgoFlags {
    fn partial_cmp(&self, rhs: &AlgoFlags) -> Option<cmp::Ordering> {
        let intersection = self.flags & rhs.flags;
        let joined = self.flags | rhs.flags;
        if intersection == joined {
            Some(cmp::Ordering::Equal)
        } else if intersection == self.flags {
            Some(cmp::Ordering::Less)
        } else if intersection == rhs.flags {
            Some(cmp::Ordering::Greater)
        } else {
            None
        }
    }
}

impl TryFrom<&str> for AlgoFlags {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut flags = 0u8;
        for c in s.chars() {
            if c.is_whitespace() {
                continue;
            }
            let flag = AlgoFlag::try_from(c)? as u8;
            flags |= flag;
        }
        Ok(Self { flags })
    }
}

impl From<&AlgoFlags> for String {
    fn from(flags: &AlgoFlags) -> Self {
        let mut s = String::new();
        if flags.is_set(AlgoFlag::Asymmetric) {
            s.push('A');
        }
        if flags.is_set(AlgoFlag::Symmetric) {
            s.push('S');
        }
        if flags.is_set(AlgoFlag::Hash) {
            s.push('H');
        }
        if flags.is_set(AlgoFlag::Sign) {
            s.push('X');
        }
        if flags.is_set(AlgoFlag::AnonSign) {
            s.push('N');
        }
        if flags.is_set(AlgoFlag::Encrypt) {
            s.push('E');
        }
        if flags.is_set(AlgoFlag::Method) {
            s.push('M');
        }
        if flags.is_set(AlgoFlag::Object) {
            s.push('O');
        }
        s
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct AlgoFlagsMask {
    flags: AlgoFlags,
    inclusive: bool,
}

impl AlgoFlagsMask {
    fn matches(&self, flags: &AlgoFlags) -> bool {
        &self.flags == flags || (self.inclusive && &self.flags < flags)
    }
}

impl TryFrom<&str> for AlgoFlagsMask {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let flags = AlgoFlags::try_from(s)?;
        if flags.flags == 0 {
            return Err(());
        }
        let inclusive = s.chars().any(|c| c.is_ascii_lowercase());
        if inclusive && s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(());
        }

        Ok(Self { flags, inclusive })
    }
}

impl From<&AlgoFlagsMask> for String {
    fn from(mask: &AlgoFlagsMask) -> Self {
        let mut s = String::from(&mask.flags);
        if mask.inclusive {
            s.make_ascii_lowercase();
        }
        s
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AlgoFlagsMasksOr {
    masks: Vec<AlgoFlagsMask>,
}

impl AlgoFlagsMasksOr {
    fn matches(&self, flags: &AlgoFlags) -> bool {
        self.masks.iter().any(|m| m.matches(flags))
    }
}

impl TryFrom<&str> for AlgoFlagsMasksOr {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut masks = Vec::new();
        for s in s.split('.') {
            masks.push(AlgoFlagsMask::try_from(s)?);
        }
        Ok(Self { masks })
    }
}

impl From<&AlgoFlagsMasksOr> for String {
    fn from(masks: &AlgoFlagsMasksOr) -> Self {
        masks
            .masks
            .iter()
            .map(String::from)
            .reduce(|mut ms, m| {
                ms.push('.');
                ms + &m
            })
            .unwrap()
    }
}

// Algorithm names and associated flags as speified in
// TCG TPM2 part 2 "Structures", Table 9 "Definition of TPM_ALG_ID constants"
#[derive(Debug)]
pub struct AlgorithmRegistryEntry {
    pub name: String,
    flags: AlgoFlags,
    pub dep: Option<String>,
}

#[derive(Debug)]
pub struct AlgorithmRegistry {
    algos: Vec<AlgorithmRegistryEntry>,
}

impl AlgorithmRegistry {
    pub(in super::super) fn new_from_csv(
        filename: &str,
        table_lines: &[(u32, String)],
    ) -> Result<Self, io::Error> {
        let header_row = &table_lines[0];
        let rows = &table_lines[1..];
        let col_headers: Vec<&str> = header_row.1.split(';').map(|e| e.trim()).collect();
        if col_headers.len() < 4 {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[0] != "Algorithm Name" {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[2] != "Type" {
            eprintln!(
                "error: {}:{}: unexpected column name header in third column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[3] != "Dep" {
            eprintln!(
                "error: {}:{}: unexpected column name header in fourth third",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut registry = AlgorithmRegistry::new();
        for row in rows {
            let cols: Vec<&str> = row.1.split(';').map(|e| e.trim()).collect();
            if cols.len() != col_headers.len() {
                eprintln!(
                    "error: {}:{}: unexpected number of columns in table row",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            // Skip empty rows.
            let name = cols[0];
            if name.is_empty() {
                continue;
            }

            // Skip "reserved" and RC code entries
            if name == "reserved" || name.strip_prefix('#').is_some() {
                continue;
            }

            let name = match name.strip_prefix("TPM_ALG_") {
                Some(name) => name,
                None => {
                    eprintln!(
                        "error: {}:{}: unexpected algorithm constant name",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };
            let mut name = name.to_owned();
            name.make_ascii_lowercase();

            let flags = match AlgoFlags::try_from(cols[2]) {
                Ok(flags) => flags,
                Err(_) => {
                    eprintln!("error: {}:{}: invalid algorithm flags", filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };

            let dep = cols[3];
            let dep = if !dep.is_empty() {
                Some(dep.to_owned())
            } else {
                None
            };

            registry
                .algos
                .push(AlgorithmRegistryEntry { name, flags, dep })
        }

        Ok(registry)
    }

    fn new() -> Self {
        Self { algos: Vec::new() }
    }

    pub fn iter<'a>(&'a self, masks: &'a AlgoFlagsMasksOr) -> AlgorithmRegistryIterator<'a> {
        AlgorithmRegistryIterator {
            registry: self,
            iter: self.algos.iter(),
            masks,
        }
    }

    pub fn _lookup(&self, name: &str) -> Option<&AlgorithmRegistryEntry> {
        let name = name.to_ascii_lowercase();
        self.algos.iter().find(|alg| alg.name == name)
    }

    pub fn lookup(&self, name: &str) -> Option<AlgorithmRegistryEntryBorrow> {
        self._lookup(name)
            .map(|entry| AlgorithmRegistryEntryBorrow {
                registry: self,
                entry,
            })
    }
}

pub struct AlgorithmRegistryIterator<'a> {
    registry: &'a AlgorithmRegistry,
    iter: slice::Iter<'a, AlgorithmRegistryEntry>,
    masks: &'a AlgoFlagsMasksOr,
}

impl<'a> Iterator for AlgorithmRegistryIterator<'a> {
    type Item = AlgorithmRegistryEntryBorrow<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.next() {
                Some(alg) => {
                    if self.masks.matches(&alg.flags) {
                        break Some(AlgorithmRegistryEntryBorrow {
                            registry: self.registry,
                            entry: alg,
                        });
                    }
                }
                None => break None,
            }
        }
    }
}

pub struct AlgorithmRegistryEntryBorrow<'a> {
    registry: &'a AlgorithmRegistry,
    entry: &'a AlgorithmRegistryEntry,
}

impl<'a> AlgorithmRegistryEntryBorrow<'a> {
    pub fn deps(&self) -> ConfigDeps {
        let mut deps = ConfigDeps::new();
        let mut worklist: Vec<&str> = Vec::new();
        worklist.push(&self.name);
        let mut i = 0;
        while i < worklist.len() {
            let name = worklist[i];
            i += 1;
            if let Some(entry) = self.registry._lookup(name) {
                if let Some(entry_deps) = entry.dep.as_ref() {
                    for dep in entry_deps.split(',') {
                        let dep = dep.trim();
                        if !dep.is_empty() && dep != name && !worklist.iter().any(|w| w == &dep) {
                            worklist.push(dep);
                        }
                    }
                }
            }

            let name = name.to_ascii_lowercase();
            match name.as_ref() {
                "error" | "keyedhash" | "xor" | "null" | "symcipher" => (),
                _ => {
                    deps.add(borrow::Cow::from(name));
                }
            };
        }
        deps
    }
}

impl<'a> Deref for AlgorithmRegistryEntryBorrow<'a> {
    type Target = AlgorithmRegistryEntry;

    fn deref(&self) -> &Self::Target {
        self.entry
    }
}

// Search a series of &str for !ALG(\..*)? macro invocations, check that all flag
// masks, if any, are consistent with each other. After having searched the
// strings of interest,
// - the AlgMacroInvocationFinder instance can be queried whether there has been
//   any !ALG macro invocation found in the set of strings at all and
// - the found flag mask, if any, can be retrieved.
#[derive(Clone)]
pub(in super::super) struct AlgMacroInvocationFinder<'a> {
    re_alg_macro_invocation: &'a Regex,
    found_mask: Option<AlgoFlagsMasksOr>,
    found_any: bool,
}

#[derive(Debug)]
pub(in super::super) enum AlgMacroInvocationFinderError {
    InvalidMask,
    InconsistentMasks,
}

impl<'a> AlgMacroInvocationFinder<'a> {
    pub fn new(re_alg_macro_invocation: &'a Regex) -> Self {
        AlgMacroInvocationFinder {
            re_alg_macro_invocation,
            found_mask: None,
            found_any: false,
        }
    }

    pub fn clone_and_reset(&self) -> Self {
        let mut new = self.clone();
        new.found_any = false;
        new
    }

    pub fn search(&mut self, s: &str) -> Result<bool, AlgMacroInvocationFinderError> {
        let mut found_one = false;
        for c in self.re_alg_macro_invocation.captures_iter(s) {
            found_one = true;
            if let Some(mask) = c.name("MASK") {
                let mask = match AlgoFlagsMasksOr::try_from(mask.as_str()) {
                    Ok(mask) => mask,
                    Err(_) => return Err(AlgMacroInvocationFinderError::InvalidMask),
                };

                match &self.found_mask {
                    Some(prev) => {
                        if prev != &mask {
                            return Err(AlgMacroInvocationFinderError::InconsistentMasks);
                        }
                    }
                    None => self.found_mask = Some(mask),
                }
            }
        }
        self.found_any |= found_one;
        Ok(found_one)
    }

    pub fn report_err(filename: &str, lineno: u32, e: AlgMacroInvocationFinderError) -> io::Error {
        match e {
            AlgMacroInvocationFinderError::InvalidMask => {
                eprintln!(
                    "error: {}:{}: invalid mask specifier in algorithm macro invocation",
                    filename, lineno
                );
            }
            AlgMacroInvocationFinderError::InconsistentMasks => {
                eprintln!(
                    "error: {}:{}: conflicting mask specifiers between algorithm macro invocations",
                    filename, lineno
                );
            }
        };
        io::Error::from(io::ErrorKind::InvalidData)
    }

    pub fn found_mask(&self) -> Option<&AlgoFlagsMasksOr> {
        self.found_mask.as_ref()
    }

    pub fn found_any(&self) -> bool {
        self.found_any
    }
}

// Normalize the !ALG(\..*)? macro incocations among a set of strings. The TCG
// TPM2 part2 "Structures" spec is a bit inconsistent about in which of a set of
// strings (table headers + fields) participating in the very same replacement,
// the algorithm flags mask will be found. The AlgMacroInvocationNormalizer
// will canonicalize this by emitting the mask specifier only in the first
// occurence in the set of strings subject to normalization, typically the table
// name if the whole table is subject to expansion or a field name otherwise, and
// stripping it from all other !ALG macro invocations, if present.
pub(in super::super) struct AlgMacroInvocationNormalizer<'a> {
    re_alg_macro_invocation: &'a Regex,
    mask: Option<&'a AlgoFlagsMasksOr>,
    no_finder_matches: bool,
}

impl<'a> AlgMacroInvocationNormalizer<'a> {
    pub fn new(finder: &'a AlgMacroInvocationFinder, strip_all_masks: bool) -> Self {
        assert!(!finder.found_any() || finder.found_mask.is_some());
        let mask = match strip_all_masks {
            true => None,
            false => finder.found_mask(),
        };

        Self {
            re_alg_macro_invocation: finder.re_alg_macro_invocation,
            mask,
            no_finder_matches: !finder.found_any(),
        }
    }

    pub fn normalize<'b>(&mut self, s: &'b str) -> borrow::Cow<'b, str> {
        if self.no_finder_matches {
            borrow::Cow::from(s)
        } else {
            self.re_alg_macro_invocation
                .replace_all(s, |caps: &regex::Captures<'_>| -> String {
                    // Only the first normalized string gets to have a
                    // mask specification.
                    // Retain the preceeding <NLWB> match, if any.
                    let mut s = if let Some(nlwb) = caps.name("NLWB") {
                        nlwb.as_str().to_owned()
                    } else {
                        String::new()
                    };
                    match &self.mask {
                        Some(mask) => {
                            let mask = *mask;
                            self.mask = None;
                            s += "!ALG.";
                            s += &String::from(mask)
                        }
                        None => {
                            s += "!ALG";
                        }
                    }
                    s
                })
        }
    }
}

pub(super) struct AlgMacroExpander<'a> {
    re_alg_macro_invocation: &'a Regex,
    alg_in_uppercase: borrow::Cow<'a, str>,
}

struct AlgMacroExpanderRegexReplacer<'a> {
    expander: &'a AlgMacroExpander<'a>,
}

impl<'a> AlgMacroExpander<'a> {
    pub fn new(re_alg_macro_invocation: &'a Regex, alg: &'a str) -> Self {
        let mut alg_in_uppercase = borrow::Cow::from(alg);
        if alg_in_uppercase
            .chars()
            .any(|c| c.is_ascii_alphabetic() && !c.is_ascii_uppercase())
        {
            alg_in_uppercase.to_mut().make_ascii_uppercase();
        }

        Self {
            re_alg_macro_invocation,
            alg_in_uppercase,
        }
    }
}

impl<'a> StringTransformer for AlgMacroExpander<'a> {
    fn transform<'b>(&self, s: &'b str) -> borrow::Cow<'b, str> {
        self.re_alg_macro_invocation
            .replace_all(s, AlgMacroExpanderRegexReplacer { expander: self })
    }
}

impl<'a> regex::Replacer for AlgMacroExpanderRegexReplacer<'a> {
    fn replace_append(&mut self, caps: &regex::Captures<'_>, dst: &mut String) {
        // Whether to use the upper or lowercase replacement depends on the
        // context: if the replacement is part of a larger word, the uppercase
        // variant is to be used.  For complete word replacement, use lowercase.
        let is_complete_word = caps.name("NLWB").is_none() && caps.name("RWB").is_some();
        if is_complete_word {
            let alg_in_lowercase = self.expander.alg_in_uppercase.to_ascii_lowercase();
            dst.push_str(&alg_in_lowercase);
        } else {
            if let Some(nlwb) = caps.name("NLWB") {
                dst.push_str(nlwb.as_str());
            }
            dst.push_str(&self.expander.alg_in_uppercase);
        }
    }
}
