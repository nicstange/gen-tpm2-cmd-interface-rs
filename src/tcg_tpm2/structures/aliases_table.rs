// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A "Types" table as found in TCG TPM2 Part 2 "Structures".

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::{
    AlgMacroExpander, AlgMacroInvocationFinder, AlgMacroInvocationNormalizer, AlgorithmRegistry,
};
use super::deps::ConfigDeps;
use super::string_transformer::StringTransformer;
use super::table_common::{ClosureDeps, CommonStructuresTableInfo};
use regex::Regex;
use std::io;

#[derive(Clone, Debug)]
pub struct AliasesTableEntry {
    pub name: String,
    pub target: String,
    pub deps: ConfigDeps,
    pub closure_deps: ClosureDeps,
}

impl AliasesTableEntry {
    fn new(name: String, target: String) -> Self {
        Self {
            name,
            target,
            deps: ConfigDeps::new(),
            closure_deps: ClosureDeps::empty(),
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let name = repl.transform(&self.name).into_owned();
        let target = repl.transform(&self.target).into_owned();
        let deps = self.deps.transform_strings(repl);
        Self {
            name,
            target,
            deps,
            closure_deps: self.closure_deps.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AliasesTable {
    info: CommonTableInfo,
    pub structures_info: CommonStructuresTableInfo,
    pub entries: Vec<AliasesTableEntry>,
}

impl AliasesTable {
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        structures_info: CommonStructuresTableInfo,
        filename: &str,
        header_alg_macro_finder: &AlgMacroInvocationFinder,
        table_lines: &[(u32, String)],
        _regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let header_row = &table_lines[0];
        let rows = &table_lines[1..];
        let col_headers: Vec<&str> = header_row.1.split(';').collect();
        if col_headers.len() < 2 {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[0].trim() != "Type" {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[1].trim() != "Name" {
            eprintln!(
                "error: {}:{}: unexpected column name header in second column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut entries = Vec::new();
        for row in rows {
            let cols: Vec<&str> = row.1.split(';').map(|e| e.trim()).collect();
            if cols.len() != col_headers.len() {
                eprintln!(
                    "error: {}:{}: unexpected number of columns in table row",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            // Skip all-empty rows.
            if !cols.iter().any(|col| !col.is_empty()) {
                continue;
            }

            let name = cols[1];
            let target = cols[0];
            if name.is_empty() {
                eprintln!(
                    "error: {}:{}: no alias name in type alias definition",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            } else if target.is_empty() {
                eprintln!(
                    "error: {}:{}: no target type in type alias definition",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
            let report_alg_finder_error =
                |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
            alg_macro_finder
                .search(name)
                .map_err(report_alg_finder_error)?;
            alg_macro_finder
                .search(target)
                .map_err(report_alg_finder_error)?;
            let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                &alg_macro_finder,
                header_alg_macro_finder.found_any(),
            );
            let name = alg_macro_normalizer.normalize(name);
            let target = alg_macro_normalizer.normalize(target);

            entries.push(AliasesTableEntry::new(
                name.into_owned(),
                target.into_owned(),
            ));
        }

        Ok(Self {
            info,
            structures_info,
            entries,
        })
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let info = self.info.clone();
        let structures_info = self.structures_info.transform_strings(repl);
        let entries = Vec::from_iter(self.entries.iter().map(|e| e.transform_strings(repl)));
        Self {
            info,
            structures_info,
            entries,
        }
    }

    pub(super) fn expand_alg_macro(
        &mut self,
        alg_registry: &AlgorithmRegistry,
        re_alg_macro_invocation: &Regex,
    ) -> Vec<AliasesTable> {
        let mut alg_macro_finder = AlgMacroInvocationFinder::new(re_alg_macro_invocation);
        for dep in self.structures_info.deps.iter_raw() {
            alg_macro_finder.search(dep).unwrap();
            if let Some(mask) = alg_macro_finder.found_mask() {
                let mut expanded_tables = Vec::new();
                for alg in alg_registry.iter(mask) {
                    let expander = AlgMacroExpander::new(re_alg_macro_invocation, &alg.name);
                    let mut expanded = self.transform_strings(&expander);
                    expanded.info.add_alg_macro_indicator(&alg.name);
                    expanded.structures_info.deps.merge_from(&alg.deps());
                    expanded_tables.push(expanded);
                }
                return expanded_tables;
            }
        }

        let mut i = 0;
        while i < self.entries.len() {
            let entry = &self.entries[i];
            let mut alg_macro_finder = alg_macro_finder.clone_and_reset();
            alg_macro_finder.search(&entry.name).unwrap();
            if let Some(mask) = alg_macro_finder.found_mask() {
                for alg in alg_registry.iter(mask) {
                    // As a heuristic, if the table has a dependency listed
                    // verbatim already, restrict the expansion to algorithms
                    // also dependent on it. Otherwise, e.g. the
                    // TPMI_ALG_RSA_SCHEME table would include ECC specific
                    // entries after the expansion.
                    if !self.structures_info.deps.is_empty()
                        && !self.structures_info.deps.contains(&alg.name)
                    {
                        match &alg.dep {
                            Some(dep) => {
                                if !self.structures_info.deps.contains(dep) {
                                    continue;
                                }
                            }
                            None => continue,
                        };
                    }

                    let expander = AlgMacroExpander::new(re_alg_macro_invocation, &alg.name);
                    let orig_entry = &self.entries[i];
                    let mut expanded_entry = orig_entry.transform_strings(&expander);
                    expanded_entry.deps.merge_from(&alg.deps());
                    self.entries.insert(i, expanded_entry);
                    i += 1;
                }
                self.entries.remove(i);
            } else {
                i += 1;
            }
        }

        Vec::new()
    }
}
