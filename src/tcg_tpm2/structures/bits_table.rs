// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A "Constants" table as found in TCG TPM2 Part 2 "Structures".

use regex::Regex;
use std::borrow;
use std::io;

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::{
    AlgMacroExpander, AlgMacroInvocationFinder, AlgMacroInvocationNormalizer, AlgorithmRegistry,
};
use super::deps::ConfigDeps;
use super::expr::{Expr, ExprParser, ExprValue};
use super::predefined::PredefinedTypeRef;
use super::string_transformer::StringTransformer;
use super::table_common::{ClosureDeps, CommonStructuresTableInfo};
use super::type_table::TypeTableResolvedBase;

#[derive(Clone, Debug)]
pub struct BitsTableEntryBits {
    pub min_bit_index: Expr,
    pub max_bit_index: Option<Expr>,
}

impl BitsTableEntryBits {
    fn new(min_bit_index: Expr, max_bit_index: Option<Expr>) -> Self {
        Self {
            min_bit_index,
            max_bit_index,
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let min_bit_index = self.min_bit_index.transform_strings(repl);
        let max_bit_index = self
            .max_bit_index
            .as_ref()
            .map(|e| e.transform_strings(repl));
        Self {
            min_bit_index,
            max_bit_index,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BitsTableEntry {
    pub name: String,
    pub bits: BitsTableEntryBits,
    pub deps: ConfigDeps,
}

impl BitsTableEntry {
    fn new(name: String, bits: BitsTableEntryBits) -> Self {
        Self {
            name,
            bits,
            deps: ConfigDeps::new(),
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let name = repl.transform(&self.name).into_owned();
        let bits = self.bits.transform_strings(repl);
        let deps = self.deps.transform_strings(repl);
        Self { name, bits, deps }
    }
}

pub type BitsTableResolvedBase = TypeTableResolvedBase;

#[derive(Clone, Debug)]
pub struct BitsTable {
    pub info: CommonTableInfo,
    pub structures_info: CommonStructuresTableInfo,
    pub name: String,
    pub base: String,
    pub entries: Vec<BitsTableEntry>,
    pub reserved: Vec<BitsTableEntryBits>,

    pub(super) resolved_base: Option<BitsTableResolvedBase>,
    pub(super) underlying_type: Option<PredefinedTypeRef>,
    pub size: Option<ExprValue>,
    pub closure_deps: ClosureDeps,
}

impl BitsTable {
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        structures_info: CommonStructuresTableInfo,
        name: String,
        base: String,
        filename: &str,
        header_alg_macro_finder: &AlgMacroInvocationFinder,
        table_lines: &[(u32, String)],
        _regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let header_row = &table_lines[0];
        let rows = &table_lines[1..];
        let col_headers: Vec<&str> = header_row.1.split(';').map(|e| e.trim()).collect();
        if col_headers.len() < 2 {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[0] != "Bit" {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[1] != "Name"
            && col_headers[1] != "Parameter"
            && col_headers[1] != "Atrribute"
        {
            // Typo is intentional, it is found like this in the spec.
            eprintln!(
                "error: {}:{}: unexpected column name header in second column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut entries = Vec::new();
        let mut reserved = Vec::new();
        for row in rows {
            let cols: Vec<&str> = row.1.split(';').collect();
            if cols.len() != col_headers.len() {
                eprintln!(
                    "error: {}:{}: unexpected number of columns in table row",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let name = cols[1].trim();
            // Skip all-empty rows.
            if name.is_empty() {
                if !cols.iter().any(|col| !col.trim().is_empty()) {
                    continue;
                } else {
                    eprintln!(
                        "error: {}:{}: no name specified for bitfield entry",
                        filename, header_row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }

            let bits_spec = cols[0];
            let (name, bits_spec, is_reserved) = if name != "Reserved" {
                let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
                let report_alg_finder_error =
                    |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
                let alg_macro_in_name = alg_macro_finder
                    .search(name)
                    .map_err(report_alg_finder_error)?;
                alg_macro_finder
                    .search(bits_spec)
                    .map_err(report_alg_finder_error)?;
                if !header_alg_macro_finder.found_any()
                    && alg_macro_finder.found_any()
                    && !alg_macro_in_name
                {
                    eprintln!("error: {}:{}: no algorithm macro invocation in expanded bitfield entry's name",
                              filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                    &alg_macro_finder,
                    header_alg_macro_finder.found_any(),
                );
                let name = alg_macro_normalizer.normalize(name).into_owned();
                let bits_spec = alg_macro_normalizer.normalize(bits_spec);
                (name, bits_spec, false)
            } else {
                let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
                let report_alg_finder_error =
                    |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
                alg_macro_finder
                    .search(bits_spec)
                    .map_err(report_alg_finder_error)?;
                if !header_alg_macro_finder.found_any() && alg_macro_finder.found_any() {
                    eprintln!(
                        "error: {}:{}: algorithm macro invocation in reserved bit range",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                (name.to_owned(), borrow::Cow::Borrowed(bits_spec), true)
            };

            let mut bit_index_min = None;
            let mut bit_index_max = None;
            for bit_index in bits_spec.split(':') {
                let bit_index = match ExprParser::parse(bit_index) {
                    Ok(expr) => expr,
                    Err(_) => {
                        eprintln!(
                            "error: {}:{}: failed to parse bit index expression",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };

                if bit_index_max.is_none() {
                    bit_index_max = Some(bit_index);
                } else if bit_index_min.is_none() {
                    bit_index_min = Some(bit_index);
                } else {
                    eprintln!(
                        "error: {}:{}: unrecognized bit index range",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }
            if bit_index_min.is_none() {
                bit_index_min = bit_index_max.take();
            }
            let bit_index_min = bit_index_min.unwrap();

            let bits = BitsTableEntryBits::new(bit_index_min, bit_index_max);
            if !is_reserved {
                entries.push(BitsTableEntry::new(name, bits));
            } else {
                reserved.push(bits);
            }
        }

        Ok(Self {
            info,
            structures_info,
            name,
            base,
            entries,
            reserved,
            resolved_base: None,
            underlying_type: None,
            size: None,
            closure_deps: ClosureDeps::empty(),
        })
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let info = self.info.clone();
        let structures_info = self.structures_info.transform_strings(repl);
        let name = repl.transform(&self.name).into_owned();
        let base = repl.transform(&self.base).into_owned();
        let entries = Vec::from_iter(self.entries.iter().map(|e| e.transform_strings(repl)));
        let reserved = Vec::from_iter(self.reserved.iter().map(|r| r.transform_strings(repl)));
        Self {
            info,
            structures_info,
            name,
            base,
            entries,
            reserved,
            resolved_base: self.resolved_base,
            underlying_type: self.underlying_type,
            size: self.size.clone(),
            closure_deps: self.closure_deps.clone(),
        }
    }

    pub(super) fn expand_alg_macro(
        &mut self,
        alg_registry: &AlgorithmRegistry,
        re_alg_macro_invocation: &Regex,
    ) -> Vec<BitsTable> {
        let mut alg_macro_finder = AlgMacroInvocationFinder::new(re_alg_macro_invocation);
        alg_macro_finder.search(&self.name).unwrap();
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

    pub fn get_underlying_type(&self) -> &PredefinedTypeRef {
        self.underlying_type.as_ref().unwrap()
    }
}
