// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A "Constants" table as found in TCG TPM2 Part 2 "Structures".

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
use super::tables::StructuresPartTablesConstantIndex;
use regex::Regex;
use std::borrow;
use std::io;

#[derive(Clone, Debug)]
pub struct ConstantsTableEntry {
    pub name: String,
    pub value: Expr,
    pub is_helper_duplicate: bool,
    pub deps: ConfigDeps,
    pub closure_deps: ClosureDeps,
}

impl ConstantsTableEntry {
    fn new(name: String, value: Expr, deps: ConfigDeps) -> Self {
        Self {
            name,
            value,
            is_helper_duplicate: false,
            deps,
            closure_deps: ClosureDeps::empty(),
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let name = repl.transform(&self.name).into_owned();
        let value = self.value.transform_strings(repl);
        let deps = self.deps.transform_strings(repl);
        Self {
            name,
            value,
            is_helper_duplicate: self.is_helper_duplicate,
            deps,
            closure_deps: self.closure_deps.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConstantsTable {
    pub info: CommonTableInfo,
    pub structures_info: CommonStructuresTableInfo,
    pub name: String,
    pub base: Option<String>,
    pub error_rc: Option<String>,
    pub entries: Vec<ConstantsTableEntry>,

    pub resolved_base: Option<PredefinedTypeRef>,
    pub resolved_error_rc: Option<StructuresPartTablesConstantIndex>,
    pub enum_like: bool,
    pub size: Option<ExprValue>,
    pub closure_deps: ClosureDeps,
}

impl ConstantsTable {
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        structures_info: CommonStructuresTableInfo,
        name: String,
        base: Option<String>,
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
        } else if !col_headers[0].contains("Name") {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[1].trim() != "Value" && !col_headers[1].contains("Code") {
            eprintln!(
                "error: {}:{}: unexpected column name header in second column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let deps_column = if col_headers.len() >= 3 && col_headers[2].trim() == "Dep" {
            Some(2)
        } else if col_headers.len() >= 4 && col_headers[3].trim() == "Dep" {
            Some(3)
        } else {
            None
        };

        let mut error_rc = None;
        let mut entries = Vec::new();
        for row in rows {
            let cols: Vec<&str> = row.1.split(';').collect();
            if cols.len() != col_headers.len() {
                eprintln!(
                    "error: {}:{}: unexpected number of columns in table row",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            // Skip empty rows.
            let name = cols[0].trim();
            if name.is_empty() {
                continue;
            }

            // Skip "reserved" entries
            if name == "reserved" {
                continue;
            } else if let Some(name) = name.strip_prefix('#') {
                if error_rc.is_some() {
                    eprintln!(
                        "error: {}:{}: multiple error RC codes in table",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                error_rc = Some(name.trim_start().to_owned());
                continue;
            }

            let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
            let report_alg_finder_error =
                |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
            let alg_macro_in_name = alg_macro_finder
                .search(name)
                .map_err(report_alg_finder_error)?;
            let value = cols[1];
            alg_macro_finder
                .search(value)
                .map_err(report_alg_finder_error)?;
            if !header_alg_macro_finder.found_any()
                && alg_macro_finder.found_any()
                && !alg_macro_in_name
            {
                eprintln!(
                    "error: {}:{}: no algorithm macro invocation in expanded constant's name",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                &alg_macro_finder,
                header_alg_macro_finder.found_any(),
            );
            let name = alg_macro_normalizer.normalize(name).into_owned();
            let value = alg_macro_normalizer.normalize(value);

            let value = match ExprParser::parse(&value) {
                Ok(expr) => expr,
                Err(_) => {
                    eprintln!(
                        "error: {}:{}: failed to parse value expression",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };
            let mut deps = ConfigDeps::new();

            if let Some(deps_column) = deps_column {
                for dep in cols[deps_column].split(',') {
                    let dep = dep.trim();
                    deps.add(borrow::Cow::from(dep));
                }
            }
            entries.push(ConstantsTableEntry::new(name, value, deps));
        }

        Ok(Self {
            info,
            structures_info,
            name,
            base,
            error_rc,
            entries,
            resolved_base: None,
            resolved_error_rc: None,
            enum_like: false,
            size: None,
            closure_deps: ClosureDeps::empty(),
        })
    }

    pub(super) fn expand_alg_macro(
        &mut self,
        alg_registry: &AlgorithmRegistry,
        re_alg_macro_invocation: &Regex,
    ) -> Vec<ConstantsTable> {
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

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let info = self.info.clone();
        let structures_info = self.structures_info.transform_strings(repl);
        let name = repl.transform(&self.name).into_owned();
        let base = self.base.as_ref().map(|s| repl.transform(s).into_owned());
        let error_rc = self
            .error_rc
            .as_ref()
            .map(|s| repl.transform(s).into_owned());
        let entries = Vec::from_iter(self.entries.iter().map(|e| e.transform_strings(repl)));
        Self {
            info,
            structures_info,
            name,
            base,
            error_rc,
            entries,
            resolved_base: self.resolved_base,
            resolved_error_rc: self.resolved_error_rc,
            enum_like: self.enum_like,
            size: self.size.clone(),
            closure_deps: self.closure_deps.clone(),
        }
    }
}
