// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A "Type" table as found in TCG TPM2 Part 2 "Structures".

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::{
    AlgMacroExpander, AlgMacroInvocationFinder, AlgMacroInvocationNormalizer, AlgorithmRegistry,
};
use super::deps::ConfigDeps;
use super::expr::{Expr, ExprOp, ExprParser, ExprResolvedId, ExprValue};
use super::predefined::PredefinedTypeRef;
use super::string_transformer::StringTransformer;
use super::table_common::{ClosureDeps, CommonStructuresTableInfo};
use super::tables::{
    StructuresPartTablesConstantIndex, StructuresPartTablesConstantsIndex,
    StructuresPartTablesTypeIndex,
};
use super::value_range::ValueRange;
use regex::Regex;
use std::io;

#[derive(Clone, Debug)]
pub struct TypeTableEntry {
    pub values: ValueRange,
    pub conditional: bool,
    pub deps: ConfigDeps,
}

impl TypeTableEntry {
    fn new(values: ValueRange, conditional: bool) -> Self {
        Self {
            values,
            conditional,
            deps: ConfigDeps::new(),
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let values = self.values.transform_strings(repl);
        let deps = self.deps.transform_strings(repl);
        Self {
            values,
            conditional: self.conditional,
            deps,
        }
    }

    fn can_be_enum_member(&self) -> bool {
        match &self.values {
            ValueRange::Range {
                min_value: _,
                max_value: _,
            } => false,
            ValueRange::Discrete(values) => {
                // This will be re-evaluated after CPP-like macro expansion at
                // the resolving phase, but do it here as well for completeness.
                if values.len() == 1 {
                    matches!(&values[0].op, ExprOp::Id(_))
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TypeTableResolvedBase {
    Predefined(PredefinedTypeRef),
    Constants(StructuresPartTablesConstantsIndex),
    Type(StructuresPartTablesTypeIndex),
}

#[derive(Clone, Debug)]
pub struct TypeTable {
    pub info: CommonTableInfo,
    pub structures_info: CommonStructuresTableInfo,
    pub name: String,
    pub base: String,
    pub error_rc: Option<String>,
    pub entries: Vec<TypeTableEntry>,

    pub conditional: bool,
    pub enum_like: bool,

    pub(super) resolved_base: Option<TypeTableResolvedBase>,
    pub resolved_error_rc: Option<StructuresPartTablesConstantIndex>,
    pub underlying_type: Option<PredefinedTypeRef>,
    pub size: Option<ExprValue>,
    pub closure_deps: ClosureDeps,
    pub closure_deps_conditional: ClosureDeps,
}

impl TypeTable {
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
        if col_headers.is_empty() {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[0] != "Value"
            && col_headers[0] != "Values"
            && col_headers[0] != "Parameter"
        {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut error_rc = None;
        let mut entries = Vec::new();
        let mut conditional = false;
        let mut enum_like = true;
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

            let value = cols[0];
            if let Some(name) = value.strip_prefix('#') {
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
            alg_macro_finder
                .search(value)
                .map_err(report_alg_finder_error)?;
            let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                &alg_macro_finder,
                header_alg_macro_finder.found_any(),
            );
            let value = alg_macro_normalizer.normalize(value);

            if value.starts_with('{') {
                let (range, remainder) =
                    ValueRange::new_from_csv(filename, row.0, &value)?.unwrap();
                if !remainder.trim().is_empty() {
                    eprintln!(
                        "error: {}:{}: garbage after value range specifier: \"{}\"",
                        filename, row.0, remainder
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                enum_like = false;
                entries.push(TypeTableEntry::new(range, false));
            } else {
                let mut entry_conditional = false;
                let value = match value.strip_prefix('+') {
                    Some(value) => {
                        entry_conditional = true;
                        value
                    }
                    None => &*value,
                };
                conditional |= entry_conditional;

                let value = match ExprParser::parse(value) {
                    Ok(expr) => expr,
                    Err(_) => {
                        eprintln!(
                            "error: {}:{}: failed to parse value expression",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };
                match &value.op {
                    ExprOp::Id(_) => (),
                    _ => enum_like = false,
                };
                let values = vec![value];

                let entry = TypeTableEntry::new(ValueRange::Discrete(values), entry_conditional);
                if !entry.can_be_enum_member() {
                    enum_like = false;
                }
                entries.push(entry);
            }
        }
        Ok(Self {
            info,
            structures_info,
            name,
            base,
            error_rc,
            entries,
            conditional,
            enum_like,
            resolved_base: None,
            resolved_error_rc: None,
            underlying_type: None,
            size: None,
            closure_deps: ClosureDeps::empty(),
            closure_deps_conditional: ClosureDeps::empty(),
        })
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let info = self.info.clone();
        let structures_info = self.structures_info.transform_strings(repl);
        let name = repl.transform(&self.name).into_owned();
        let base = repl.transform(&self.base).into_owned();
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
            conditional: self.conditional,
            enum_like: self.enum_like,
            resolved_base: self.resolved_base,
            resolved_error_rc: self.resolved_error_rc,
            underlying_type: self.underlying_type,
            size: self.size.clone(),
            closure_deps: self.closure_deps.clone(),
            closure_deps_conditional: self.closure_deps_conditional.clone(),
        }
    }

    pub(super) fn expand_alg_macro(
        &mut self,
        alg_registry: &AlgorithmRegistry,
        re_alg_macro_invocation: &Regex,
    ) -> Vec<TypeTable> {
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
            let mut search_expr = |e: &Expr, _: &[()]| {
                match &e.op {
                    ExprOp::Id(id) => {
                        alg_macro_finder.search(&id.name).unwrap();
                    }
                    ExprOp::Sizeof(id) => {
                        alg_macro_finder.search(&id.name).unwrap();
                    }
                    _ => (),
                };
            };
            match &entry.values {
                ValueRange::Discrete(values) => {
                    for v in values {
                        v.map(&mut search_expr);
                    }
                }
                ValueRange::Range {
                    min_value,
                    max_value,
                } => {
                    if let Some(min_value) = min_value {
                        min_value.map(&mut search_expr);
                    }
                    if let Some(max_value) = max_value {
                        max_value.map(&mut search_expr);
                    }
                }
            };

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

    pub fn get_enum_type_member_constant(&self, j: usize) -> StructuresPartTablesConstantIndex {
        assert!(self.enum_like);
        match &self.entries[j].values {
            ValueRange::Discrete(values) => {
                assert_eq!(values.len(), 1);
                match &values[0].op {
                    ExprOp::Id(id) => match id.resolved.as_ref().unwrap() {
                        ExprResolvedId::Constant(constant_index) => *constant_index,
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }
}
