// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// An "union" table as found in TCG TPM2 Part 2 "Structures".

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::{
    AlgMacroExpander, AlgMacroInvocationFinder, AlgMacroInvocationNormalizer, AlgorithmRegistry,
};
use super::deps::ConfigDeps;
use super::expr::{Expr, ExprParser, ExprValue};
use super::string_transformer::StringTransformer;
use super::structure_table::{
    StructureTableEntryResolvedBaseType, StructureTableEntryResolvedDiscriminantType,
};
use super::table_common::ClosureDeps;
use super::table_common::CommonStructuresTableInfo;
use super::tables::StructuresPartTablesStructureIndex;
use regex::Regex;
use std::borrow;
use std::cmp;
use std::io;

pub type UnionTableEntryResolvedBaseType = StructureTableEntryResolvedBaseType;

#[derive(Clone, Debug)]
pub struct UnionTableEntryPlainType {
    pub base_type: Option<String>,
    pub base_type_enable_conditional: bool,
    pub resolved_base_type: Option<UnionTableEntryResolvedBaseType>,
}

impl UnionTableEntryPlainType {
    fn new(base_type: borrow::Cow<str>, base_type_enable_conditional: bool) -> Self {
        // An empty type specifier means "no contents" for this member's selector case.
        let base_type = match base_type.is_empty() {
            false => Some(base_type.into_owned()),
            true => None,
        };

        Self {
            base_type,
            base_type_enable_conditional,
            resolved_base_type: None,
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let base_type = self
            .base_type
            .as_ref()
            .map(|base_type| repl.transform(base_type).into_owned());
        Self {
            base_type,
            base_type_enable_conditional: self.base_type_enable_conditional,
            resolved_base_type: self.resolved_base_type,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UnionTableEntryArrayType {
    pub element_type: String,
    pub element_type_enable_conditional: bool,
    pub size: Expr,
    pub resolved_element_type: Option<UnionTableEntryResolvedBaseType>,
}

impl UnionTableEntryArrayType {
    fn new(element_type: String, element_type_enable_conditional: bool, size: Expr) -> Self {
        Self {
            element_type,
            element_type_enable_conditional,
            size,
            resolved_element_type: None,
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        Self {
            element_type: repl.transform(&self.element_type).into_owned(),
            element_type_enable_conditional: self.element_type_enable_conditional,
            size: self.size.transform_strings(repl),
            resolved_element_type: self.resolved_element_type,
        }
    }
}

#[derive(Clone, Debug)]
pub enum UnionTableEntryType {
    Plain(UnionTableEntryPlainType),
    Array(UnionTableEntryArrayType),
}

impl UnionTableEntryType {
    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        match self {
            Self::Plain(t) => Self::Plain(t.transform_strings(repl)),
            Self::Array(t) => Self::Array(t.transform_strings(repl)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UnionTableEntry {
    pub name: String,
    pub selector: Option<String>,
    pub entry_type: UnionTableEntryType,
    pub deps: ConfigDeps,
}

impl UnionTableEntry {
    fn new(name: String, selector: Option<String>, entry_type: UnionTableEntryType) -> Self {
        Self {
            name,
            selector,
            entry_type,
            deps: ConfigDeps::new(),
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let name = repl.transform(&self.name).into_owned();
        let selector = self
            .selector
            .as_ref()
            .map(|s| repl.transform(s).into_owned());
        let entry_type = self.entry_type.transform_strings(repl);
        let deps = self.deps.transform_strings(repl);
        Self {
            name,
            selector,
            entry_type,
            deps,
        }
    }
}

// Unions are special, in that they always only exist as part of a larger
// structure also containing some discriminant. In this context, there is the
// so-called "tagged union" pattern, which refers to some structure containing
// nothing but a discriminant and an associated union members. If, for the same
// union type, several such "tagged union" structures exist, pairwise
// relationships between their respective discriminant type might induce a
// similar relation between the containing tagged union structures. For example,
// conversions might be possible between certain tagged union structures.  Keep
// track of the tagged union structures associated with some union type at the
// union type itself.
#[derive(Clone, Debug)]
pub struct TaggedUnionsByDiscriminant {
    pub discriminant_type: StructureTableEntryResolvedDiscriminantType,
    tagged_unions: Vec<StructuresPartTablesStructureIndex>,
}

impl cmp::PartialEq<StructureTableEntryResolvedDiscriminantType> for TaggedUnionsByDiscriminant {
    fn eq(&self, other_discriminant_type: &StructureTableEntryResolvedDiscriminantType) -> bool {
        let self_raw = self.discriminant_type.get_raw();
        let other_raw = other_discriminant_type.get_raw();

        self_raw == other_raw
    }
}

impl cmp::PartialEq for TaggedUnionsByDiscriminant {
    fn eq(&self, other: &TaggedUnionsByDiscriminant) -> bool {
        self.eq(&other.discriminant_type)
    }
}

impl cmp::Eq for TaggedUnionsByDiscriminant {}

impl cmp::PartialOrd<StructureTableEntryResolvedDiscriminantType> for TaggedUnionsByDiscriminant {
    fn partial_cmp(
        &self,
        other_discriminant_type: &StructureTableEntryResolvedDiscriminantType,
    ) -> Option<cmp::Ordering> {
        let self_raw = self.discriminant_type.get_raw();
        let other_raw = other_discriminant_type.get_raw();

        Some(self_raw.cmp(&other_raw))
    }
}

impl cmp::PartialOrd for TaggedUnionsByDiscriminant {
    fn partial_cmp(&self, other: &TaggedUnionsByDiscriminant) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.discriminant_type)
    }
}

impl cmp::Ord for TaggedUnionsByDiscriminant {
    fn cmp(&self, other: &TaggedUnionsByDiscriminant) -> cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct TaggedUnions {
    pub by_discriminant: Vec<TaggedUnionsByDiscriminant>, // per-discriminant-type tagged union structures
}

impl TaggedUnions {
    fn new() -> Self {
        Self {
            by_discriminant: Vec::new(),
        }
    }

    pub(super) fn add(
        &mut self,
        discriminant_type: StructureTableEntryResolvedDiscriminantType,
        tagged_union: StructuresPartTablesStructureIndex,
    ) {
        let index = match self
            .by_discriminant
            .binary_search_by(|entry| entry.partial_cmp(&discriminant_type).unwrap())
        {
            Ok(index) => index,
            Err(index) => {
                let entry = TaggedUnionsByDiscriminant {
                    discriminant_type,
                    tagged_unions: Vec::new(),
                };
                self.by_discriminant.insert(index, entry);
                index
            }
        };

        let dep = &mut self.by_discriminant[index];
        match dep.tagged_unions.binary_search(&tagged_union) {
            Ok(_) => (),
            Err(index) => {
                dep.tagged_unions.insert(index, tagged_union);
            }
        };
    }
}

#[derive(Clone, Debug)]
pub struct UnionTable {
    pub info: CommonTableInfo,
    pub structures_info: CommonStructuresTableInfo,
    pub name: String,
    pub entries: Vec<UnionTableEntry>,

    pub tagged_unions: TaggedUnions,
    pub max_size: Option<ExprValue>,
    pub size: Option<ExprValue>,
    pub max_size_deps: ClosureDeps, // Dependencies on sizeof() of the union as a whole.
}

impl UnionTable {
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        structures_info: CommonStructuresTableInfo,
        name: String,
        filename: &str,
        header_alg_macro_finder: &AlgMacroInvocationFinder,
        table_lines: &[(u32, String)],
        regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let header_row = &table_lines[0];
        let rows = &table_lines[1..];
        let col_headers: Vec<&str> = header_row.1.split(';').map(|e| e.trim()).collect();
        if col_headers.len() < 3 {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[0] != "Parameter" {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[1] != "Type" {
            eprintln!(
                "error: {}:{}: unexpected column name header in second column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[2] != "Selector" {
            eprintln!(
                "error: {}:{}: unexpected column name header in second third",
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

            let name = cols[0];
            // Skip all-empty rows.
            if name.is_empty() {
                if !cols.iter().any(|col| !col.is_empty()) {
                    continue;
                } else {
                    eprintln!(
                        "error: {}:{}: no name specified for union member entry",
                        filename, header_row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }

            if name.starts_with('#') {
                eprintln!(
                    "error: {}:{}: RC code specifications not supported for unions",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let mut base_type = cols[1];
            if base_type.starts_with('+') {
                eprintln!(
                    "error: {}:{}: conditional members not supported for unions",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mut base_type_enable_conditional = false;
            base_type = match base_type.strip_suffix('+') {
                Some(base_type) => {
                    base_type_enable_conditional = true;
                    base_type.trim_end()
                }
                None => base_type,
            };

            let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
            let report_alg_finder_error =
                |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
            alg_macro_finder
                .search(base_type)
                .map_err(report_alg_finder_error)?;

            let selector = cols[2];
            alg_macro_finder
                .search(selector)
                .map_err(report_alg_finder_error)?;

            let captures = match regexps_cache.re_union_member_name.captures(name) {
                None => {
                    eprintln!(
                        "error: {}:{}: unrecognized union member name format",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                Some(captures) => captures,
            };

            let name = captures.name("NAME").unwrap().as_str();
            if name.ends_with('=') {
                eprintln!(
                    "error: {}:{}: size specifying members not allowed in unions",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let alg_macro_in_name = alg_macro_finder
                .search(name)
                .map_err(report_alg_finder_error)?;
            let (name, selector, entry_type) = if let Some(size) = captures.name("ARRAYSIZE") {
                if base_type.is_empty() {
                    eprintln!(
                        "error: {}:{}: union array member with empty element type",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                let size = size.as_str();
                alg_macro_finder
                    .search(size)
                    .map_err(report_alg_finder_error)?;
                if !header_alg_macro_finder.found_any()
                    && alg_macro_finder.found_any()
                    && !alg_macro_in_name
                {
                    eprintln!("error: {}:{}: no algorithm macro invocation in expanded union member's name",
                                   filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                    &alg_macro_finder,
                    header_alg_macro_finder.found_any(),
                );
                let name = alg_macro_normalizer.normalize(name);
                let base_type = alg_macro_normalizer.normalize(base_type).into_owned();
                let selector = alg_macro_normalizer.normalize(selector);
                let size = alg_macro_normalizer.normalize(size);

                let size = match ExprParser::parse(&size) {
                    Ok(expr) => expr,
                    Err(_) => {
                        eprintln!(
                            "error: {}:{}: failed to parse array size expression",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };

                let entry_type =
                    UnionTableEntryArrayType::new(base_type, base_type_enable_conditional, size);
                let entry_type = UnionTableEntryType::Array(entry_type);

                (name, selector, entry_type)
            } else {
                if !header_alg_macro_finder.found_any()
                    && alg_macro_finder.found_any()
                    && !alg_macro_in_name
                {
                    eprintln!("error: {}:{}: no algorithm macro invocation in expanded union member's name",
                                   filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                    &alg_macro_finder,
                    header_alg_macro_finder.found_any(),
                );
                let name = alg_macro_normalizer.normalize(name);
                let base_type = alg_macro_normalizer.normalize(base_type);
                let selector = alg_macro_normalizer.normalize(selector);

                let entry_type =
                    UnionTableEntryPlainType::new(base_type, base_type_enable_conditional);
                let entry_type = UnionTableEntryType::Plain(entry_type);

                (name, selector, entry_type)
            };

            // Union members which have no associated selector cannot get
            // (de)serialized, but still participate in the union's sizeof()
            // calculation.
            let selector = match selector.is_empty() {
                false => Some(selector.into_owned()),
                true => None,
            };
            entries.push(UnionTableEntry::new(
                name.into_owned(),
                selector,
                entry_type,
            ));
        }

        Ok(Self {
            info,
            structures_info,
            name,
            entries,
            tagged_unions: TaggedUnions::new(),
            max_size: None,
            size: None,
            max_size_deps: ClosureDeps::empty(),
        })
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let info = self.info.clone();
        let structures_info = self.structures_info.transform_strings(repl);
        let name = repl.transform(&self.name).into_owned();
        let entries = Vec::from_iter(self.entries.iter().map(|e| e.transform_strings(repl)));
        Self {
            info,
            structures_info,
            name,
            entries,
            tagged_unions: self.tagged_unions.clone(),
            max_size: self.max_size.clone(),
            size: self.size.clone(),
            max_size_deps: self.max_size_deps.clone(),
        }
    }

    pub(super) fn expand_alg_macro(
        &mut self,
        alg_registry: &AlgorithmRegistry,
        re_alg_macro_invocation: &Regex,
    ) -> Vec<UnionTable> {
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

    pub fn lookup_member(&self, selector: &str) -> Option<usize> {
        self.entries.iter().position(|e| {
            if let Some(e_selector) = e.selector.as_ref() {
                e_selector == selector
            } else {
                false
            }
        })
    }
}
