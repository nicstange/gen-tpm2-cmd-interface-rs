// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A "Structure" table as found in TCG TPM2 Part 2 "Structures".
use super::super::commands::CommandTable;
use super::super::commands::ResponseTable;
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
    StructuresPartTablesBitsIndex, StructuresPartTablesConstantIndex,
    StructuresPartTablesConstantsIndex, StructuresPartTablesIndex,
    StructuresPartTablesStructureIndex, StructuresPartTablesTypeIndex,
    StructuresPartTablesUnionIndex,
};
use super::value_range::ValueRange;
use regex::Regex;
use std::io;

#[derive(Copy, Clone, Debug)]
pub enum StructureTableEntryResolvedBaseType {
    Predefined(PredefinedTypeRef),
    Constants(StructuresPartTablesConstantsIndex),
    Bits(StructuresPartTablesBitsIndex),
    Type(StructuresPartTablesTypeIndex),
    Structure(StructuresPartTablesStructureIndex),
}

impl TryFrom<StructureTableEntryResolvedBaseType> for StructuresPartTablesIndex {
    type Error = ();

    fn try_from(value: StructureTableEntryResolvedBaseType) -> Result<Self, Self::Error> {
        match value {
            StructureTableEntryResolvedBaseType::Predefined(_) => Err(()),
            StructureTableEntryResolvedBaseType::Constants(i) => Ok(Self::Constants(i)),
            StructureTableEntryResolvedBaseType::Bits(i) => Ok(Self::Bits(i)),
            StructureTableEntryResolvedBaseType::Type(i) => Ok(Self::Type(i)),
            StructureTableEntryResolvedBaseType::Structure(i) => Ok(Self::Structure(i)),
        }
    }
}

impl TryFrom<StructuresPartTablesIndex> for StructureTableEntryResolvedBaseType {
    type Error = ();

    fn try_from(value: StructuresPartTablesIndex) -> Result<Self, Self::Error> {
        match value {
            StructuresPartTablesIndex::Aliases(_) => Err(()),
            StructuresPartTablesIndex::Constants(i) => Ok(Self::Constants(i)),
            StructuresPartTablesIndex::Bits(i) => Ok(Self::Bits(i)),
            StructuresPartTablesIndex::Type(i) => Ok(Self::Type(i)),
            StructuresPartTablesIndex::Structure(i) => Ok(Self::Structure(i)),
            StructuresPartTablesIndex::Union(_) => Err(()),
        }
    }
}

impl From<StructureTableEntryResolvedDiscriminantType> for StructureTableEntryResolvedBaseType {
    fn from(value: StructureTableEntryResolvedDiscriminantType) -> Self {
        match value {
            StructureTableEntryResolvedDiscriminantType::Constants(index) => {
                StructureTableEntryResolvedBaseType::Constants(index)
            }
            StructureTableEntryResolvedDiscriminantType::Type(index) => {
                StructureTableEntryResolvedBaseType::Type(index)
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum StructureTableEntryResolvedDiscriminantType {
    Constants(StructuresPartTablesConstantsIndex),
    Type(StructuresPartTablesTypeIndex),
}

impl StructureTableEntryResolvedDiscriminantType {
    pub(super) fn get_raw(&self) -> usize {
        match self {
            Self::Constants(index) => index.0,
            Self::Type(index) => index.0,
        }
    }
}

impl TryFrom<StructureTableEntryResolvedBaseType> for StructureTableEntryResolvedDiscriminantType {
    type Error = ();

    fn try_from(value: StructureTableEntryResolvedBaseType) -> Result<Self, Self::Error> {
        match value {
            StructureTableEntryResolvedBaseType::Predefined(_) => Err(()),
            StructureTableEntryResolvedBaseType::Constants(i) => Ok(Self::Constants(i)),
            StructureTableEntryResolvedBaseType::Bits(_) => Err(()),
            StructureTableEntryResolvedBaseType::Type(i) => Ok(Self::Type(i)),
            StructureTableEntryResolvedBaseType::Structure(_) => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StructureTableEntryPlainType {
    pub base_type: String,
    pub base_type_conditional: bool,
    pub base_type_enable_conditional: bool,
    pub range: Option<ValueRange>,
    pub is_size_specifier: bool,
    pub resolved_base_type: Option<StructureTableEntryResolvedBaseType>,
}

impl StructureTableEntryPlainType {
    fn new(
        base_type: String,
        base_type_conditional: bool,
        base_type_enable_conditional: bool,
        range: Option<ValueRange>,
        is_size_specifier: bool,
    ) -> Self {
        Self {
            base_type,
            base_type_conditional,
            base_type_enable_conditional,
            range,
            is_size_specifier,
            resolved_base_type: None,
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        Self {
            base_type: repl.transform(&self.base_type).into_owned(),
            base_type_conditional: self.base_type_conditional,
            base_type_enable_conditional: self.base_type_enable_conditional,
            range: self.range.as_ref().map(|r| r.transform_strings(repl)),
            is_size_specifier: self.is_size_specifier,
            resolved_base_type: self.resolved_base_type,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StructureTableEntryDiscriminantType {
    pub discriminant_type: String,
    pub discriminant_type_conditional: bool,
    pub discriminant_type_enable_conditional: bool,
    pub resolved_discriminant_type: Option<StructureTableEntryResolvedDiscriminantType>,
    pub discriminated_union_members: Vec<usize>,
    pub conditional_selects_none: bool,
}

impl StructureTableEntryDiscriminantType {
    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        Self {
            discriminant_type: repl.transform(&self.discriminant_type).into_owned(),
            discriminant_type_conditional: self.discriminant_type_conditional,
            discriminant_type_enable_conditional: self.discriminant_type_enable_conditional,
            resolved_discriminant_type: self.resolved_discriminant_type,
            discriminated_union_members: self.discriminated_union_members.clone(),
            conditional_selects_none: self.conditional_selects_none,
        }
    }
}

impl TryFrom<StructureTableEntryPlainType> for StructureTableEntryDiscriminantType {
    type Error = ();

    fn try_from(value: StructureTableEntryPlainType) -> Result<Self, Self::Error> {
        if value.range.is_some() || value.is_size_specifier {
            return Err(());
        }

        let resolved_discriminant_type = match value.resolved_base_type {
            Some(resolved_base_type) => Some(
                StructureTableEntryResolvedDiscriminantType::try_from(resolved_base_type)?,
            ),
            None => None,
        };

        Ok(Self {
            discriminant_type: value.base_type,
            discriminant_type_conditional: value.base_type_conditional,
            discriminant_type_enable_conditional: value.base_type_enable_conditional,
            resolved_discriminant_type,
            discriminated_union_members: Vec::new(),
            conditional_selects_none: false,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StructureTableEntryUnionType {
    pub union_type: String,
    pub discriminant: String,
    pub resolved_union_type: Option<StructuresPartTablesUnionIndex>,
    pub resolved_discriminant: Option<usize>,
}

impl StructureTableEntryUnionType {
    fn new(union_type: String, discriminant: String) -> Self {
        Self {
            union_type,
            discriminant,
            resolved_union_type: None,
            resolved_discriminant: None,
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        Self {
            union_type: repl.transform(&self.union_type).into_owned(),
            discriminant: repl.transform(&self.discriminant).into_owned(),
            resolved_union_type: self.resolved_union_type,
            resolved_discriminant: self.resolved_discriminant,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StructureTableEntryArrayType {
    pub element_type: String,
    pub element_type_conditional: bool,
    pub element_type_enable_conditional: bool,
    pub size: Expr,
    pub size_range: Option<ValueRange>,
    pub resolved_element_type: Option<StructureTableEntryResolvedBaseType>,
}

impl StructureTableEntryArrayType {
    fn new(
        element_type: String,
        element_type_conditional: bool,
        element_type_enable_conditional: bool,
        size: Expr,
        size_range: Option<ValueRange>,
    ) -> Self {
        Self {
            element_type,
            element_type_conditional,
            element_type_enable_conditional,
            size,
            size_range,
            resolved_element_type: None,
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        Self {
            element_type: repl.transform(&self.element_type).into_owned(),
            element_type_conditional: self.element_type_conditional,
            element_type_enable_conditional: self.element_type_enable_conditional,
            size: self.size.transform_strings(repl),
            size_range: self.size_range.as_ref().map(|r| r.transform_strings(repl)),
            resolved_element_type: self.resolved_element_type,
        }
    }
}

#[derive(Clone, Debug)]
pub enum StructureTableEntryType {
    Plain(StructureTableEntryPlainType),
    Discriminant(StructureTableEntryDiscriminantType),
    Union(StructureTableEntryUnionType),
    Array(StructureTableEntryArrayType),
}

impl StructureTableEntryType {
    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        match self {
            Self::Plain(t) => Self::Plain(t.transform_strings(repl)),
            Self::Discriminant(t) => Self::Discriminant(t.transform_strings(repl)),
            Self::Union(t) => Self::Union(t.transform_strings(repl)),
            Self::Array(t) => Self::Array(t.transform_strings(repl)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StructureTableEntry {
    pub name: String,
    pub entry_type: StructureTableEntryType,
    pub deps: ConfigDeps,
}

impl StructureTableEntry {
    fn new(name: String, entry_type: StructureTableEntryType) -> Self {
        Self {
            name,
            entry_type,
            deps: ConfigDeps::new(),
        }
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let name = repl.transform(&self.name).into_owned();
        let entry_type = self.entry_type.transform_strings(repl);
        let deps = self.deps.transform_strings(repl);
        Self {
            name,
            entry_type,
            deps,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StructureTable {
    pub info: CommonTableInfo,
    pub structures_info: CommonStructuresTableInfo,
    pub name: String,
    pub error_rc: Option<String>,
    pub entries: Vec<StructureTableEntry>,
    pub conditional: bool,
    pub is_command_response_params: bool,

    pub resolved_error_rc: Option<StructuresPartTablesConstantIndex>,
    pub max_size: Option<ExprValue>,
    pub size: Option<ExprValue>,
    pub closure_deps: ClosureDeps,
    pub closure_deps_conditional: ClosureDeps,
}

impl StructureTable {
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
        if col_headers.len() < 2 {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if name == "TPM2B_TIMEOUT" && col_headers[0] == "Type" && col_headers[1] == "Name" {
            // Table 88, the defintition of TPM2B_TIMEOUT, from TCG TPM2 spec part 2 "Structures" got
            // the column headers wrongly interchanged. Accept it nonetheless in this specific case.
        } else if col_headers[0] != "Parameter" && col_headers[0] != "Name" {
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
        }

        let mut error_rc = None;
        let mut entries = Vec::new();
        let mut conditional = false;
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
                        "error: {}:{}: no name specified for struct member entry",
                        filename, header_row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }

            // Some struct member fields are "commented out" in the spec, skip those.
            if name.starts_with("//") {
                continue;
            }

            if let Some(name) = name.strip_prefix('#') {
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

            let mut base_type = cols[1];
            let mut base_type_conditional = false;
            base_type = match base_type.strip_prefix('+') {
                Some(base_type) => {
                    base_type_conditional = true;
                    base_type.trim_start()
                }
                None => base_type,
            };
            let mut base_type_enable_conditional = false;
            base_type = match base_type.strip_suffix('+') {
                Some(base_type) => {
                    base_type_enable_conditional = true;
                    base_type.trim_end()
                }
                None => base_type,
            };
            if base_type_conditional && base_type_enable_conditional {
                eprintln!(
                    "error: {}:{}: inconsistent base type conditionality",
                    filename, header_row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if base_type_conditional {
                conditional = true;
            }
            if base_type.is_empty() {
                eprintln!(
                    "error: {}:{}: no base type specified for structure entry",
                    filename, header_row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
            let report_alg_finder_error =
                |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
            alg_macro_finder
                .search(base_type)
                .map_err(report_alg_finder_error)?;

            let captures = match regexps_cache.re_struct_member_name.captures(name) {
                None => {
                    eprintln!(
                        "error: {}:{}: unrecognized struct member name format",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                Some(captures) => captures,
            };

            let name = captures.name("NAME").unwrap().as_str();
            let alg_macro_in_name = alg_macro_finder
                .search(name)
                .map_err(report_alg_finder_error)?;
            let (name, entry_type) = if let Some(discriminant) = captures.name("DISCR") {
                if base_type_conditional || base_type_enable_conditional {
                    eprintln!(
                        "error: {}:{}: conditional union types unsupported",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                if captures.name("IS_SIZE_SPEC").is_some()
                    || captures.name("ARRAYSIZE").is_some()
                    || captures.name("RANGE").is_some()
                {
                    eprintln!(
                        "error: {}:{}: conflicting specifications in struct member name",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                let discriminant = discriminant.as_str();
                alg_macro_finder
                    .search(discriminant)
                    .map_err(report_alg_finder_error)?;
                if !header_alg_macro_finder.found_any()
                    && alg_macro_finder.found_any()
                    && !alg_macro_in_name
                {
                    eprintln!("error: {}:{}: no algorithm macro invocation in expanded struct member's name",
                                   filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                    &alg_macro_finder,
                    header_alg_macro_finder.found_any(),
                );
                let name = alg_macro_normalizer.normalize(name);
                let base_type = alg_macro_normalizer.normalize(base_type).into_owned();
                let discriminant = alg_macro_normalizer.normalize(discriminant).into_owned();

                let entry_type = StructureTableEntryUnionType::new(base_type, discriminant);
                let entry_type = StructureTableEntryType::Union(entry_type);

                (name, entry_type)
            } else if let Some(size) = captures.name("ARRAYSIZE") {
                let size = size.as_str();
                alg_macro_finder
                    .search(size)
                    .map_err(report_alg_finder_error)?;
                let size_range = captures.name("RANGE").map(|capture| capture.as_str());
                if let Some(size_range) = size_range {
                    alg_macro_finder
                        .search(size_range)
                        .map_err(report_alg_finder_error)?;
                }
                if !header_alg_macro_finder.found_any()
                    && alg_macro_finder.found_any()
                    && !alg_macro_in_name
                {
                    eprintln!("error: {}:{}: no algorithm macro invocation in expanded struct member's name",
                                      filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                    &alg_macro_finder,
                    header_alg_macro_finder.found_any(),
                );
                let name = alg_macro_normalizer.normalize(name);
                let base_type = alg_macro_normalizer.normalize(base_type).into_owned();
                let size = alg_macro_normalizer.normalize(size);
                let size_range = size_range.map(|r| alg_macro_normalizer.normalize(r));

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
                let size_range = match size_range {
                    Some(range) => Some(
                        ValueRange::new_from_csv(filename, row.0, &range)?
                            .unwrap()
                            .0,
                    ),
                    None => None,
                };

                let entry_type = StructureTableEntryArrayType::new(
                    base_type,
                    base_type_conditional,
                    base_type_enable_conditional,
                    size,
                    size_range,
                );
                let entry_type = StructureTableEntryType::Array(entry_type);

                (name, entry_type)
            } else {
                let range = captures.name("RANGE").map(|capture| capture.as_str());
                if let Some(range) = range {
                    alg_macro_finder
                        .search(range)
                        .map_err(report_alg_finder_error)?;
                }
                if !header_alg_macro_finder.found_any()
                    && alg_macro_finder.found_any()
                    && !alg_macro_in_name
                {
                    eprintln!("error: {}:{}: no algorithm macro invocation in expanded struct member's name",
                                      filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                let mut alg_macro_normalizer = AlgMacroInvocationNormalizer::new(
                    &alg_macro_finder,
                    header_alg_macro_finder.found_any(),
                );
                let name = alg_macro_normalizer.normalize(name);
                let base_type = alg_macro_normalizer.normalize(base_type).into_owned();
                let range = range.map(|r| alg_macro_normalizer.normalize(r));

                let range = match range {
                    Some(range) => Some(
                        ValueRange::new_from_csv(filename, row.0, &range)?
                            .unwrap()
                            .0,
                    ),
                    None => None,
                };
                let is_size_specifier = captures.name("IS_SIZESPEC").is_some();

                let entry_type = StructureTableEntryPlainType::new(
                    base_type,
                    base_type_conditional,
                    base_type_enable_conditional,
                    range,
                    is_size_specifier,
                );
                let entry_type = StructureTableEntryType::Plain(entry_type);

                (name, entry_type)
            };

            entries.push(StructureTableEntry::new(name.into_owned(), entry_type));
        }

        Ok(Self {
            info,
            structures_info,
            name,
            error_rc,
            entries,
            conditional,
            is_command_response_params: false,
            resolved_error_rc: None,
            max_size: None,
            size: None,
            closure_deps: ClosureDeps::empty(),
            closure_deps_conditional: ClosureDeps::empty(),
        })
    }

    pub(super) fn new_from_command(cmd: &CommandTable) -> (Option<Self>, Option<Self>) {
        let handles = if !cmd.handles.is_empty() {
            let mut handles = Vec::new();
            for handle in cmd.handles.iter() {
                let handle_type = StructureTableEntryPlainType::new(
                    handle.handle_type.to_owned(),
                    false,
                    handle.handle_type_enable_conditional,
                    None,
                    false,
                );
                let handle_type = StructureTableEntryType::Plain(handle_type);
                handles.push(StructureTableEntry {
                    name: handle.name.clone(),
                    entry_type: handle_type,
                    deps: ConfigDeps::new(),
                });
            }
            let info = cmd.info.clone();
            let structures_info = CommonStructuresTableInfo::new();
            let name = cmd.name.clone() + "_COMMAND_HANDLES";
            Some(Self {
                info,
                structures_info,
                name,
                error_rc: None,
                entries: handles,
                conditional: false,
                is_command_response_params: false,
                resolved_error_rc: None,
                max_size: None,
                size: None,
                closure_deps: ClosureDeps::empty(),
                closure_deps_conditional: ClosureDeps::empty(),
            })
        } else {
            None
        };

        let params = if !cmd.params.is_empty() {
            let mut params = Vec::new();
            for param in cmd.params.iter() {
                let param_type = StructureTableEntryPlainType::new(
                    param.param_type.to_owned(),
                    false,
                    param.param_type_enable_conditional,
                    None,
                    false,
                );
                let param_type = StructureTableEntryType::Plain(param_type);
                params.push(StructureTableEntry {
                    name: param.name.clone(),
                    entry_type: param_type,
                    deps: ConfigDeps::new(),
                });
            }
            let info = cmd.info.clone();
            let structures_info = CommonStructuresTableInfo::new();
            let name = cmd.name.clone() + "_COMMAND_PARAMS";
            Some(Self {
                info,
                structures_info,
                name,
                error_rc: None,
                entries: params,
                conditional: false,
                is_command_response_params: true,
                resolved_error_rc: None,
                max_size: None,
                size: None,
                closure_deps: ClosureDeps::empty(),
                closure_deps_conditional: ClosureDeps::empty(),
            })
        } else {
            None
        };

        (handles, params)
    }

    pub(super) fn new_from_response(resp: &ResponseTable) -> (Option<Self>, Option<Self>) {
        let handles = if !resp.handles.is_empty() {
            let mut handles = Vec::new();
            for handle in resp.handles.iter() {
                let handle_type = StructureTableEntryPlainType::new(
                    handle.handle_type.to_owned(),
                    false,
                    handle.handle_type_enable_conditional,
                    None,
                    false,
                );
                let handle_type = StructureTableEntryType::Plain(handle_type);
                handles.push(StructureTableEntry {
                    name: handle.name.clone(),
                    entry_type: handle_type,
                    deps: ConfigDeps::new(),
                });
            }
            let info = resp.info.clone();
            let structures_info = CommonStructuresTableInfo::new();
            let name = resp.name.clone() + "_RESPONSE_HANDLES";
            Some(Self {
                info,
                structures_info,
                name,
                error_rc: None,
                entries: handles,
                conditional: false,
                is_command_response_params: false,
                resolved_error_rc: None,
                max_size: None,
                size: None,
                closure_deps: ClosureDeps::empty(),
                closure_deps_conditional: ClosureDeps::empty(),
            })
        } else {
            None
        };

        let params = if !resp.params.is_empty() {
            let mut params = Vec::new();
            for param in resp.params.iter() {
                let param_type = StructureTableEntryPlainType::new(
                    param.param_type.to_owned(),
                    false,
                    param.param_type_enable_conditional,
                    None,
                    false,
                );
                let param_type = StructureTableEntryType::Plain(param_type);
                params.push(StructureTableEntry {
                    name: param.name.clone(),
                    entry_type: param_type,
                    deps: ConfigDeps::new(),
                });
            }
            let info = resp.info.clone();
            let structures_info = CommonStructuresTableInfo::new();
            let name = resp.name.clone() + "_RESPONSE_PARAMS";
            Some(Self {
                info,
                structures_info,
                name,
                error_rc: None,
                entries: params,
                conditional: false,
                is_command_response_params: true,
                resolved_error_rc: None,
                max_size: None,
                size: None,
                closure_deps: ClosureDeps::empty(),
                closure_deps_conditional: ClosureDeps::empty(),
            })
        } else {
            None
        };

        (handles, params)
    }

    fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let info = self.info.clone();
        let structures_info = self.structures_info.transform_strings(repl);
        let name = repl.transform(&self.name).into_owned();
        let error_rc = self
            .error_rc
            .as_ref()
            .map(|s| repl.transform(s).into_owned());
        let entries = Vec::from_iter(self.entries.iter().map(|e| e.transform_strings(repl)));
        Self {
            info,
            structures_info,
            name,
            error_rc,
            entries,
            conditional: self.conditional,
            is_command_response_params: self.is_command_response_params,
            resolved_error_rc: self.resolved_error_rc,
            max_size: self.max_size.clone(),
            size: self.size.clone(),
            closure_deps: self.closure_deps.clone(),
            closure_deps_conditional: self.closure_deps_conditional.clone(),
        }
    }

    pub(super) fn expand_alg_macro(
        &mut self,
        alg_registry: &AlgorithmRegistry,
        re_alg_macro_invocation: &Regex,
    ) -> Vec<StructureTable> {
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

    pub fn can_crypt(&self) -> bool {
        if self.entries.is_empty() {
            return false;
        }

        // First field must be a UINT16 and serve as a size specifier. Meaning
        // it is either explicitly annotated as such or that it is the length
        // specifier of the one and only subsequent byte array member in the
        // structure.
        match &self.entries[0].entry_type {
            StructureTableEntryType::Plain(plain_type) => {
                match plain_type.resolved_base_type.unwrap() {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        if predefined.bits != 16 || predefined.signed {
                            return false;
                        }
                    }
                    _ => return false,
                };
                if plain_type.is_size_specifier {
                    return true;
                }
            }
            _ => return false,
        };

        if self.entries.len() != 2 {
            return false;
        }

        match &self.entries[1].entry_type {
            StructureTableEntryType::Array(array_type) => {
                match array_type.resolved_element_type.unwrap() {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        if predefined.bits == 8 && !predefined.signed {
                            match &array_type.size.op {
                                ExprOp::Id(id) => {
                                    matches!(id.resolved.unwrap(), ExprResolvedId::StructMember(0))
                                }
                                _ => false,
                            }
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}
