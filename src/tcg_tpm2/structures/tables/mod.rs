// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A collection of TCG TPM2 Part 2 "Structures" tables.

use std::borrow::Borrow;
use std::cell::RefMut;
use std::io;
use std::iter;

use crate::tcg_tpm2::structures::predefined::PredefinedConstantRef;
use crate::tcg_tpm2::structures::predefined::PredefinedConstants;
use regex::Regex;
use std::borrow;
use std::cell;
use std::collections::HashMap;
use std::ops::Deref;

use super::super::commands::CommandTable;
use super::super::commands::ResponseTable;
use super::algs::AlgorithmRegistry;
use super::aliases_table::{AliasesTable, AliasesTableEntry};
use super::bits_table::{BitsTable, BitsTableResolvedBase};
use super::constants_table::{ConstantsTable, ConstantsTableEntry};
use super::deps::ConfigDeps;
use super::eccdefines_table::EccDefinesTable;
use super::expr::{Expr, ExprOp, ExprResolvedId, ExprResolvedType, ExprValue};
use super::hashdefines_table::HashDefinesTable;
use super::structure_table::{
    StructureTable, StructureTableEntryResolvedBaseType,
    StructureTableEntryResolvedDiscriminantType, StructureTableEntryType,
};
use super::symcipherdefines_table::SymcipherDefinesTable;
use super::table_common::{ClosureDeps, ClosureDepsFlags};
use super::type_table::{TypeTable, TypeTableEntry};
use super::union_table::{UnionTable, UnionTableEntry, UnionTableEntryType};
use super::value_range::ValueRange;

mod eval_impl;
mod resolve_impl;

#[derive(Clone, Debug)]
pub enum StructuresPartTable {
    Constants(ConstantsTable),
    Bits(BitsTable),
    Type(TypeTable),
    Structure(StructureTable),
    Union(UnionTable),
    Aliases(AliasesTable),
}

#[derive(Debug)]
pub struct StructuresPartTables {
    pub tables: Vec<cell::RefCell<StructuresPartTable>>,

    pub alg_registry: Option<AlgorithmRegistry>,

    ecc_defines: Vec<EccDefinesTable>,
    hash_defines: Vec<HashDefinesTable>,
    symcipher_defines: Vec<SymcipherDefinesTable>,

    name_to_structure: HashMap<String, StructuresPartTablesIndex>,
    name_to_constant: HashMap<String, StructuresPartTablesConstantIndex>,
    name_to_alias: HashMap<String, StructuresPartTablesAliasIndex>,
    name_to_cppdefine: HashMap<String, String>,

    re_alg_macro_invocation: Regex,

    pub predefined_constants_deps: HashMap<&'static str, ClosureDeps>,
}

impl StructuresPartTables {
    pub(in super::super) fn new(re_alg_macro_invocation: &Regex) -> Self {
        Self {
            tables: Vec::new(),
            alg_registry: None,
            ecc_defines: Vec::new(),
            hash_defines: Vec::new(),
            symcipher_defines: Vec::new(),
            name_to_structure: HashMap::new(),
            name_to_constant: HashMap::new(),
            name_to_alias: HashMap::new(),
            name_to_cppdefine: HashMap::new(),
            re_alg_macro_invocation: re_alg_macro_invocation.clone(),
            predefined_constants_deps: HashMap::new(),
        }
    }

    pub(in super::super) fn push_constants_table(
        &mut self,
        mut table: ConstantsTable,
    ) -> Result<(), io::Error> {
        // Once the alg_registry is available, expand !ALG macro invocations
        // right at table addition and register (potentially expanded names with
        // the lookup maps.
        if let Some(alg_registry) = &self.alg_registry {
            let mut expanded = table.expand_alg_macro(alg_registry, &self.re_alg_macro_invocation);
            // If the macro expansion yielded some new tables, skip the original.
            let skip_orig = !expanded.is_empty();
            let new_tables = iter::once(table)
                .chain(expanded.drain(..))
                .skip(skip_orig as usize);
            for table in new_tables {
                // This will become the current table's index.
                let i = StructuresPartTablesConstantsIndex(self.tables.len());
                self.register_constants_name(&table.name, i)?;
                self.register_constant_names(i, &table)?;
                self.tables
                    .push(cell::RefCell::new(StructuresPartTable::Constants(table)));
            }
        } else {
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Constants(table)));
        }

        Ok(())
    }

    pub(in super::super) fn push_bits_table(
        &mut self,
        mut table: BitsTable,
    ) -> Result<(), io::Error> {
        // Once the alg_registry is available, expand !ALG macro invocations
        // right at table addition and register (potentially expanded names with
        // the lookup maps.
        if let Some(alg_registry) = &self.alg_registry {
            let mut expanded = table.expand_alg_macro(alg_registry, &self.re_alg_macro_invocation);
            // If the macro expansion yielded some new tables, skip the original.
            let skip_orig = !expanded.is_empty();
            let new_tables = iter::once(table)
                .chain(expanded.drain(..))
                .skip(skip_orig as usize);
            for table in new_tables {
                // This will become the current table's index.
                let i = StructuresPartTablesBitsIndex(self.tables.len());
                self.register_bits_name(&table.name, i)?;
                self.tables
                    .push(cell::RefCell::new(StructuresPartTable::Bits(table)));
            }
        } else {
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Bits(table)));
        }

        Ok(())
    }

    pub(in super::super) fn push_type_table(
        &mut self,
        mut table: TypeTable,
    ) -> Result<(), io::Error> {
        // Once the alg_registry is available, expand !ALG macro invocations
        // right at table addition and register (potentially expanded names with
        // the lookup maps.
        if let Some(alg_registry) = &self.alg_registry {
            let mut expanded = table.expand_alg_macro(alg_registry, &self.re_alg_macro_invocation);
            // If the macro expansion yielded some new tables, skip the original.
            let skip_orig = !expanded.is_empty();
            let new_tables = iter::once(table)
                .chain(expanded.drain(..))
                .skip(skip_orig as usize);
            for table in new_tables {
                // This will become the current table's index.
                let i = StructuresPartTablesTypeIndex(self.tables.len());
                self.register_type_name(&table.name, i)?;
                self.tables
                    .push(cell::RefCell::new(StructuresPartTable::Type(table)));
            }
        } else {
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Type(table)));
        }

        Ok(())
    }

    pub(in super::super) fn push_structure_table(
        &mut self,
        mut table: StructureTable,
    ) -> Result<(), io::Error> {
        // Once the alg_registry is available, expand !ALG macro invocations
        // right at table addition and register (potentially expanded names with
        // the lookup maps.
        if let Some(alg_registry) = &self.alg_registry {
            let mut expanded = table.expand_alg_macro(alg_registry, &self.re_alg_macro_invocation);
            // If the macro expansion yielded some new tables, skip the original.
            let skip_orig = !expanded.is_empty();
            let new_tables = iter::once(table)
                .chain(expanded.drain(..))
                .skip(skip_orig as usize);
            for table in new_tables {
                // This will become the current table's index.
                let i = StructuresPartTablesStructureIndex(self.tables.len());
                self.register_structure_name(&table.name, i)?;
                self.tables
                    .push(cell::RefCell::new(StructuresPartTable::Structure(table)));
            }
        } else {
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Structure(table)));
        }

        Ok(())
    }

    pub(in super::super) fn push_union_table(
        &mut self,
        mut table: UnionTable,
    ) -> Result<(), io::Error> {
        // Once the alg_registry is available, expand !ALG macro invocations
        // right at table addition and register (potentially expanded names with
        // the lookup maps.
        if let Some(alg_registry) = &self.alg_registry {
            let mut expanded = table.expand_alg_macro(alg_registry, &self.re_alg_macro_invocation);
            // If the macro expansion yielded some new tables, skip the original.
            let skip_orig = !expanded.is_empty();
            let new_tables = iter::once(table)
                .chain(expanded.drain(..))
                .skip(skip_orig as usize);
            for table in new_tables {
                // This will become the current table's index.
                let i = StructuresPartTablesUnionIndex(self.tables.len());
                self.register_union_name(&table.name, i)?;
                self.tables
                    .push(cell::RefCell::new(StructuresPartTable::Union(table)));
            }
        } else {
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Union(table)));
        }

        Ok(())
    }

    pub(in super::super) fn push_aliases_table(
        &mut self,
        mut table: AliasesTable,
    ) -> Result<(), io::Error> {
        // Once the alg_registry is available, expand !ALG macro invocations
        // right at table addition and register (potentially expanded names with
        // the lookup maps.
        if let Some(alg_registry) = &self.alg_registry {
            let mut expanded = table.expand_alg_macro(alg_registry, &self.re_alg_macro_invocation);
            // If the macro expansion yielded some new tables, skip the original.
            let skip_orig = !expanded.is_empty();
            let new_tables = iter::once(table)
                .chain(expanded.drain(..))
                .skip(skip_orig as usize);
            for table in new_tables {
                // This will become the current table's index.
                let i = StructuresPartTablesAliasesIndex(self.tables.len());
                self.register_alias_names(i, &table)?;
                self.tables
                    .push(cell::RefCell::new(StructuresPartTable::Aliases(table)));
            }
        } else {
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Aliases(table)));
        }

        Ok(())
    }

    pub(in super::super) fn set_alg_registry(
        &mut self,
        alg_registry: AlgorithmRegistry,
    ) -> Result<(), io::Error> {
        if self.alg_registry.is_some() {
            eprintln!("error: multiple algorithm registry tables (TPM_ALG_ID)");
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        // Once the algorithm registry has been extracted from the TPM_ALG_ID table,
        // the !ALG macro invocations in existing tables can get expanded.
        let mut i = 0;
        while i < self.tables.len() {
            let mut expanded = match self.tables[i].get_mut() {
                StructuresPartTable::Constants(t) => t
                    .expand_alg_macro(&alg_registry, &self.re_alg_macro_invocation)
                    .drain(..)
                    .map(StructuresPartTable::Constants)
                    .collect::<Vec<StructuresPartTable>>(),
                StructuresPartTable::Bits(t) => t
                    .expand_alg_macro(&alg_registry, &self.re_alg_macro_invocation)
                    .drain(..)
                    .map(StructuresPartTable::Bits)
                    .collect(),
                StructuresPartTable::Type(t) => t
                    .expand_alg_macro(&alg_registry, &self.re_alg_macro_invocation)
                    .drain(..)
                    .map(StructuresPartTable::Type)
                    .collect(),
                StructuresPartTable::Structure(t) => t
                    .expand_alg_macro(&alg_registry, &self.re_alg_macro_invocation)
                    .drain(..)
                    .map(StructuresPartTable::Structure)
                    .collect(),
                StructuresPartTable::Union(t) => t
                    .expand_alg_macro(&alg_registry, &self.re_alg_macro_invocation)
                    .drain(..)
                    .map(StructuresPartTable::Union)
                    .collect(),
                StructuresPartTable::Aliases(t) => t
                    .expand_alg_macro(&alg_registry, &self.re_alg_macro_invocation)
                    .drain(..)
                    .map(StructuresPartTable::Aliases)
                    .collect(),
            };

            if expanded.is_empty() {
                i += 1;
                continue;
            }

            let n = expanded.len();
            self.tables
                .splice(i..i + 1, expanded.drain(..).map(cell::RefCell::new));
            i += n;
        }

        self.alg_registry = Some(alg_registry);

        // And finally, once the !ALG macro has been expanded on existing tables and will
        // be expanded immediately on tables added in the future, the lookup
        // tables start getting populating.
        let mut tables = std::mem::take(&mut self.tables);
        for table in tables.drain(..) {
            match table.into_inner() {
                StructuresPartTable::Constants(table) => {
                    self.push_constants_table(table)?;
                }
                StructuresPartTable::Bits(table) => {
                    self.push_bits_table(table)?;
                }
                StructuresPartTable::Type(table) => {
                    self.push_type_table(table)?;
                }
                StructuresPartTable::Structure(table) => {
                    self.push_structure_table(table)?;
                }
                StructuresPartTable::Union(table) => {
                    self.push_union_table(table)?;
                }
                StructuresPartTable::Aliases(table) => {
                    self.push_aliases_table(table)?;
                }
            };
        }

        Ok(())
    }

    pub(in super::super) fn push_ecc_defines_table(
        &mut self,
        table: EccDefinesTable,
    ) -> Result<(), io::Error> {
        if self.lookup_ecc_defines_table(&table.curve_id).is_some() {
            eprintln!(
                "error: multiple ECC curve definitions of \"{}\"",
                &table.curve_id
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.ecc_defines.push(table);
        Ok(())
    }

    pub fn lookup_ecc_defines_table(&self, curve_id: &str) -> Option<&EccDefinesTable> {
        self.ecc_defines.iter().find(|t| t.curve_id == curve_id)
    }

    pub(in super::super) fn push_hash_defines_table(
        &mut self,
        table: HashDefinesTable,
    ) -> Result<(), io::Error> {
        if self.lookup_hash_defines_table(&table.name).is_some() {
            eprintln!("error: multiple hash definitions of \"{}\"", &table.name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.hash_defines.push(table);
        Ok(())
    }

    pub fn lookup_hash_defines_table(&self, name: &str) -> Option<&HashDefinesTable> {
        self.hash_defines.iter().find(|t| t.name == name)
    }

    pub(in super::super) fn push_symcipher_defines_table(
        &mut self,
        table: SymcipherDefinesTable,
    ) -> Result<(), io::Error> {
        if self.lookup_symcipher_defines_table(&table.name).is_some() {
            eprintln!(
                "error: multiple symmetric cipher definitions of \"{}\"",
                &table.name
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.symcipher_defines.push(table);
        Ok(())
    }

    pub fn lookup_symcipher_defines_table(&self, name: &str) -> Option<&SymcipherDefinesTable> {
        self.symcipher_defines.iter().find(|t| t.name == name)
    }

    fn register_constants_name(
        &mut self,
        name: &str,
        i: StructuresPartTablesConstantsIndex,
    ) -> Result<(), io::Error> {
        if self.name_to_alias.contains_key(name) {
            eprintln!("error: multiple bindings for \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if self.name_to_structure.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_structure
            .insert(name.to_owned(), StructuresPartTablesIndex::Constants(i));
        Ok(())
    }

    fn register_bits_name(
        &mut self,
        name: &str,
        i: StructuresPartTablesBitsIndex,
    ) -> Result<(), io::Error> {
        if self.name_to_alias.contains_key(name) {
            eprintln!("error: multiple bindings for \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if self.name_to_structure.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_structure
            .insert(name.to_owned(), StructuresPartTablesIndex::Bits(i));
        Ok(())
    }

    fn register_type_name(
        &mut self,
        name: &str,
        i: StructuresPartTablesTypeIndex,
    ) -> Result<(), io::Error> {
        if self.name_to_alias.contains_key(name) {
            eprintln!("error: multiple bindings for \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if self.name_to_structure.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_structure
            .insert(name.to_owned(), StructuresPartTablesIndex::Type(i));
        Ok(())
    }

    fn register_structure_name(
        &mut self,
        name: &str,
        i: StructuresPartTablesStructureIndex,
    ) -> Result<(), io::Error> {
        if self.name_to_alias.contains_key(name) {
            eprintln!("error: multiple bindings for \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if self.name_to_structure.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_structure
            .insert(name.to_owned(), StructuresPartTablesIndex::Structure(i));
        Ok(())
    }

    fn register_union_name(
        &mut self,
        name: &str,
        i: StructuresPartTablesUnionIndex,
    ) -> Result<(), io::Error> {
        if self.name_to_alias.contains_key(name) {
            eprintln!("error: multiple bindings for \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if self.name_to_structure.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_structure
            .insert(name.to_owned(), StructuresPartTablesIndex::Union(i));
        Ok(())
    }

    fn register_constant_name(
        &mut self,
        name: &str,
        i: StructuresPartTablesConstantsIndex,
        j: usize,
    ) -> Result<(), io::Error> {
        if self.name_to_constant.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" constant", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_constant
            .insert(name.to_owned(), StructuresPartTablesConstantIndex(i, j));
        Ok(())
    }

    fn register_constant_names(
        &mut self,
        i: StructuresPartTablesConstantsIndex,
        table: &ConstantsTable,
    ) -> Result<(), io::Error> {
        for j in 0..table.entries.len() {
            self.register_constant_name(&table.entries[j].name, i, j)?;
        }
        Ok(())
    }

    fn register_alias_name(
        &mut self,
        name: &str,
        target: &str,
        i: StructuresPartTablesAliasesIndex,
        j: usize,
    ) -> Result<(), io::Error> {
        if self.name_to_structure.contains_key(name) {
            eprintln!("error: multiple bindings for \"{}\" type", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        // Check for loops
        let mut cur_index = self.name_to_alias.get(target);
        while let Some(cur) = cur_index {
            let cur_alias = self.get_alias(*cur);
            if cur_alias.target == name {
                eprintln!("error: type alias loop for \"{}\"", name);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            cur_index = self.name_to_alias.get(&cur_alias.target)
        }

        if self.name_to_alias.contains_key(name) {
            eprintln!("error: multiple definitions of \"{}\" type alias", name);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_alias
            .insert(name.to_owned(), StructuresPartTablesAliasIndex(i, j));
        Ok(())
    }

    fn register_alias_names(
        &mut self,
        i: StructuresPartTablesAliasesIndex,
        table: &AliasesTable,
    ) -> Result<(), io::Error> {
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            self.register_alias_name(&entry.name, &entry.target, i, j)?;
        }
        Ok(())
    }

    pub fn register_cppdefine(
        &mut self,
        name: String,
        replacement: String,
    ) -> Result<(), io::Error> {
        if self.name_to_cppdefine.contains_key(&name) {
            eprintln!(
                "error: multiple definitions of \"{}\" CPP-style define",
                name
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.name_to_cppdefine.insert(name, replacement);
        Ok(())
    }

    pub(in super::super) fn push_command_structures(
        &mut self,
        cmd: &CommandTable,
    ) -> [Option<StructuresPartTablesStructureIndex>; 2] {
        let mut indices = [None, None];
        let (handles, params) = StructureTable::new_from_command(cmd);
        if let Some(handles) = handles {
            indices[0] = Some(StructuresPartTablesStructureIndex(self.tables.len()));
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Structure(handles)));
        }
        if let Some(params) = params {
            indices[1] = Some(StructuresPartTablesStructureIndex(self.tables.len()));
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Structure(params)));
        }
        indices
    }

    pub(in super::super) fn push_response_structures(
        &mut self,
        resp: &ResponseTable,
    ) -> [Option<StructuresPartTablesStructureIndex>; 2] {
        let mut indices = [None, None];
        let (handles, params) = StructureTable::new_from_response(resp);
        if let Some(handles) = handles {
            indices[0] = Some(StructuresPartTablesStructureIndex(self.tables.len()));
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Structure(handles)));
        }
        if let Some(params) = params {
            indices[1] = Some(StructuresPartTablesStructureIndex(self.tables.len()));
            self.tables
                .push(cell::RefCell::new(StructuresPartTable::Structure(params)));
        }
        indices
    }

    pub fn get_constants(
        &self,
        index: StructuresPartTablesConstantsIndex,
    ) -> cell::Ref<ConstantsTable> {
        cell::Ref::map(self.tables[index.0].borrow(), |table| match table {
            StructuresPartTable::Constants(table) => table,
            _ => unreachable!(),
        })
    }

    fn get_constants_mut(
        &self,
        index: StructuresPartTablesConstantsIndex,
    ) -> cell::RefMut<ConstantsTable> {
        cell::RefMut::map(self.tables[index.0].borrow_mut(), |table| match table {
            StructuresPartTable::Constants(table) => table,
            _ => unreachable!(),
        })
    }

    pub fn get_bits(&self, index: StructuresPartTablesBitsIndex) -> cell::Ref<BitsTable> {
        cell::Ref::map(self.tables[index.0].borrow(), |table| match table {
            StructuresPartTable::Bits(table) => table,
            _ => unreachable!(),
        })
    }

    fn get_bits_mut(&self, index: StructuresPartTablesBitsIndex) -> cell::RefMut<BitsTable> {
        cell::RefMut::map(self.tables[index.0].borrow_mut(), |table| match table {
            StructuresPartTable::Bits(table) => table,
            _ => unreachable!(),
        })
    }

    pub fn get_type(&self, index: StructuresPartTablesTypeIndex) -> cell::Ref<TypeTable> {
        cell::Ref::map(self.tables[index.0].borrow(), |table| match table {
            StructuresPartTable::Type(table) => table,
            _ => unreachable!(),
        })
    }

    fn get_type_mut(&self, index: StructuresPartTablesTypeIndex) -> cell::RefMut<TypeTable> {
        cell::RefMut::map(self.tables[index.0].borrow_mut(), |table| match table {
            StructuresPartTable::Type(table) => table,
            _ => unreachable!(),
        })
    }

    pub fn get_structure(
        &self,
        index: StructuresPartTablesStructureIndex,
    ) -> cell::Ref<StructureTable> {
        cell::Ref::map(self.tables[index.0].borrow(), |table| match table {
            StructuresPartTable::Structure(table) => table,
            _ => unreachable!(),
        })
    }

    pub(in super::super) fn get_structure_mut(
        &self,
        index: StructuresPartTablesStructureIndex,
    ) -> cell::RefMut<StructureTable> {
        cell::RefMut::map(self.tables[index.0].borrow_mut(), |table| match table {
            StructuresPartTable::Structure(table) => table,
            _ => unreachable!(),
        })
    }

    pub fn get_union(&self, index: StructuresPartTablesUnionIndex) -> cell::Ref<UnionTable> {
        cell::Ref::map(self.tables[index.0].borrow(), |table| match table {
            StructuresPartTable::Union(table) => table,
            _ => unreachable!(),
        })
    }

    fn get_union_mut(&self, index: StructuresPartTablesUnionIndex) -> cell::RefMut<UnionTable> {
        cell::RefMut::map(self.tables[index.0].borrow_mut(), |table| match table {
            StructuresPartTable::Union(table) => table,
            _ => unreachable!(),
        })
    }

    fn get_aliases(&self, index: StructuresPartTablesAliasesIndex) -> cell::Ref<AliasesTable> {
        cell::Ref::map(self.tables[index.0].borrow(), |table| match table {
            StructuresPartTable::Aliases(table) => table,
            _ => unreachable!(),
        })
    }

    fn get_aliases_mut(
        &self,
        index: StructuresPartTablesAliasesIndex,
    ) -> cell::RefMut<AliasesTable> {
        cell::RefMut::map(self.tables[index.0].borrow_mut(), |table| match table {
            StructuresPartTable::Aliases(table) => table,
            _ => unreachable!(),
        })
    }

    pub fn get_constant(
        &self,
        index: StructuresPartTablesConstantIndex,
    ) -> cell::Ref<ConstantsTableEntry> {
        cell::Ref::map(self.get_constants(index.0), |table| &table.entries[index.1])
    }

    fn get_constant_mut(
        &self,
        index: StructuresPartTablesConstantIndex,
    ) -> cell::RefMut<ConstantsTableEntry> {
        cell::RefMut::map(self.get_constants_mut(index.0), |table| {
            &mut table.entries[index.1]
        })
    }

    fn get_alias(&self, index: StructuresPartTablesAliasIndex) -> cell::Ref<AliasesTableEntry> {
        cell::Ref::map(self.get_aliases(index.0), |table| &table.entries[index.1])
    }

    fn get_alias_mut(
        &self,
        index: StructuresPartTablesAliasIndex,
    ) -> cell::RefMut<AliasesTableEntry> {
        cell::RefMut::map(self.get_aliases_mut(index.0), |table| {
            &mut table.entries[index.1]
        })
    }

    pub fn iter(&self) -> StructuresPartTablesIndexIterator {
        StructuresPartTablesIndexIterator::new(self)
    }

    pub fn lookup(&self, name: &str) -> Option<StructuresPartTablesIndex> {
        self.name_to_structure.get(name).copied()
    }

    pub fn lookup_constant(&self, name: &str) -> Option<StructuresPartTablesConstantIndex> {
        self.name_to_constant.get(name).copied()
    }

    fn lookup_alias<'a>(&'a self, name: &'a str) -> StructuresPartTablesAliasIterator<'a> {
        StructuresPartTablesAliasIterator::new(self, name)
    }

    fn lookup_alias_as_ref<'a>(
        &'a self,
        name: &'a str,
    ) -> StructuresPartTablesAliasRefIterator<'a> {
        StructuresPartTablesAliasRefIterator {
            it: self.lookup_alias(name),
        }
    }

    fn translate_aliases<'a>(&'a self, name: &'a str) -> StructuresPartTablesTranslatedAlias<'a> {
        if let Some(alias) = self.lookup_alias_as_ref(name).last() {
            StructuresPartTablesTranslatedAlias::Translated(alias)
        } else {
            StructuresPartTablesTranslatedAlias::Original(name)
        }
    }

    fn lookup_cppdefine(&self, name: &str) -> Option<&str> {
        self.name_to_cppdefine.get(name).map(|v| v.as_str())
    }

    pub fn set_closure_deps_for(
        &mut self,
        closure_deps: ClosureDepsFlags,
        pattern: &regex::Regex,
        for_cond: bool,
    ) -> Result<(), io::Error> {
        let mut matched_some = false;
        for i in self.iter() {
            match i {
                StructuresPartTablesIndex::Aliases(index) => {
                    if for_cond {
                        continue;
                    }
                    let mut j = 0;
                    'reborrow: loop {
                        let t = self.get_aliases(index);
                        while j < t.entries.len() {
                            let entry = &t.entries[j];
                            if let Some(m) = pattern.find(&entry.name) {
                                if m.start() != 0 || m.end() != entry.name.len() {
                                    j += 1;
                                    continue;
                                }

                                if closure_deps
                                    .intersects(ClosureDepsFlags::ANY_DEFINITION.complement())
                                {
                                    eprintln!(
                                        "error: non-definition dependency on \"{}\" type alias",
                                        &entry.name
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }

                                matched_some = true;
                                let mut config_deps = t.structures_info.deps.clone();
                                config_deps.merge_from(&entry.deps);

                                drop(t);
                                let mut t = self.get_aliases_mut(index);
                                let entry = &mut t.entries[j];
                                entry
                                    .closure_deps
                                    .insert(borrow::Cow::Owned(config_deps), closure_deps);
                                j += 1;
                                continue 'reborrow;
                            }
                            j += 1;
                        }
                        break;
                    }
                }
                StructuresPartTablesIndex::Bits(index) => {
                    if for_cond {
                        continue;
                    }
                    let mut t = self.get_bits_mut(index);
                    if let Some(m) = pattern.find(&t.name) {
                        if m.start() != 0 || m.end() != t.name.len() {
                            continue;
                        }

                        if closure_deps.intersects(
                            ClosureDepsFlags::ANY_TRY_CLONE
                                | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                        ) {
                            eprintln!(
                                "error: try-clone/into-buffers-owner dependency on \"{}\" bits type",
                                &t.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }

                        matched_some = true;
                        let config_deps = borrow::Cow::Owned(t.structures_info.deps.clone());
                        t.closure_deps.insert(config_deps, closure_deps);
                    }
                }
                StructuresPartTablesIndex::Constants(index) => {
                    if for_cond {
                        continue;
                    }
                    let mut t = self.get_constants_mut(index);
                    if let Some(m) = pattern.find(&t.name) {
                        if m.start() != 0 || m.end() != t.name.len() {
                            continue;
                        }

                        if t.resolved_base.is_none()
                            && closure_deps
                                .intersects(ClosureDepsFlags::ANY_DEFINITION.complement())
                        {
                            eprintln!("error: table {}: non-definition dependency on constants type with no base",
                                     &t.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        } else if closure_deps.intersects(
                            ClosureDepsFlags::ANY_TRY_CLONE
                                | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                        ) {
                            eprintln!(
                                "error: try-clone/into-buffers-owner dependency on \"{}\" constants type",
                                &t.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }

                        matched_some = true;
                        let config_deps = borrow::Cow::Owned(t.structures_info.deps.clone());
                        t.closure_deps.insert(config_deps, closure_deps);
                    } else {
                        drop(t);
                        let mut j = 0;
                        'reborrow: loop {
                            let t = self.get_constants(index);
                            while j < t.entries.len() {
                                let entry = &t.entries[j];
                                if let Some(m) = pattern.find(&entry.name) {
                                    if m.start() != 0 || m.end() != entry.name.len() {
                                        j += 1;
                                        continue;
                                    }

                                    if closure_deps
                                        .intersects(ClosureDepsFlags::ANY_DEFINITION.complement())
                                    {
                                        eprintln!
                                            ("error: table {}: non-definition dependency on individual \"{}\" constant",
                                             &t.name, &entry.name);
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }

                                    matched_some = true;
                                    let mut config_deps = t.structures_info.deps.clone();
                                    config_deps.merge_from(&entry.deps);

                                    drop(t);
                                    let mut t = self.get_constants_mut(index);
                                    let entry = &mut t.entries[j];
                                    entry
                                        .closure_deps
                                        .insert(borrow::Cow::Owned(config_deps), closure_deps);
                                    j += 1;
                                    continue 'reborrow;
                                }
                                j += 1;
                            }
                            break;
                        }
                    }
                }
                StructuresPartTablesIndex::Type(index) => {
                    let mut t = self.get_type_mut(index);
                    if for_cond && !t.conditional {
                        continue;
                    }
                    if let Some(m) = pattern.find(&t.name) {
                        if m.start() != 0 || m.end() != t.name.len() {
                            continue;
                        }

                        if closure_deps.intersects(
                            ClosureDepsFlags::ANY_TRY_CLONE
                                | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                        ) {
                            eprintln!(
                                "error: try-clone/into-buffers-owner dependency on \"{}\" type",
                                &t.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }

                        matched_some = true;
                        let config_deps = borrow::Cow::Owned(t.structures_info.deps.clone());
                        if !for_cond {
                            t.closure_deps.insert(config_deps, closure_deps);
                        } else {
                            t.closure_deps_conditional.insert(config_deps, closure_deps);
                        }
                    }
                }
                StructuresPartTablesIndex::Structure(index) => {
                    let mut t = self.get_structure_mut(index);
                    if for_cond && !t.conditional {
                        continue;
                    }
                    if let Some(m) = pattern.find(&t.name) {
                        if m.start() != 0 || m.end() != t.name.len() {
                            continue;
                        }

                        matched_some = true;
                        let config_deps = borrow::Cow::Owned(t.structures_info.deps.clone());
                        if !for_cond {
                            t.closure_deps.insert(config_deps, closure_deps);
                        } else {
                            t.closure_deps_conditional.insert(config_deps, closure_deps);
                        }
                    }
                }
                StructuresPartTablesIndex::Union(index) => {
                    if for_cond {
                        continue;
                    }
                    let mut t = self.get_union_mut(index);
                    if let Some(m) = pattern.find(&t.name) {
                        if m.start() != 0 || m.end() != t.name.len() {
                            continue;
                        }

                        if closure_deps.intersects(ClosureDepsFlags::ANY_MAX_SIZE.complement()) {
                            eprintln!(
                                "error: table {}: non-sizeof() dependency on union type",
                                &t.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }

                        matched_some = true;
                        let config_deps = borrow::Cow::Owned(t.structures_info.deps.clone());
                        t.max_size_deps.insert(config_deps, closure_deps);
                    }
                }
            };
        }

        if !matched_some {
            eprintln!(
                "error: could not find any match for \"{}\"",
                pattern.as_str()
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        Ok(())
    }

    pub fn propagate_closure_deps(&mut self) -> Result<(), io::Error> {
        struct Worklist {
            worklist: Vec<StructuresPartTablesIndex>,
            on_worklist: Vec<bool>,
        }

        impl Worklist {
            fn new(tables_size: usize) -> Self {
                let worklist = Vec::new();
                let mut on_worklist = Vec::new();
                on_worklist.resize(tables_size, false);
                Self {
                    worklist,
                    on_worklist,
                }
            }

            fn push(&mut self, table_index: StructuresPartTablesIndex) {
                if self.on_worklist[table_index.get_raw()] {
                    return;
                }
                self.worklist.push(table_index);
                self.on_worklist[table_index.get_raw()] = true;
            }

            fn drain(&mut self) -> Vec<StructuresPartTablesIndex> {
                std::mem::take(&mut self.worklist)
            }

            fn drained_one(&mut self, table_index: StructuresPartTablesIndex) {
                self.on_worklist[table_index.get_raw()] = false;
            }

            fn is_empty(&self) -> bool {
                self.worklist.is_empty()
            }
        }

        let mut worklist = Worklist::new(self.tables.len());
        let mut any_unmarshal = false;
        for i in self.iter() {
            match i {
                StructuresPartTablesIndex::Aliases(_) => (),
                StructuresPartTablesIndex::Bits(index) => {
                    let mut t = self.get_bits_mut(index);
                    if !t.closure_deps.is_empty() {
                        // If (un)marshalling is needed, so is the type definition in the first place.
                        // If marshalling from extern is needed, the marshalled size is as well for
                        // allocating a suitable destination buffer.
                        t.closure_deps = t
                            .closure_deps
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL,
                                ClosureDepsFlags::PUBLIC_DEFINITION,
                            )
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::EXTERN_MARSHAL,
                                ClosureDepsFlags::EXTERN_SIZE,
                            )
                            .into_owned();
                        any_unmarshal |= t.closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL);
                        worklist.push(i);
                    }
                }
                StructuresPartTablesIndex::Constants(index) => {
                    let mut t = self.get_constants_mut(index);
                    if !t.closure_deps.is_empty() {
                        // If (un)marshalling is needed, so is the type definition in the first place.
                        // If marshalling from extern is needed, the marshalled size is as well for
                        // allocating a suitable destination buffer.
                        t.closure_deps = t
                            .closure_deps
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL,
                                ClosureDepsFlags::PUBLIC_DEFINITION,
                            )
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::EXTERN_MARSHAL,
                                ClosureDepsFlags::EXTERN_SIZE,
                            )
                            .into_owned();
                        any_unmarshal |= t.closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL);
                        worklist.push(i);
                    }
                }
                StructuresPartTablesIndex::Type(index) => {
                    let mut t = self.get_type_mut(index);
                    if !t.closure_deps.is_empty() || !t.closure_deps_conditional.is_empty() {
                        // If (un)marshalling is needed, so is the type definition in the first place.
                        // If marshalling from extern is needed, the marshalled size is as well for
                        // allocating a suitable destination buffer.
                        t.closure_deps = t
                            .closure_deps
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL,
                                ClosureDepsFlags::PUBLIC_DEFINITION,
                            )
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::EXTERN_MARSHAL,
                                ClosureDepsFlags::EXTERN_SIZE,
                            )
                            .into_owned();
                        any_unmarshal |= t.closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL);
                        t.closure_deps_conditional = t
                            .closure_deps_conditional
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL,
                                ClosureDepsFlags::PUBLIC_DEFINITION,
                            )
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::EXTERN_MARSHAL,
                                ClosureDepsFlags::EXTERN_SIZE,
                            )
                            .into_owned();
                        any_unmarshal |= t
                            .closure_deps_conditional
                            .any(ClosureDepsFlags::ANY_UNMARSHAL);
                        worklist.push(i);
                    }
                }
                StructuresPartTablesIndex::Structure(index) => {
                    let mut t = self.get_structure_mut(index);
                    if !t.closure_deps.is_empty() || !t.closure_deps_conditional.is_empty() {
                        // If (un)marshalling or buffer stabilization is needed, so is the type
                        // definition in the first place. If marshalling from extern is needed, the
                        // marshalled size is as well for allocating a suitable destination buffer.
                        t.closure_deps = t
                            .closure_deps
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                                    | ClosureDepsFlags::ANY_TRY_CLONE
                                    | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                                ClosureDepsFlags::PUBLIC_DEFINITION,
                            )
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::EXTERN_MARSHAL,
                                ClosureDepsFlags::EXTERN_SIZE,
                            )
                            .into_owned();
                        any_unmarshal |= t.closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL);
                        t.closure_deps_conditional = t
                            .closure_deps_conditional
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                                    | ClosureDepsFlags::ANY_TRY_CLONE
                                    | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                                ClosureDepsFlags::PUBLIC_DEFINITION,
                            )
                            .mod_all_closure_deps_set_cond(
                                ClosureDepsFlags::EXTERN_MARSHAL,
                                ClosureDepsFlags::EXTERN_SIZE,
                            )
                            .into_owned();
                        any_unmarshal |= t
                            .closure_deps_conditional
                            .any(ClosureDepsFlags::ANY_UNMARSHAL);
                        worklist.push(i);
                    }
                }
                StructuresPartTablesIndex::Union(_) => (),
            };
        }

        let set_max_size_deps =
            |worklist: &mut Worklist,
             index: StructuresPartTablesIndex,
             container_deps: borrow::Cow<ClosureDeps>| {
                if container_deps.is_empty() {
                    return;
                }
                let container_deps = container_deps.mod_all_closure_deps(
                    ClosureDepsFlags::empty(),
                    ClosureDepsFlags::ANY_MAX_SIZE.complement(),
                );
                let updated = match index {
                    StructuresPartTablesIndex::Aliases(_) => false,
                    StructuresPartTablesIndex::Bits(index) => {
                        let mut t = self.get_bits_mut(index);
                        t.closure_deps.merge_from(container_deps)
                    }
                    StructuresPartTablesIndex::Constants(index) => {
                        let mut t = self.get_constants_mut(index);
                        t.closure_deps.merge_from(container_deps)
                    }
                    StructuresPartTablesIndex::Type(index) => {
                        let mut t = self.get_type_mut(index);
                        t.closure_deps.merge_from(container_deps)
                    }
                    StructuresPartTablesIndex::Structure(index) => {
                        let mut t = self.get_structure_mut(index);
                        t.closure_deps.merge_from(container_deps)
                    }
                    StructuresPartTablesIndex::Union(index) => {
                        let mut t = self.get_union_mut(index);
                        t.max_size_deps.merge_from(container_deps)
                    }
                };
                if updated {
                    worklist.push(index);
                }
            };

        let propagate_deps_to_alias =
            |worklist: &mut Worklist, type_name: &str, container_deps: borrow::Cow<ClosureDeps>| {
                if container_deps.is_empty() {
                    return;
                }
                for index in self.lookup_alias(type_name) {
                    let mut alias_entry = self.get_alias_mut(index);
                    if alias_entry
                        .closure_deps
                        .merge_from(container_deps.mod_all_closure_deps(
                            ClosureDepsFlags::empty(),
                            ClosureDepsFlags::ANY_DEFINITION.complement(),
                        ))
                    {
                        let index = StructuresPartTablesAliasesIndex::from(index);
                        let index = StructuresPartTablesIndex::Aliases(index);
                        worklist.push(index);
                    }
                }
            };

        let propagate_constant_deps =
            |worklist: &mut Worklist,
             index: StructuresPartTablesConstantIndex,
             container_deps: borrow::Cow<ClosureDeps>| {
                if container_deps.is_empty() {
                    return;
                }

                // The closure deps to propagate to constants: if any dependency, turn it
                // into one on a PRIVATE_DEFINITION.
                let mut c = self.get_constant_mut(index);
                let container_deps = container_deps.mod_all_closure_deps(
                    ClosureDepsFlags::PRIVATE_DEFINITION,
                    ClosureDepsFlags::PRIVATE_DEFINITION.complement(),
                );
                if c.closure_deps.merge_from(container_deps) {
                    let index = StructuresPartTablesConstantsIndex::from(index);
                    let index = StructuresPartTablesIndex::Constants(index);
                    worklist.push(index);
                }
            };

        let mut predefined_constants_deps: HashMap<&'static str, ClosureDeps> = HashMap::new();
        let propagate_predefined_constant_deps_one =
            |worklist: &mut Worklist,
             predefined_constants_deps: &mut HashMap<&str, ClosureDeps>,
             predefined_deps_worklist: &mut Vec<PredefinedConstantRef>,
             predefined: &PredefinedConstantRef,
             container_deps: borrow::Cow<ClosureDeps>| {
                let predefined_deps = match predefined_constants_deps.get_mut(predefined.name) {
                    Some(predefined_deps) => predefined_deps,
                    None => {
                        predefined_constants_deps.insert(predefined.name, ClosureDeps::empty());
                        predefined_constants_deps.get_mut(predefined.name).unwrap()
                    }
                };

                if !predefined_deps.merge_from(container_deps.clone()) {
                    return;
                }

                // Record the predefined ("runtime") constants' sizeof()
                // dependencies.
                for sizeof_dep in predefined.sizeof_deps.iter().copied().flatten() {
                    propagate_deps_to_alias(worklist, sizeof_dep, container_deps.clone());
                    let sizeof_dep = &self.translate_aliases(sizeof_dep);
                    if let Some(index) = self.lookup(sizeof_dep) {
                        let max_size_deps = container_deps.mod_all_closure_deps(
                            ClosureDepsFlags::INTERN_MAX_SIZE,
                            ClosureDepsFlags::INTERN_MAX_SIZE.complement(),
                        );
                        set_max_size_deps(worklist, index, max_size_deps);
                    }
                }

                // Recursively propagate the dependencies to any dependency from this to other
                // predefined constants.
                for predefined_dep in predefined
                    .predefined_constant_deps
                    .iter()
                    .copied()
                    .flatten()
                {
                    let predefined_dep = PredefinedConstants::lookup(predefined_dep).unwrap();
                    predefined_deps_worklist.push(predefined_dep);
                }
            };

        let propagate_predefined_constant_deps =
            |worklist: &mut Worklist,
             predefined_constants_deps: &mut HashMap<&str, ClosureDeps>,
             predefined: &PredefinedConstantRef,
             container_deps: borrow::Cow<ClosureDeps>| {
                if container_deps.is_empty() {
                    return;
                }

                let container_deps = container_deps.mod_all_closure_deps(
                    ClosureDepsFlags::PRIVATE_DEFINITION,
                    ClosureDepsFlags::PRIVATE_DEFINITION.complement(),
                );

                // Worklist for handling recursive deps on predefined constants.
                let mut predefined_deps_worklist = Vec::new();
                propagate_predefined_constant_deps_one(
                    worklist,
                    predefined_constants_deps,
                    &mut predefined_deps_worklist,
                    predefined,
                    borrow::Cow::Borrowed(&container_deps),
                );

                while !predefined_deps_worklist.is_empty() {
                    let wl = std::mem::take(&mut predefined_deps_worklist);
                    for predefined in wl {
                        propagate_predefined_constant_deps_one(
                            worklist,
                            predefined_constants_deps,
                            &mut predefined_deps_worklist,
                            &predefined,
                            borrow::Cow::Borrowed(&container_deps),
                        );
                    }
                }
            };

        let propagate_error_rc_deps =
            |worklist: &mut Worklist,
             error_rc: StructuresPartTablesConstantIndex,
             container_deps: borrow::Cow<ClosureDeps>| {
                // Transform any dependencies to PRIVATE_DEFINITION dependencies on the error code.
                let container_deps = container_deps.mod_all_closure_deps(
                    ClosureDepsFlags::PRIVATE_DEFINITION,
                    ClosureDepsFlags::PRIVATE_DEFINITION.complement(),
                );
                let container_deps = container_deps.into_owned();
                propagate_constant_deps(worklist, error_rc, borrow::Cow::Owned(container_deps));
            };

        // These error code definitions are needed for the unmarshalling code.
        if any_unmarshal {
            let mut deps = ClosureDeps::empty();
            deps.insert(
                borrow::Cow::Owned(ConfigDeps::new()),
                ClosureDepsFlags::PRIVATE_DEFINITION,
            );
            for error_rc in [
                "TPM_RC_INSUFFICIENT",
                "TPM_RC_MEMORY",
            ] {
                match self.lookup_constant(error_rc) {
                    Some(error_rc) => {
                        propagate_error_rc_deps(
                            &mut worklist,
                            error_rc,
                            borrow::Cow::Borrowed(&deps),
                        );
                    }
                    None => {
                        eprintln!(
                            "error: no definition of {}, needed for unmarshalling",
                            error_rc
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };
            }
        }

        let propagate_error_rc_deps =
            |worklist: &mut Worklist,
             table_name: &str,
             table_error_rc: Option<StructuresPartTablesConstantIndex>,
             alternative_error_rc: &str,
             container_deps: borrow::Cow<ClosureDeps>| {
                 if container_deps.is_empty() {
                     return Ok(());
                 }
                 let error_rc = if let Some(error_rc) = table_error_rc {
                     error_rc
                 } else {
                     match self.lookup_constant(alternative_error_rc) {
                         Some(error_rc) => error_rc,
                         None => {
                             eprintln!(
                                 "error: table {}: no definition of {}",
                                 table_name, alternative_error_rc
                             );
                             return Err(io::Error::from(io::ErrorKind::InvalidData));
                         }
                     }
                 };
                 propagate_error_rc_deps(worklist, error_rc, container_deps);
                 Ok(())
             };

        while !worklist.is_empty() {
            let mut wl = worklist.drain();
            for i in wl.drain(..) {
                worklist.drained_one(i);

                let propagate_expr_deps =
                    |worklist: &mut Worklist,
                     predefined_constants_deps: &mut HashMap<&str, ClosureDeps>,
                     e: &Expr,
                     container_deps: borrow::Cow<ClosureDeps>| {
                        if container_deps.is_empty() {
                            return;
                        }
                        e.map(&mut |e: &Expr, _: &[()]| {
                            match &e.op {
                                ExprOp::Id(id) => {
                                    match id.resolved.as_ref().unwrap() {
                                        ExprResolvedId::PredefinedConstant(predefined) => {
                                            propagate_predefined_constant_deps(
                                                worklist,
                                                predefined_constants_deps,
                                                predefined,
                                                container_deps.clone(),
                                            );
                                        }
                                        ExprResolvedId::Constant(index) => {
                                            propagate_constant_deps(
                                                worklist,
                                                *index,
                                                container_deps.clone(),
                                            );
                                        }
                                        ExprResolvedId::StructMember(_) => (),
                                    };
                                }
                                ExprOp::Sizeof(s) => {
                                    match s.resolved.as_ref().unwrap() {
                                        ExprResolvedType::PredefinedType(_) => {}
                                        ExprResolvedType::Type(index) => {
                                            // For sizeof()s, record an INTERN_MAX_SIZE on the type.
                                            let container_deps = container_deps
                                                .mod_all_closure_deps(
                                                    ClosureDepsFlags::INTERN_MAX_SIZE,
                                                    ClosureDepsFlags::INTERN_MAX_SIZE.complement(),
                                                );
                                            set_max_size_deps(worklist, *index, container_deps);
                                        }
                                    };
                                }
                                _ => (),
                            };
                        });
                    };

                let propagate_value_range_deps =
                    |worklist: &mut Worklist,
                     predefined_constants_deps: &mut HashMap<&str, ClosureDeps>,
                     r: &ValueRange,
                     container_deps: borrow::Cow<ClosureDeps>| {
                        if container_deps.is_empty() {
                            return;
                        }
                        match r {
                            ValueRange::Range {
                                min_value,
                                max_value,
                            } => {
                                if let Some(value) = min_value {
                                    propagate_expr_deps(
                                        worklist,
                                        predefined_constants_deps,
                                        value,
                                        borrow::Cow::Borrowed(&container_deps),
                                    );
                                }
                                if let Some(value) = max_value {
                                    propagate_expr_deps(
                                        worklist,
                                        predefined_constants_deps,
                                        value,
                                        borrow::Cow::Borrowed(&container_deps),
                                    );
                                }
                            }
                            ValueRange::Discrete(values) => {
                                for value in values.iter() {
                                    propagate_expr_deps(
                                        worklist,
                                        predefined_constants_deps,
                                        value,
                                        borrow::Cow::Borrowed(&container_deps),
                                    );
                                }
                            }
                        };
                    };

                let propagate_deps_to_member =
                    |worklist: &mut Worklist,
                     base_type_name: &str,
                     base_type: &StructureTableEntryResolvedBaseType,
                     container_deps: borrow::Cow<ClosureDeps>,
                     to_conditional: bool| {
                        if container_deps.is_empty() {
                            return;
                        }
                        propagate_deps_to_alias(
                            worklist,
                            base_type_name,
                            borrow::Cow::Borrowed(&container_deps),
                        );
                        match base_type {
                            StructureTableEntryResolvedBaseType::Predefined(_) => (),
                            StructureTableEntryResolvedBaseType::Constants(index) => {
                                let container_deps = container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_TRY_CLONE
                                        | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                                );
                                assert!(!to_conditional);
                                let mut t = self.get_constants_mut(*index);
                                if t.closure_deps.propagate_from(container_deps) {
                                    worklist.push(StructuresPartTablesIndex::Constants(*index));
                                }
                            }
                            StructureTableEntryResolvedBaseType::Bits(index) => {
                                let container_deps = container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_TRY_CLONE
                                        | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                                );
                                assert!(!to_conditional);
                                let mut t = self.get_bits_mut(*index);
                                if t.closure_deps.propagate_from(container_deps) {
                                    worklist.push(StructuresPartTablesIndex::Bits(*index));
                                }
                            }
                            StructureTableEntryResolvedBaseType::Type(index) => {
                                let container_deps = container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_TRY_CLONE
                                        | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                                );
                                let mut t = self.get_type_mut(*index);
                                assert!(!to_conditional || t.conditional);
                                let propagated = if to_conditional {
                                    t.closure_deps_conditional.propagate_from(container_deps)
                                } else {
                                    t.closure_deps.propagate_from(container_deps)
                                };
                                if propagated {
                                    worklist.push(StructuresPartTablesIndex::Type(*index));
                                }
                            }
                            StructureTableEntryResolvedBaseType::Structure(index) => {
                                let mut t = self.get_structure_mut(*index);
                                assert!(!to_conditional || t.conditional);
                                let propagated = if to_conditional {
                                    t.closure_deps_conditional.propagate_from(container_deps)
                                } else {
                                    t.closure_deps.propagate_from(container_deps)
                                };
                                if propagated {
                                    worklist.push(StructuresPartTablesIndex::Structure(*index));
                                }
                            }
                        };
                    };

                let propagate_union_entry_deps =
                    |worklist: &mut Worklist,
                     table_name: &str,
                     predefined_constants_deps: &mut HashMap<&str, ClosureDeps>,
                     entry: &UnionTableEntry,
                     container_deps: borrow::Cow<ClosureDeps>| -> Result<(), io::Error> {
                        assert!(container_deps.are_all_configs_limited(&entry.deps));
                        match &entry.entry_type {
                            UnionTableEntryType::Plain(plain_type) => {
                                if let Some(base_type) = plain_type.resolved_base_type.as_ref() {
                                    propagate_deps_to_member(
                                        worklist,
                                        plain_type.base_type.as_ref().unwrap().as_str(),
                                        base_type,
                                        container_deps,
                                        plain_type.base_type_enable_conditional,
                                    );
                                }
                            }
                            UnionTableEntryType::Array(array_type) => {
                                propagate_deps_to_member(
                                    worklist,
                                    array_type.element_type.as_str(),
                                    array_type.resolved_element_type.as_ref().unwrap(),
                                    borrow::Cow::Borrowed(&container_deps),
                                    array_type.element_type_enable_conditional,
                                );

                                // Now handle the size expression. The size is
                                // relevant only to (un)marshalling, the
                                // marshalled size and sizeof(). If compile-time
                                // constant, it might also matter for the the
                                // definition, as the array could get embedded
                                // into the containing structure.
                                let mut size_deps = ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                                    | ClosureDepsFlags::ANY_SIZE
                                    | ClosureDepsFlags::ANY_MAX_SIZE;
                                if let ExprValue::CompiletimeConstant(_) =
                                    array_type.size.value.as_ref().unwrap()
                                {
                                    size_deps |= ClosureDepsFlags::ANY_DEFINITION;
                                }
                                let container_deps = container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    size_deps.complement(),
                                );
                                propagate_expr_deps(
                                    worklist,
                                    predefined_constants_deps,
                                    &array_type.size,
                                    borrow::Cow::Borrowed(&container_deps),
                                );

                                let container_deps = container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_MARSHAL.complement()
                                );
                                propagate_error_rc_deps(worklist, table_name,
                                                        None, "TPM_RC_SIZE", container_deps)?;
                            }
                        };
                        Ok(())
                    };

                match i {
                    StructuresPartTablesIndex::Aliases(_) => (),
                    StructuresPartTablesIndex::Bits(index) => {
                        let t = self.get_bits(index);
                        // sizeof() on a Bits type does not depend on any base type's sizeof, only
                        // on the final underlying predefined integer type. Also, the sizeof() does
                        // not depend on the individual members' bit ranges.
                        let container_deps = borrow::Cow::Borrowed(&t.closure_deps);
                        let container_deps = container_deps.mod_all_closure_deps(
                            ClosureDepsFlags::empty(),
                            ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE,
                        );
                        match t.resolved_base.unwrap() {
                            BitsTableResolvedBase::Predefined(_) => {}
                            BitsTableResolvedBase::Constants(index) => {
                                let index = StructureTableEntryResolvedBaseType::Constants(index);
                                propagate_deps_to_member(
                                    &mut worklist,
                                    &t.base,
                                    &index,
                                    borrow::Cow::Borrowed(&container_deps),
                                    false,
                                );
                            }
                            BitsTableResolvedBase::Type(index) => {
                                let index = StructureTableEntryResolvedBaseType::Type(index);
                                propagate_deps_to_member(
                                    &mut worklist,
                                    &t.base,
                                    &index,
                                    borrow::Cow::Borrowed(&container_deps),
                                    false,
                                );
                            }
                        };

                        for entry in t.entries.iter() {
                            let container_deps = container_deps.limit_config_scopes(&entry.deps);
                            propagate_expr_deps(
                                &mut worklist,
                                &mut predefined_constants_deps,
                                &entry.bits.min_bit_index,
                                borrow::Cow::Borrowed(&container_deps),
                            );
                            if let Some(max_bit_index) = &entry.bits.max_bit_index {
                                propagate_expr_deps(
                                    &mut worklist,
                                    &mut predefined_constants_deps,
                                    max_bit_index,
                                    borrow::Cow::Borrowed(&container_deps),
                                );
                            }
                        }
                        for reserved in t.reserved.iter() {
                            propagate_expr_deps(
                                &mut worklist,
                                &mut predefined_constants_deps,
                                &reserved.min_bit_index,
                                borrow::Cow::Borrowed(&container_deps),
                            );
                            if let Some(max_bit_index) = &reserved.max_bit_index {
                                propagate_expr_deps(
                                    &mut worklist,
                                    &mut predefined_constants_deps,
                                    max_bit_index,
                                    borrow::Cow::Borrowed(&container_deps),
                                );
                            }
                        }

                        if !t.reserved.is_empty() {
                            let container_deps = container_deps.mod_all_closure_deps(
                                ClosureDepsFlags::empty(),
                                ClosureDepsFlags::ANY_UNMARSHAL.complement(),
                            );
                            propagate_error_rc_deps(&mut worklist, &t.name,
                                                    None, "TPM_RC_RESERVED_BITS", container_deps)?;
                        }
                    }
                    StructuresPartTablesIndex::Constants(index) => {
                        let t = self.get_constants_mut(index);
                        let (mut entries, t_container_deps) =
                            RefMut::map_split(t, |t| (&mut t.entries, &mut t.closure_deps));

                        // sizeof() on a Constants type does not depend on any of the members' expressions,
                        // mask it off.
                        let container_deps = borrow::Cow::Borrowed(&*t_container_deps);
                        let container_deps = container_deps.mod_all_closure_deps(
                            ClosureDepsFlags::empty(),
                            ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE,
                        );

                        // Turn (un)marshal dependencies on the Constants type to PUBLIC_DEFINITION
                        // dependencies on the members.
                        let container_deps = container_deps.transform_all_closure_deps(
                            ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL,
                            ClosureDepsFlags::PUBLIC_DEFINITION,
                        );
                        let entries_len = entries.len();
                        for j in 0..entries_len {
                            // In enum-like Constants type, do not propagate any dependencies on the type
                            // to helper members -- these might be completely internal to the type and only
                            // be used in definining other, public members. Their respective expressions will
                            // impose a PRIVATE_DEFINITION dependency on the helper, if needed.
                            let entry = &mut entries[j];
                            if !entry.is_helper_duplicate {
                                let container_deps =
                                    container_deps.limit_config_scopes(&entry.deps);
                                entry.closure_deps.merge_from(container_deps);
                            }
                        }
                        drop(entries);
                        drop(t_container_deps);

                        // Evaluating the constants' expression, can recurse into the same Constants table.
                        // So be careful with the borrowing.
                        for j in 0..entries_len {
                            let t = self.get_constants(index);
                            let entry = &t.entries[j];
                            let value = entry.value.clone();
                            let closure_deps = entry.closure_deps.clone();
                            drop(t);
                            propagate_expr_deps(
                                &mut worklist,
                                &mut predefined_constants_deps,
                                &value,
                                borrow::Cow::Owned(closure_deps),
                            );
                        }

                        let t = self.get_constants(index);

                        // Propagate dependencies to the unmarshalling error code as needed. Note
                        // that for enum-like ANY_DEFINITION constants, a TryFrom<> implementation
                        // will be provided.
                        if t.closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) ||
                            (t.enum_like && t.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION))
                        {
                            let container_deps = borrow::Cow::Borrowed(&t.closure_deps);
                            let container_deps = if t.enum_like
                                && container_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                                // For enum-like constants with an ANY_DEFINTION dependency, a
                                // TryFrom<> implementation will be provided.
                                container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_DEFINITION.complement(),
                                )
                            } else {
                                container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_UNMARSHAL.complement()
                                )
                            };
                            let container_deps = borrow::Cow::Owned(container_deps.into_owned());
                            let table_name = t.name.clone();
                            let table_error_rc = t.resolved_error_rc;
                            drop(t);
                            propagate_error_rc_deps(&mut worklist, &table_name,
                                                    table_error_rc, "TPM_RC_VALUE",
                                                    container_deps)?;
                        }
                    }
                    StructuresPartTablesIndex::Type(index) => {
                        let t = self.get_type(index);
                        // sizeof() on a Type type does not depend on any base type's sizeof, only
                        // on the final underlying predefined integer type. Also, neither of the
                        // ANY_DEFINITION or ANY_UNMARSHAL_OR_MARSHAL related definitions/code
                        // rely on the base type. So don't propagate any dependencies there.
                        //
                        // Moreover, the sizeof() does not depend on the individual members' value ranges,
                        // so mask it off.
                        let container_deps_conditional =
                            borrow::Cow::Borrowed(&t.closure_deps_conditional);
                        let container_deps = t.closure_deps.union(&container_deps_conditional);
                        let container_deps_conditional = container_deps_conditional
                            .mod_all_closure_deps(
                                ClosureDepsFlags::empty(),
                                ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE,
                            );
                        let container_deps = container_deps.mod_all_closure_deps(
                            ClosureDepsFlags::empty(),
                            ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE,
                        );
                        for entry in t.entries.iter() {
                            if entry.conditional {
                                let container_deps_conditional =
                                    container_deps_conditional.limit_config_scopes(&entry.deps);
                                propagate_value_range_deps(
                                    &mut worklist,
                                    &mut predefined_constants_deps,
                                    &entry.values,
                                    container_deps_conditional,
                                );
                            } else {
                                let container_deps =
                                    container_deps.limit_config_scopes(&entry.deps);
                                propagate_value_range_deps(
                                    &mut worklist,
                                    &mut predefined_constants_deps,
                                    &entry.values,
                                    container_deps,
                                );
                            }
                        }

                        // Propagate dependencies to the unmarshalling error code as needed. Note
                        // that for enum-like ANY_DEFINITION constants, a TryFrom<> implementation
                        // will be provided.
                        // Propagate dependencies to the unmarshalling error code as needed. Note
                        // that for enum-like ANY_DEFINITION constants, a TryFrom<> implementation
                        // will be provided.
                        if container_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) ||
                            (t.enum_like && t.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION))
                        {
                            let container_deps = if t.enum_like
                                && container_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                                // For enum-like constants with an ANY_DEFINTION dependency, a
                                // TryFrom<> implementation will be provided.
                                container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_DEFINITION.complement(),
                                )
                            } else {
                                container_deps.mod_all_closure_deps(
                                    ClosureDepsFlags::empty(),
                                    ClosureDepsFlags::ANY_UNMARSHAL.complement()
                                )
                            };
                            propagate_error_rc_deps(&mut worklist, &t.name,
                                                    t.resolved_error_rc, "TPM_RC_VALUE",
                                                    container_deps)?;
                        }
                    }
                    StructuresPartTablesIndex::Structure(index) => {
                        let t = self.get_structure(index);
                        for entry in t.entries.iter() {
                            match &entry.entry_type {
                                StructureTableEntryType::Plain(plain_type) => {
                                    // Two sets of container_deps to propagate: one for the case
                                    // that the type's "conditional" variant is used, and
                                    // another one if not.
                                    let container_deps_conditional =
                                        if plain_type.base_type_conditional {
                                            borrow::Cow::Borrowed(&t.closure_deps_conditional)
                                        } else if plain_type.base_type_enable_conditional {
                                            t.closure_deps.union(&t.closure_deps_conditional)
                                        } else {
                                            borrow::Cow::Owned(ClosureDeps::empty())
                                        };
                                    assert!(container_deps_conditional
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps_conditional =
                                        container_deps_conditional.limit_config_scopes(&entry.deps);
                                    propagate_deps_to_member(
                                        &mut worklist,
                                        plain_type.base_type.as_str(),
                                        plain_type.resolved_base_type.as_ref().unwrap(),
                                        borrow::Cow::Borrowed(&*container_deps_conditional),
                                        true,
                                    );

                                    let container_deps = if plain_type.base_type_conditional {
                                        borrow::Cow::Borrowed(&t.closure_deps)
                                    } else if !plain_type.base_type_enable_conditional {
                                        t.closure_deps.union(&t.closure_deps_conditional)
                                    } else {
                                        borrow::Cow::Owned(ClosureDeps::empty())
                                    };
                                    assert!(container_deps
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps =
                                        container_deps.limit_config_scopes(&entry.deps);
                                    propagate_deps_to_member(
                                        &mut worklist,
                                        plain_type.base_type.as_str(),
                                        plain_type.resolved_base_type.as_ref().unwrap(),
                                        borrow::Cow::Borrowed(&*container_deps),
                                        false,
                                    );

                                    if let Some(range) = &plain_type.range {
                                        // The allowed value range is significant only to unmarshalling.
                                        let container_deps =
                                            t.closure_deps.union(&t.closure_deps_conditional);
                                        let container_deps = container_deps.mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            ClosureDepsFlags::ANY_UNMARSHAL.complement(),
                                        );
                                        propagate_value_range_deps(
                                            &mut worklist,
                                            &mut predefined_constants_deps,
                                            range,
                                            borrow::Cow::Borrowed(container_deps.borrow()),
                                        );

                                        propagate_error_rc_deps(&mut worklist, &t.name,
                                                                t.resolved_error_rc, "TPM_RC_VALUE", container_deps)?;
                                    }
                                    if plain_type.is_size_specifier {
                                        let container_deps =
                                            t.closure_deps.union(&t.closure_deps_conditional);
                                        let container_deps = container_deps.mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            ClosureDepsFlags::ANY_UNMARSHAL.complement(),
                                        );
                                        propagate_error_rc_deps(&mut worklist, &t.name,
                                                                t.resolved_error_rc, "TPM_RC_SIZE", container_deps)?;

                                        let container_deps =
                                            t.closure_deps.union(&t.closure_deps_conditional);
                                        let container_deps = container_deps.mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            ClosureDepsFlags::ANY_MARSHAL.complement(),
                                        );
                                        propagate_error_rc_deps(&mut worklist, &t.name,
                                                                None, "TPM_RC_SIZE", container_deps)?;
                                    }
                                }
                                StructureTableEntryType::Discriminant(discriminant) => {
                                    // Two sets of container_deps to propagate: one for the case
                                    // that the discriminant's "conditional" variant is used, and
                                    // another one if not.
                                    let container_deps_conditional = if discriminant
                                        .discriminant_type_conditional
                                    {
                                        borrow::Cow::Borrowed(&t.closure_deps_conditional)
                                    } else if discriminant.discriminant_type_enable_conditional {
                                        t.closure_deps.union(&t.closure_deps_conditional)
                                    } else {
                                        borrow::Cow::Owned(ClosureDeps::empty())
                                    };
                                    assert!(container_deps_conditional
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps_conditional =
                                        container_deps_conditional.limit_config_scopes(&entry.deps);

                                    let container_deps = if discriminant
                                        .discriminant_type_conditional
                                    {
                                        borrow::Cow::Borrowed(&t.closure_deps)
                                    } else if !discriminant.discriminant_type_enable_conditional {
                                        t.closure_deps.union(&t.closure_deps_conditional)
                                    } else {
                                        borrow::Cow::Owned(ClosureDeps::empty())
                                    };
                                    assert!(container_deps
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps =
                                        container_deps.limit_config_scopes(&entry.deps);

                                    // Record the dependencies on the discriminant's type itself.
                                    // The discriminant will get absorbed into a tagged union type,
                                    // i.e. a Rust enum. Hence a PRIVATE_DEFINITION on the respective
                                    // constants suffices, even if the containing Structure is
                                    // PUBLIC_DEFININITION. The size/sizeof() dependendies need to get
                                    // propagated to the respective type though.
                                    for (container_deps, to_conditional) in [
                                        (&container_deps, false),
                                        (&container_deps_conditional, true)
                                    ] {
                                        if container_deps.is_empty() {
                                            continue;
                                        }

                                        let discriminant_type_name =
                                            discriminant.discriminant_type.as_str();
                                        let discriminant_type =
                                            discriminant.resolved_discriminant_type.unwrap();
                                        let size_deps = ClosureDepsFlags::ANY_SIZE
                                            | ClosureDepsFlags::ANY_MAX_SIZE;
                                        let container_size_deps =
                                            container_deps.mod_all_closure_deps(
                                                ClosureDepsFlags::empty(),
                                                size_deps.complement(),
                                            );
                                        propagate_deps_to_member(
                                            &mut worklist,
                                            discriminant_type_name,
                                            &StructureTableEntryResolvedBaseType::from(
                                                discriminant_type,
                                            ),
                                            borrow::Cow::Borrowed(
                                                &*container_size_deps,
                                            ),
                                            to_conditional,
                                        );

                                        let container_deps = container_deps
                                            .mod_all_closure_deps(
                                                ClosureDepsFlags::empty(),
                                                size_deps
                                                    | ClosureDepsFlags::ANY_TRY_CLONE
                                                    | ClosureDepsFlags::ANY_INTO_BUFS_OWNER,
                                            );

                                        if container_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) {
                                            // Propagate any unmarshal deps to the discriminant base type's
                                            // recorded RC value constant.
                                            let container_deps = container_deps.mod_all_closure_deps(
                                                ClosureDepsFlags::empty(),
                                                ClosureDepsFlags::ANY_UNMARSHAL.complement(),
                                            );
                                            let base_type = discriminant.resolved_discriminant_type.as_ref().unwrap();
                                            let error_rc = match base_type {
                                                StructureTableEntryResolvedDiscriminantType::Constants(i) => {
                                                    let constants_table = self.get_constants(*i);
                                                    constants_table.resolved_error_rc
                                                }
                                                StructureTableEntryResolvedDiscriminantType::Type(i) => {
                                                    let type_table = self.get_type(*i);
                                                    type_table.resolved_error_rc
                                                }
                                            };
                                            propagate_error_rc_deps(&mut worklist, &t.name,
                                                                    error_rc, "TPM_RC_VALUE", container_deps)?;
                                        }

                                        let container_deps = container_deps
                                            .transform_all_closure_deps(
                                                ClosureDepsFlags::PUBLIC_DEFINITION,
                                                ClosureDepsFlags::PRIVATE_DEFINITION,
                                            );
                                        // The selector holds a Ref to the current constant's table.
                                        // Collect all dependencies first and apply them afterwards.
                                        let mut enum_constants_deps = Vec::new();
                                        for selector in UnionSelectorIterator::new(
                                            self,
                                            discriminant_type,
                                            to_conditional,
                                        ) {
                                            let selector_value = match selector {
                                                UnionSelectorIteratorValue::Constant(
                                                    _,
                                                    constant_index,
                                                ) => constant_index,
                                                UnionSelectorIteratorValue::Type(
                                                    _,
                                                    table_index,
                                                    entry_index,
                                                ) => {
                                                    let type_table = self.get_type(table_index);
                                                    type_table
                                                        .get_enum_type_member_constant(entry_index)
                                                }
                                            };
                                            let container_deps =
                                                container_deps
                                                    .limit_config_scopes(selector.config_deps());
                                            enum_constants_deps.push((
                                                selector_value,
                                                container_deps.clone(),
                                            ));
                                        }
                                        for dep in enum_constants_deps.drain(..) {
                                            propagate_constant_deps(&mut worklist, dep.0, dep.1);
                                        }
                                    }

                                    // For sizeof() dependencies, all union members are to be
                                    // considered whereas for the union member type dependency
                                    // propagations, only the members actually selected by the
                                    // chosen discriminant are considered. Split out the *_MAX_SIZE
                                    // dependencies and record them at the union(s) as a whole
                                    // below.
                                    let max_size_container_deps =
                                        t.closure_deps.union(&t.closure_deps_conditional);
                                    let max_size_container_deps = max_size_container_deps
                                        .mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            ClosureDepsFlags::ANY_MAX_SIZE.complement(),
                                        );
                                    let container_deps_conditional = container_deps_conditional
                                        .mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            ClosureDepsFlags::ANY_MAX_SIZE,
                                        );
                                    let container_deps = container_deps.mod_all_closure_deps(
                                        ClosureDepsFlags::empty(),
                                        ClosureDepsFlags::ANY_MAX_SIZE,
                                    );

                                    // For each union member selected by the discriminant, propagate
                                    // the dependencies directly to that member's type etc.
                                    for union_member_index in
                                        discriminant.discriminated_union_members.iter()
                                    {
                                        let union_type_index =
                                            match &t.entries[*union_member_index].entry_type {
                                                StructureTableEntryType::Union(union_type) => {
                                                    union_type.resolved_union_type.unwrap()
                                                }
                                                _ => unreachable!(),
                                            };
                                        let mut union_type = self.get_union_mut(union_type_index);
                                        if union_type.max_size_deps.propagate_from(
                                            borrow::Cow::Borrowed(&*max_size_container_deps),
                                        ) {
                                            worklist.push(StructuresPartTablesIndex::Union(
                                                union_type_index,
                                            ));
                                        }
                                        drop(union_type);
                                        let union_type = self.get_union(union_type_index);

                                        for (container_deps, to_conditional) in [
                                            (&container_deps, false),
                                            (&container_deps_conditional, true)
                                        ] {
                                            if container_deps.is_empty() {
                                                continue;
                                            }

                                            let discriminant_type = discriminant
                                                .resolved_discriminant_type
                                                .as_ref()
                                                .unwrap();
                                            let selectors = UnionSelectorIterator::new(
                                                self,
                                                *discriminant_type,
                                                to_conditional,
                                            );
                                            for selector in selectors {
                                                let container_deps = container_deps
                                                    .limit_config_scopes(selector.config_deps());
                                                let entry = union_type
                                                    .lookup_member(selector.name())
                                                    .unwrap();
                                                let entry = &union_type.entries[entry];
                                                propagate_union_entry_deps(
                                                    &mut worklist,
                                                    &union_type.name,
                                                    &mut predefined_constants_deps,
                                                    entry,
                                                    container_deps,
                                                )?;
                                            }
                                        }
                                    }
                                }
                                StructureTableEntryType::Union(_) => {
                                    // Nothing to do, everything's handled in the course of
                                    // processing the associated discriminant.
                                }
                                StructureTableEntryType::Array(array_type) => {
                                    // Two sets of container_deps to propagate: one for the case
                                    // that the element type's "conditional" variant is used, and
                                    // another one if not.
                                    let container_deps_conditional =
                                        if array_type.element_type_conditional {
                                            borrow::Cow::Borrowed(&t.closure_deps_conditional)
                                        } else if array_type.element_type_enable_conditional {
                                            t.closure_deps.union(&t.closure_deps_conditional)
                                        } else {
                                            borrow::Cow::Owned(ClosureDeps::empty())
                                        };
                                    assert!(container_deps_conditional
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps_conditional =
                                        container_deps_conditional.limit_config_scopes(&entry.deps);
                                    propagate_deps_to_member(
                                        &mut worklist,
                                        array_type.element_type.as_str(),
                                        array_type.resolved_element_type.as_ref().unwrap(),
                                        borrow::Cow::Borrowed(&*container_deps_conditional),
                                        true,
                                    );

                                    let container_deps = if array_type.element_type_conditional {
                                        borrow::Cow::Borrowed(&t.closure_deps)
                                    } else if !array_type.element_type_enable_conditional {
                                        t.closure_deps.union(&t.closure_deps_conditional)
                                    } else {
                                        borrow::Cow::Owned(ClosureDeps::empty())
                                    };
                                    assert!(container_deps
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps =
                                        container_deps.limit_config_scopes(&entry.deps);
                                    propagate_deps_to_member(
                                        &mut worklist,
                                        array_type.element_type.as_str(),
                                        array_type.resolved_element_type.as_ref().unwrap(),
                                        borrow::Cow::Borrowed(&*container_deps),
                                        false,
                                    );

                                    // Now handle the size expression and the allowed size range, if any.
                                    let container_deps =
                                        t.closure_deps.union(&t.closure_deps_conditional);
                                    assert!(container_deps
                                        .are_all_configs_limited(&t.structures_info.deps));
                                    let container_deps =
                                        container_deps.limit_config_scopes(&entry.deps);
                                    // The size is relevant only to
                                    // (un)marshalling, the marshalled size and
                                    // sizeof(). If compile-time constant, it
                                    // might also matter for the the definition,
                                    // as the array could get embedded into the
                                    // containing structure.
                                    let mut size_deps = ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                                        | ClosureDepsFlags::ANY_SIZE
                                        | ClosureDepsFlags::ANY_MAX_SIZE;
                                    if let ExprValue::CompiletimeConstant(_) =
                                        array_type.size.value.as_ref().unwrap()
                                    {
                                        size_deps |= ClosureDepsFlags::ANY_DEFINITION;
                                    }
                                    let container_deps = container_deps.mod_all_closure_deps(
                                        ClosureDepsFlags::empty(),
                                        size_deps.complement(),
                                    );
                                    propagate_expr_deps(
                                        &mut worklist,
                                        &mut predefined_constants_deps,
                                        &array_type.size,
                                        borrow::Cow::Borrowed(&container_deps),
                                    );
                                    if let Some(range) = &array_type.size_range {
                                        // The allowed size range is significant only to unmarshalling + sizeof().
                                        let size_deps = ClosureDepsFlags::ANY_UNMARSHAL
                                            | ClosureDepsFlags::ANY_MAX_SIZE;
                                        let container_deps = container_deps.mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            size_deps.complement(),
                                        );
                                        propagate_value_range_deps(
                                            &mut worklist,
                                            &mut predefined_constants_deps,
                                            range,
                                            borrow::Cow::Borrowed(container_deps.borrow()),
                                        );

                                        let container_deps = container_deps.mod_all_closure_deps(
                                            ClosureDepsFlags::empty(),
                                            ClosureDepsFlags::ANY_UNMARSHAL.complement(),
                                        );
                                        propagate_error_rc_deps(&mut worklist, &t.name,
                                                                t.resolved_error_rc, "TPM_RC_SIZE", container_deps)?;
                                    }

                                    let container_deps = container_deps.mod_all_closure_deps(
                                        ClosureDepsFlags::empty(),
                                        ClosureDepsFlags::ANY_MARSHAL.complement(),
                                    );
                                    propagate_error_rc_deps(&mut worklist, &t.name,
                                                            None, "TPM_RC_SIZE", container_deps)?;
                                }
                            };
                        }
                    }
                    StructuresPartTablesIndex::Union(index) => {
                        let t = self.get_union(index);
                        let max_size_container_deps = &t.max_size_deps;
                        assert!(max_size_container_deps
                            .are_all_configs_limited(&t.structures_info.deps));
                        if !max_size_container_deps.is_empty() {
                            for entry in t.entries.iter() {
                                let selector_deps = {
                                    match entry.selector.as_ref() {
                                        Some(selector) => {
                                            match self.lookup_constant(selector.as_str()) {
                                                Some(index) => {
                                                    let mut selector_deps =
                                                        self.get_constant(index).deps.clone();
                                                    let index =
                                                        StructuresPartTablesConstantsIndex::from(
                                                            index,
                                                        );
                                                    selector_deps.merge_from(
                                                        &self
                                                            .get_constants(index)
                                                            .structures_info
                                                            .deps,
                                                    );
                                                    selector_deps
                                                }
                                                None => ConfigDeps::new(),
                                            }
                                        }
                                        None => ConfigDeps::new(),
                                    }
                                };
                                let max_size_container_deps =
                                    max_size_container_deps.limit_config_scopes(&selector_deps);
                                propagate_union_entry_deps(
                                    &mut worklist,
                                    &t.name,
                                    &mut predefined_constants_deps,
                                    entry,
                                    max_size_container_deps,
                                )?;
                            }
                        }
                    }
                };
            }
        }

        self.predefined_constants_deps = predefined_constants_deps;

        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StructuresPartTablesConstantsIndex(pub(super) usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuresPartTablesBitsIndex(usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuresPartTablesTypeIndex(pub(super) usize);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StructuresPartTablesStructureIndex(usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuresPartTablesUnionIndex(usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuresPartTablesAliasesIndex(usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StructuresPartTablesIndex {
    Constants(StructuresPartTablesConstantsIndex),
    Bits(StructuresPartTablesBitsIndex),
    Type(StructuresPartTablesTypeIndex),
    Structure(StructuresPartTablesStructureIndex),
    Union(StructuresPartTablesUnionIndex),
    Aliases(StructuresPartTablesAliasesIndex),
}

impl StructuresPartTablesIndex {
    fn get_raw(&self) -> usize {
        match self {
            Self::Constants(index) => index.0,
            Self::Bits(index) => index.0,
            Self::Type(index) => index.0,
            Self::Structure(index) => index.0,
            Self::Union(index) => index.0,
            Self::Aliases(index) => index.0,
        }
    }
}

impl From<(&StructuresPartTables, usize)> for StructuresPartTablesIndex {
    fn from(tables_and_raw_index: (&StructuresPartTables, usize)) -> Self {
        let tables = tables_and_raw_index.0;
        let raw_index = tables_and_raw_index.1;
        match *tables.tables[raw_index].borrow() {
            StructuresPartTable::Constants(_) => {
                Self::Constants(StructuresPartTablesConstantsIndex(raw_index))
            }
            StructuresPartTable::Bits(_) => Self::Bits(StructuresPartTablesBitsIndex(raw_index)),
            StructuresPartTable::Type(_) => Self::Type(StructuresPartTablesTypeIndex(raw_index)),
            StructuresPartTable::Structure(_) => {
                Self::Structure(StructuresPartTablesStructureIndex(raw_index))
            }
            StructuresPartTable::Union(_) => Self::Union(StructuresPartTablesUnionIndex(raw_index)),
            StructuresPartTable::Aliases(_) => {
                Self::Aliases(StructuresPartTablesAliasesIndex(raw_index))
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuresPartTablesConstantIndex(pub StructuresPartTablesConstantsIndex, pub usize);

impl From<StructuresPartTablesConstantIndex> for StructuresPartTablesConstantsIndex {
    fn from(value: StructuresPartTablesConstantIndex) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct StructuresPartTablesAliasIndex(StructuresPartTablesAliasesIndex, usize);

impl From<StructuresPartTablesAliasIndex> for StructuresPartTablesAliasesIndex {
    fn from(value: StructuresPartTablesAliasIndex) -> Self {
        value.0
    }
}

pub struct StructuresPartTablesIndexIterator<'a> {
    tables: &'a StructuresPartTables,
    cur_raw_index: usize,
}

impl<'a> StructuresPartTablesIndexIterator<'a> {
    fn new(tables: &'a StructuresPartTables) -> Self {
        Self {
            tables,
            cur_raw_index: 0,
        }
    }
}

impl<'a> Iterator for StructuresPartTablesIndexIterator<'a> {
    type Item = StructuresPartTablesIndex;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_raw_index == self.tables.tables.len() {
            None
        } else {
            let cur_raw_index = self.cur_raw_index;
            self.cur_raw_index += 1;
            Some(StructuresPartTablesIndex::from((
                self.tables,
                cur_raw_index,
            )))
        }
    }
}

struct StructuresPartTablesAliasIterator<'a> {
    structures: &'a StructuresPartTables,
    cur: Option<StructuresPartTablesAliasIndex>,
}

impl<'a> StructuresPartTablesAliasIterator<'a> {
    fn new(structures: &'a StructuresPartTables, name: &str) -> Self {
        Self {
            structures,
            cur: structures.name_to_alias.get(name).copied(),
        }
    }
}

impl<'a> Iterator for StructuresPartTablesAliasIterator<'a> {
    type Item = StructuresPartTablesAliasIndex;

    fn next(&mut self) -> Option<Self::Item> {
        match self.cur {
            Some(cur) => {
                let alias = self.structures.get_alias(cur);
                self.cur = self.structures.name_to_alias.get(&alias.target).copied();
                Some(cur)
            }
            None => None,
        }
    }
}

struct StructuresPartTablesAliasRefIterator<'a> {
    it: StructuresPartTablesAliasIterator<'a>,
}

impl<'a> Iterator for StructuresPartTablesAliasRefIterator<'a> {
    type Item = cell::Ref<'a, AliasesTableEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.it.next().map(|i| self.it.structures.get_alias(i))
    }
}

enum StructuresPartTablesTranslatedAlias<'a> {
    Original(&'a str),
    Translated(cell::Ref<'a, AliasesTableEntry>),
}

impl<'a> Deref for StructuresPartTablesTranslatedAlias<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Original(s) => s,
            Self::Translated(alias) => &alias.target,
        }
    }
}

enum UnionSelectorIteratorInternIterator<'a> {
    Constant {
        table: cell::Ref<'a, ConstantsTable>,
        table_index: StructuresPartTablesConstantsIndex,
        i: usize,
    },
    Type {
        table: cell::Ref<'a, TypeTable>,
        table_index: StructuresPartTablesTypeIndex,
        i: usize,
    },
}

pub enum UnionSelectorIteratorValue<'a> {
    Constant(&'a ConstantsTableEntry, StructuresPartTablesConstantIndex),
    Type(&'a TypeTableEntry, StructuresPartTablesTypeIndex, usize),
}

impl<'a> UnionSelectorIteratorValue<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            Self::Constant(entry, _) => &entry.name,
            Self::Type(entry, _, _) => match &entry.values {
                ValueRange::Discrete(values) => {
                    assert_eq!(values.len(), 1);
                    match &values[0].op {
                        ExprOp::Id(id) => &id.name,
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            },
        }
    }

    pub fn config_deps(&self) -> &'a ConfigDeps {
        match self {
            Self::Constant(entry, _) => &entry.deps,
            Self::Type(entry, _, _) => &entry.deps,
        }
    }

    pub fn is_conditional(&self) -> bool {
        match self {
            Self::Constant(_, _) => false,
            Self::Type(entry, _, _) => entry.conditional,
        }
    }
}

pub struct UnionSelectorIterator<'a> {
    it: UnionSelectorIteratorInternIterator<'a>,
    enable_conditional: bool,
}

impl<'a> UnionSelectorIterator<'a> {
    pub fn new(
        structures: &'a StructuresPartTables,
        discriminant_type_index: StructureTableEntryResolvedDiscriminantType,
        enable_conditional: bool,
    ) -> Self {
        match discriminant_type_index {
            StructureTableEntryResolvedDiscriminantType::Constants(index) => {
                let table = structures.get_constants(index);
                assert!(table.enum_like);
                let it = UnionSelectorIteratorInternIterator::Constant {
                    table,
                    table_index: index,
                    i: 0,
                };
                Self {
                    it,
                    enable_conditional,
                }
            }
            StructureTableEntryResolvedDiscriminantType::Type(index) => {
                let table = structures.get_type(index);
                assert!(table.enum_like);
                let it = UnionSelectorIteratorInternIterator::Type {
                    table,
                    table_index: index,
                    i: 0,
                };
                Self {
                    it,
                    enable_conditional,
                }
            }
        }
    }
}

impl<'a> Iterator for UnionSelectorIterator<'a> {
    type Item = UnionSelectorIteratorValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.it {
            UnionSelectorIteratorInternIterator::Constant {
                table,
                table_index,
                i,
            } => loop {
                if *i == table.entries.len() {
                    break None;
                } else {
                    let entry_index = *i;
                    *i += 1;
                    let entry = &table.entries[entry_index];
                    if !entry.is_helper_duplicate {
                        let entry = unsafe {
                            std::mem::transmute::<&ConstantsTableEntry, &'a ConstantsTableEntry>(
                                entry,
                            )
                        };
                        let constant_index =
                            StructuresPartTablesConstantIndex(*table_index, entry_index);
                        break Some(UnionSelectorIteratorValue::Constant(entry, constant_index));
                    }
                }
            },
            UnionSelectorIteratorInternIterator::Type {
                table,
                table_index,
                i,
            } => loop {
                if *i == table.entries.len() {
                    break None;
                } else {
                    let entry_index = *i;
                    *i += 1;
                    let entry = &table.entries[entry_index];
                    if !entry.conditional || self.enable_conditional {
                        let entry = unsafe {
                            std::mem::transmute::<&TypeTableEntry, &'a TypeTableEntry>(entry)
                        };
                        break Some(UnionSelectorIteratorValue::Type(
                            entry,
                            *table_index,
                            entry_index,
                        ));
                    }
                }
            },
        }
    }
}
