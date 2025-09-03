// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;
use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use structures::expr::{Expr, ExprId, ExprOp, ExprResolvedId, ExprValue};
use structures::predefined::PredefinedTypeRef;
use structures::structure_table::{
    StructureTable, StructureTableEntry, StructureTableEntryDiscriminantType,
    StructureTableEntryResolvedBaseType, StructureTableEntryResolvedDiscriminantType,
    StructureTableEntryType, StructureTableEntryUnionType,
};
use structures::table_common::ClosureDepsFlags;
use structures::tables::{
    StructuresPartTablesConstantIndex, StructuresPartTablesStructureIndex,
    StructuresPartTablesUnionIndex, UnionSelectorIterator, UnionSelectorIteratorValue,
};
use structures::union_table::{UnionTable, UnionTableEntryType};

use super::{Tpm2InterfaceRustCodeGenerator, code_writer};

mod into_bufs_owner_impl;
mod marshal_impl;
mod marshalled_size_impl;
mod tagged_union_conversions;
mod try_clone_impl;
mod unmarshal_impl;

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn to_structure_discriminant_entry_type(
        entry_type: &StructureTableEntryType,
    ) -> &StructureTableEntryDiscriminantType {
        match entry_type {
            StructureTableEntryType::Discriminant(discriminant_type) => discriminant_type,
            _ => unreachable!(),
        }
    }

    fn to_structure_union_entry_type(
        entry_type: &StructureTableEntryType,
    ) -> &StructureTableEntryUnionType {
        match entry_type {
            StructureTableEntryType::Union(union_type) => union_type,
            _ => unreachable!(),
        }
    }

    fn structure_plain_member_references_inbuf(
        &self,
        resolved_plain_type: &StructureTableEntryResolvedBaseType,
    ) -> bool {
        match resolved_plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_) => false,
            StructureTableEntryResolvedBaseType::Constants(_) => false,
            StructureTableEntryResolvedBaseType::Bits(_) => false,
            StructureTableEntryResolvedBaseType::Type(_) => false,
            StructureTableEntryResolvedBaseType::Structure(i) => {
                self.structure_references_inbuf(&self.tables.structures.get_structure(*i))
            }
        }
    }

    fn union_member_references_inbuf(&self, entry_type: &UnionTableEntryType) -> bool {
        match entry_type {
            UnionTableEntryType::Plain(plain_type) => {
                if let Some(plain_type) = plain_type.resolved_base_type.as_ref() {
                    self.structure_plain_member_references_inbuf(plain_type)
                } else {
                    false
                }
            }
            UnionTableEntryType::Array(array_type) => {
                match array_type.resolved_element_type.as_ref().unwrap() {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        predefined.bits == 8 && !predefined.signed
                    }
                    _ => self.structure_plain_member_references_inbuf(
                        array_type.resolved_element_type.as_ref().unwrap(),
                    ),
                }
            }
        }
    }

    fn union_references_inbuf(
        &self,
        discriminant_type: &StructureTableEntryResolvedDiscriminantType,
        union_table: &UnionTable,
    ) -> bool {
        for selector in
            UnionSelectorIterator::new(&self.tables.structures, *discriminant_type, true)
        {
            let entry = union_table.lookup_member(selector.name()).unwrap();
            let entry = &union_table.entries[entry];
            if self.union_member_references_inbuf(&entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn structure_member_references_inbuf(
        &self,
        table: &StructureTable,
        entry_type: &StructureTableEntryType,
    ) -> bool {
        match entry_type {
            StructureTableEntryType::Plain(plain_type) => self
                .structure_plain_member_references_inbuf(
                    plain_type.resolved_base_type.as_ref().unwrap(),
                ),
            StructureTableEntryType::Discriminant(_) => false,
            StructureTableEntryType::Union(union_type) => {
                let discriminant_entry = union_type.resolved_discriminant.unwrap();
                let discriminant_entry = &table.entries[discriminant_entry];
                let discriminant_type =
                    Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);
                let discriminant_type = discriminant_type
                    .resolved_discriminant_type
                    .as_ref()
                    .unwrap();
                let union_table = self
                    .tables
                    .structures
                    .get_union(union_type.resolved_union_type.unwrap());
                self.union_references_inbuf(discriminant_type, &union_table)
            }
            StructureTableEntryType::Array(array_type) => {
                match array_type.resolved_element_type.as_ref().unwrap() {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        predefined.bits == 8 && !predefined.signed
                    }
                    _ => self.structure_plain_member_references_inbuf(
                        array_type.resolved_element_type.as_ref().unwrap(),
                    ),
                }
            }
        }
    }

    pub(in super::super) fn structure_references_inbuf(&self, table: &StructureTable) -> bool {
        for entry in table.entries.iter() {
            if self.structure_member_references_inbuf(table, &entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn structure_plain_member_contains_array(
        &self,
        resolved_plain_type: &StructureTableEntryResolvedBaseType,
    ) -> bool {
        match resolved_plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_) => false,
            StructureTableEntryResolvedBaseType::Constants(_) => false,
            StructureTableEntryResolvedBaseType::Bits(_) => false,
            StructureTableEntryResolvedBaseType::Type(_) => false,
            StructureTableEntryResolvedBaseType::Structure(i) => {
                self.structure_contains_array(&self.tables.structures.get_structure(*i))
            }
        }
    }

    fn union_member_contains_array(&self, entry_type: &UnionTableEntryType) -> bool {
        match entry_type {
            UnionTableEntryType::Plain(plain_type) => {
                if let Some(plain_type) = plain_type.resolved_base_type.as_ref() {
                    self.structure_plain_member_contains_array(plain_type)
                } else {
                    false
                }
            }
            UnionTableEntryType::Array(_) => true,
        }
    }

    fn union_contains_array(
        &self,
        discriminant_type: &StructureTableEntryResolvedDiscriminantType,
        union_table: &UnionTable,
    ) -> bool {
        for selector in
            UnionSelectorIterator::new(&self.tables.structures, *discriminant_type, true)
        {
            let entry = union_table.lookup_member(selector.name()).unwrap();
            let entry = &union_table.entries[entry];
            if self.union_member_contains_array(&entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn structure_member_contains_array(
        &self,
        table: &StructureTable,
        entry_type: &StructureTableEntryType,
    ) -> bool {
        match entry_type {
            StructureTableEntryType::Plain(plain_type) => self
                .structure_plain_member_contains_array(
                    plain_type.resolved_base_type.as_ref().unwrap(),
                ),
            StructureTableEntryType::Discriminant(_) => false,
            StructureTableEntryType::Union(union_type) => {
                let discriminant_entry = union_type.resolved_discriminant.unwrap();
                let discriminant_entry = &table.entries[discriminant_entry];
                let discriminant_type =
                    Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);
                let discriminant_type = discriminant_type
                    .resolved_discriminant_type
                    .as_ref()
                    .unwrap();
                let union_table = self
                    .tables
                    .structures
                    .get_union(union_type.resolved_union_type.unwrap());
                self.union_contains_array(discriminant_type, &union_table)
            }
            StructureTableEntryType::Array(_) => true,
        }
    }

    pub(in super::super) fn structure_contains_array(&self, table: &StructureTable) -> bool {
        for entry in table.entries.iter() {
            if self.structure_member_contains_array(table, &entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn tagged_union_contains_array(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
    ) -> bool {
        for k in discriminant.discriminated_union_members.iter() {
            let union_member_entry = &table.entries[*k];
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            if self.union_contains_array(
                discriminant.resolved_discriminant_type.as_ref().unwrap(),
                &union_table,
            ) {
                return true;
            }
        }
        false
    }

    fn structure_plain_member_contains_nonbyte_array(
        &self,
        resolved_plain_type: &StructureTableEntryResolvedBaseType,
    ) -> bool {
        match resolved_plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_) => false,
            StructureTableEntryResolvedBaseType::Constants(_) => false,
            StructureTableEntryResolvedBaseType::Bits(_) => false,
            StructureTableEntryResolvedBaseType::Type(_) => false,
            StructureTableEntryResolvedBaseType::Structure(i) => {
                self.structure_contains_nonbyte_array(&self.tables.structures.get_structure(*i))
            }
        }
    }

    fn union_member_contains_nonbyte_array(&self, entry_type: &UnionTableEntryType) -> bool {
        match entry_type {
            UnionTableEntryType::Plain(plain_type) => {
                if let Some(plain_type) = plain_type.resolved_base_type.as_ref() {
                    self.structure_plain_member_contains_nonbyte_array(plain_type)
                } else {
                    false
                }
            }
            UnionTableEntryType::Array(array_type) => {
                match array_type.resolved_element_type.as_ref().unwrap() {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        predefined.bits != 8 || predefined.signed
                    }
                    _ => true,
                }
            }
        }
    }

    fn union_contains_nonbyte_array(
        &self,
        discriminant_type: &StructureTableEntryResolvedDiscriminantType,
        union_table: &UnionTable,
    ) -> bool {
        for selector in
            UnionSelectorIterator::new(&self.tables.structures, *discriminant_type, true)
        {
            let entry = union_table.lookup_member(selector.name()).unwrap();
            let entry = &union_table.entries[entry];
            if self.union_member_contains_nonbyte_array(&entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn structure_member_contains_nonbyte_array(
        &self,
        table: &StructureTable,
        entry_type: &StructureTableEntryType,
    ) -> bool {
        match entry_type {
            StructureTableEntryType::Plain(plain_type) => self
                .structure_plain_member_contains_nonbyte_array(
                    plain_type.resolved_base_type.as_ref().unwrap(),
                ),
            StructureTableEntryType::Discriminant(_) => false,
            StructureTableEntryType::Union(union_type) => {
                let discriminant_entry = union_type.resolved_discriminant.unwrap();
                let discriminant_entry = &table.entries[discriminant_entry];
                let discriminant_type =
                    Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);
                let discriminant_type = discriminant_type
                    .resolved_discriminant_type
                    .as_ref()
                    .unwrap();
                let union_table = self
                    .tables
                    .structures
                    .get_union(union_type.resolved_union_type.unwrap());
                self.union_contains_nonbyte_array(discriminant_type, &union_table)
            }
            StructureTableEntryType::Array(array_type) => {
                match array_type.resolved_element_type.as_ref().unwrap() {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        predefined.bits != 8 || predefined.signed
                    }
                    _ => true,
                }
            }
        }
    }

    fn structure_contains_nonbyte_array(&self, table: &StructureTable) -> bool {
        for entry in table.entries.iter() {
            if self.structure_member_contains_nonbyte_array(table, &entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn tagged_union_contains_nonbyte_array(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
    ) -> bool {
        for k in discriminant.discriminated_union_members.iter() {
            let union_member_entry = &table.entries[*k];
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            if self.union_contains_nonbyte_array(
                discriminant.resolved_discriminant_type.as_ref().unwrap(),
                &union_table,
            ) {
                return true;
            }
        }
        false
    }

    fn format_structure_member_array_type(
        &self,
        element_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        use_anon_lifetime: bool,
        enable_allocator_api: bool,
    ) -> String {
        if let StructureTableEntryResolvedBaseType::Predefined(predefined) = element_type {
            if predefined.bits == 8 && !predefined.signed {
                if !use_anon_lifetime {
                    if enable_allocator_api {
                        return "TpmBuffer<'a, A>".to_owned();
                    } else {
                        return "TpmBuffer<'a>".to_owned();
                    }
                } else {
                    if enable_allocator_api {
                        return "TpmBuffer::<'_, A>".to_owned();
                    } else {
                        return "TpmBuffer".to_owned();
                    }
                }
            }
        }

        "Vec<".to_owned()
            + &self.format_structure_member_plain_type(
                element_type,
                conditional,
                use_anon_lifetime,
                enable_allocator_api,
            )
            + enable_allocator_api.then_some(", A").unwrap_or("")
            + ">"
    }

    pub(in super::super) fn format_structure_member_plain_type(
        &self,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        use_anon_lifetime: bool,
        enable_allocator_api: bool,
    ) -> borrow::Cow<str> {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                borrow::Cow::Borrowed(Self::predefined_type_to_rust(*predefined))
            }
            StructureTableEntryResolvedBaseType::Constants(index) => {
                let table = self.tables.structures.get_constants(*index);
                borrow::Cow::Owned(Self::camelize(&table.name))
            }
            StructureTableEntryResolvedBaseType::Bits(index) => {
                let table = self.tables.structures.get_bits(*index);
                borrow::Cow::Owned(Self::camelize(&table.name))
            }
            StructureTableEntryResolvedBaseType::Type(index) => {
                let table = self.tables.structures.get_type(*index);
                let name = if table.conditional && conditional {
                    borrow::Cow::Owned(table.name.clone() + "_W_C_V")
                } else {
                    borrow::Cow::Borrowed(&table.name)
                };
                let name = Self::camelize(&name);
                borrow::Cow::Owned(name)
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                let (name, table_closure_deps) = if table.conditional && conditional {
                    (
                        borrow::Cow::Owned(table.name.clone() + "_W_C_V"),
                        &table.closure_deps_conditional,
                    )
                } else {
                    (borrow::Cow::Borrowed(&table.name), &table.closure_deps)
                };
                let mut name = Self::camelize(&name);
                if table_closure_deps.any(ClosureDepsFlags::ANY_DEFINITION)
                    && self.structure_contains_array(&table)
                {
                    if self.structure_references_inbuf(&table) {
                        if !use_anon_lifetime {
                            name += enable_allocator_api.then_some("<'a, A>").unwrap_or("<'a>")
                        } else if enable_allocator_api {
                            name += "::<'_, A>";
                        }
                    } else if enable_allocator_api {
                        if !use_anon_lifetime {
                            name += "<A>";
                        } else {
                            name += "::<A>";
                        }
                    }
                }
                borrow::Cow::Owned(name)
            }
        }
    }

    fn format_structure_member_name(name: &str) -> borrow::Cow<str> {
        let name = Self::uncamelize(name);

        if name == "type" {
            // "type" is a keyword in Rust
            borrow::Cow::Borrowed("typ")
        } else {
            borrow::Cow::Owned(name)
        }
    }

    fn format_structure_name(table: &StructureTable, conditional: bool) -> borrow::Cow<str> {
        if !table.conditional || !conditional {
            borrow::Cow::Borrowed(&table.name)
        } else {
            borrow::Cow::Owned(table.name.to_owned() + "_W_C_V")
        }
    }

    fn format_structure_discriminant_member_enum_name(
        table: &StructureTable,
        conditional: bool,
        discriminant_entry: &StructureTableEntry,
    ) -> String {
        let discriminant =
            Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);

        // If the discriminant type is not conditional, i.e. does not depend on
        // the containing structure's conditional flag, if any, introduce only a
        // single enum for the member.
        let table_name = if !discriminant.discriminant_type_conditional {
            borrow::Cow::Borrowed(table.name.as_str())
        } else {
            Self::format_structure_name(table, conditional)
        };

        let member_name = Self::format_structure_member_name(&discriminant_entry.name);
        table_name.to_string() + "_MEMBER_" + &member_name
    }

    fn tagged_union_references_inbuf(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
    ) -> bool {
        for k in discriminant.discriminated_union_members.iter() {
            let union_member_entry = &table.entries[*k];
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            if self.union_references_inbuf(
                discriminant.resolved_discriminant_type.as_ref().unwrap(),
                &union_table,
            ) {
                return true;
            }
        }
        false
    }

    fn tagged_union_member_references_inbuf(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
        selector: &str,
    ) -> bool {
        for k in discriminant.discriminated_union_members.iter() {
            let union_member_entry = &table.entries[*k];
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            let union_entry = union_table.lookup_member(selector).unwrap();
            let union_entry = &union_table.entries[union_entry];
            if self.union_member_references_inbuf(&union_entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn tagged_union_member_contains_array(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
        selector: &str,
    ) -> bool {
        for k in discriminant.discriminated_union_members.iter() {
            let union_member_entry = &table.entries[*k];
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            let union_entry = union_table.lookup_member(selector).unwrap();
            let union_entry = &union_table.entries[union_entry];
            if self.union_member_contains_array(&union_entry.entry_type) {
                return true;
            }
        }
        false
    }

    pub(super) fn format_tagged_union_member_value(
        &self,
        selector_value_index: StructuresPartTablesConstantIndex,
        base_type: PredefinedTypeRef,
    ) -> Result<(String, bool), ()> {
        let c = self.tables.structures.get_constant(selector_value_index);
        match &c.value.value.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(_) => (),
            _ => unreachable!(),
        };
        let e = ExprResolvedId::Constant(selector_value_index);
        let e = ExprId {
            name: c.name.clone(),
            resolved: Some(e),
        };
        let e = ExprOp::Id(e);
        let e = Expr {
            op: e,
            rdepth: 0,
            value: Some(c.value.value.as_ref().unwrap().clone()),
        };
        self.format_compiletime_const_expr_for_type(&e, base_type, "limits", None)
    }

    fn tagged_union_member_is_empty(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
        selector: &str,
    ) -> bool {
        for u in discriminant.discriminated_union_members.iter() {
            let u = &table.entries[*u];
            let union_type = Self::to_structure_union_entry_type(&u.entry_type);
            let union_type = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_type);
            let selected = union_table.lookup_member(selector).unwrap();
            let selected = &union_table.entries[selected];
            match &selected.entry_type {
                UnionTableEntryType::Plain(plain_type) => {
                    match &plain_type.resolved_base_type {
                        None => (),
                        _ => {
                            return false;
                        }
                    };
                }
                UnionTableEntryType::Array(_) => {
                    return false;
                }
            };
        }
        true
    }

    fn format_tagged_union_member_name(&self, selector: &UnionSelectorIteratorValue) -> String {
        match selector {
            UnionSelectorIteratorValue::Constant(_, constant_index) => {
                self.format_const_member_name(*constant_index)
            }
            UnionSelectorIteratorValue::Type(_, type_table_index, type_table_entry_index) => {
                let type_table = self.tables.structures.get_type(*type_table_index);
                self.format_enum_type_member_name(&type_table, *type_table_entry_index)
            }
        }
    }

    fn get_structure_selected_union_members(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
        selector: &UnionSelectorIteratorValue<'_>,
    ) -> Vec<(usize, StructuresPartTablesUnionIndex, usize)> {
        let mut selected_union_members = Vec::new();
        for u in discriminant.discriminated_union_members.iter() {
            let union_entry = &table.entries[*u];
            assert!(union_entry.deps.is_unconditional_true());
            let union_entry = Self::to_structure_union_entry_type(&union_entry.entry_type);
            let union_table_index = union_entry.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            let selected_member_index = union_table.lookup_member(selector.name()).unwrap();
            let selected_member = &union_table.entries[selected_member_index];

            match &selected_member.entry_type {
                UnionTableEntryType::Plain(plain_type) => {
                    match &plain_type.resolved_base_type {
                        None => continue, // Empty.
                        Some(_) => (),
                    };
                }
                UnionTableEntryType::Array(_) => (),
            };

            selected_union_members.push((*u, union_table_index, selected_member_index));
        }

        selected_union_members
    }

    fn gen_tagged_union_def<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        table_deps: &ConfigDepsDisjunction,
        discriminant_member: usize,
        _make_public: bool,
        mut conditional: bool,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error> {
        let entry = &table.entries[discriminant_member];
        assert!(entry.deps.is_unconditional_true());
        let entry = &entry.entry_type;
        let discriminant = Self::to_structure_discriminant_entry_type(entry);
        if !discriminant.discriminant_type_conditional {
            conditional = false;
        }
        let discriminant_base = match discriminant.resolved_discriminant_type.as_ref().unwrap() {
            StructureTableEntryResolvedDiscriminantType::Constants(i) => self
                .tables
                .structures
                .get_constants(*i)
                .resolved_base
                .unwrap(),
            StructureTableEntryResolvedDiscriminantType::Type(i) => {
                self.tables.structures.get_type(*i).underlying_type.unwrap()
            }
        };

        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            conditional | discriminant.discriminant_type_enable_conditional,
        ) {
            let deps = selector.config_deps().factor_by_common_of(table_deps);
            if !deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
            }

            let name = self.format_tagged_union_member_name(&selector);
            let name = Self::camelize(&name);

            let selector_value = match selector {
                UnionSelectorIteratorValue::Constant(_, constant_index) => constant_index,
                UnionSelectorIteratorValue::Type(_, type_table_index, type_table_entry_index) => {
                    let type_table = self.tables.structures.get_type(type_table_index);
                    type_table.get_enum_type_member_constant(type_table_entry_index)
                }
            };
            let selector_value = self
                .format_tagged_union_member_value(selector_value, discriminant_base)
                .map_err(|_| {
                    eprintln!(
                        "error: {}: integer overflow in {} selector expression",
                        &table.name,
                        selector.name()
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;

            // If the selector selects an empty field (without a type specified),
            // make the Rust-enum variant dataless.
            if self.tagged_union_member_is_empty(table, discriminant, selector.name()) {
                writeln!(out, "{} = {},", name, &selector_value.0)?;
                continue;
            }

            // Depending on the number of discriminanted union members, make the
            // Rust enum variants either tuple- or struct-like.
            if discriminant.discriminated_union_members.len() == 1 {
                let u = discriminant.discriminated_union_members[0];
                let u = &table.entries[u];
                assert!(u.deps.is_unconditional_true());
                let union_type = Self::to_structure_union_entry_type(&u.entry_type);
                let union_type = union_type.resolved_union_type.unwrap();
                let union_table = self.tables.structures.get_union(union_type);
                let selected = union_table.lookup_member(selector.name()).unwrap();
                let selected = &union_table.entries[selected];
                match &selected.entry_type {
                    UnionTableEntryType::Plain(plain_type) => {
                        match &plain_type.resolved_base_type {
                            None => unreachable!(),
                            Some(base_type) => {
                                let type_spec = self.format_structure_member_plain_type(
                                    base_type,
                                    plain_type.base_type_enable_conditional,
                                    false,
                                    enable_allocator_api,
                                );
                                writeln!(out, "{}({}) = {},", name, type_spec, selector_value.0)?;
                            }
                        };
                    }
                    UnionTableEntryType::Array(array_type) => {
                        let type_spec = self.format_structure_member_array_type(
                            array_type.resolved_element_type.as_ref().unwrap(),
                            array_type.element_type_enable_conditional,
                            false,
                            enable_allocator_api,
                        );
                        writeln!(out, "{}({}) = {},", name, type_spec, selector_value.0)?;
                    }
                };
            } else {
                writeln!(out, "{}{{", name)?;
                let mut iout = out.make_indent();
                for u in discriminant.discriminated_union_members.iter() {
                    let u = &table.entries[*u];
                    assert!(u.deps.is_unconditional_true());
                    let union_type = Self::to_structure_union_entry_type(&u.entry_type);
                    let union_type = union_type.resolved_union_type.unwrap();
                    let union_table = self.tables.structures.get_union(union_type);
                    let selected = union_table.lookup_member(selector.name()).unwrap();
                    let selected = &union_table.entries[selected];
                    match &selected.entry_type {
                        UnionTableEntryType::Plain(plain_type) => {
                            match &plain_type.resolved_base_type {
                                None => {
                                    // Skip empty union members
                                }
                                Some(base_type) => {
                                    let type_spec = self.format_structure_member_plain_type(
                                        base_type,
                                        plain_type.base_type_enable_conditional,
                                        false,
                                        enable_allocator_api,
                                    );
                                    writeln!(
                                        &mut iout,
                                        "{}: {},",
                                        Self::format_structure_member_name(&u.name),
                                        type_spec
                                    )?;
                                }
                            }
                        }
                        UnionTableEntryType::Array(array_type) => {
                            let type_spec = self.format_structure_member_array_type(
                                array_type.resolved_element_type.as_ref().unwrap(),
                                array_type.element_type_enable_conditional,
                                false,
                                enable_allocator_api,
                            );
                            writeln!(
                                &mut iout,
                                "{}: {},",
                                Self::format_structure_member_name(&u.name),
                                type_spec
                            )?;
                        }
                    };
                }
                writeln!(out, "}} = {},", selector_value.0)?;
            }
        }

        Ok(())
    }

    fn find_structure_array_size_specifier_members(
        table: &StructureTable,
    ) -> Vec<(usize, Vec<usize>)> {
        let mut array_size_specifier_members: Vec<(usize, Vec<usize>)> = Vec::new();

        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            match &entry.entry_type {
                StructureTableEntryType::Plain(_) => (),
                StructureTableEntryType::Discriminant(_) => (),
                StructureTableEntryType::Array(array_type) => {
                    array_type.size.map(&mut |e, _: &[()]| {
                        if let ExprOp::Id(id) = &e.op {
                            match id.resolved.as_ref().unwrap() {
                                ExprResolvedId::PredefinedConstant(_) => (),
                                ExprResolvedId::Constant(_) => (),
                                ExprResolvedId::StructMember(k) => {
                                    let pos = array_size_specifier_members
                                        .binary_search_by_key(k, |e| e.0);
                                    match pos {
                                        Ok(pos) => {
                                            array_size_specifier_members[pos].1.push(j);
                                        }
                                        Err(pos) => {
                                            array_size_specifier_members.insert(pos, (*k, vec![j]));
                                        }
                                    }
                                }
                            };
                        }
                    });
                }
                StructureTableEntryType::Union(_) => (),
            };
        }

        array_size_specifier_members
    }

    fn _gen_structure<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        conditional: bool,
        enable_allocator_api: bool,
        enable_enum_transmute: bool,
        enable_in_place_unmarshal: bool,
        enable_in_place_into_bufs_owner: bool,
    ) -> Result<(), io::Error> {
        let table_closure_deps = if !conditional {
            &table.closure_deps
        } else {
            &table.closure_deps_conditional
        };
        let table_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::all());
        if table_deps.is_empty() {
            return Ok(());
        }

        writeln!(out)?;
        if let Some(src_ref) = &table.info.src_ref {
            write!(out, "// {}, {} structure", src_ref, &table.name)?;
        } else {
            write!(out, "// {} structure", &table.name)?;
        }
        if !table.conditional {
            writeln!(out)?;
        } else if !conditional {
            writeln!(out, " (without conditional values)")?;
        } else {
            writeln!(out, " (with conditional values)")?;
        };

        let array_size_specifier_members = Self::find_structure_array_size_specifier_members(table);
        let is_array_size_specifier_member = |j: usize| -> bool {
            array_size_specifier_members
                .binary_search_by_key(&j, |e| e.0)
                .is_ok()
        };

        let mut is_tagged_union = true;
        let mut discriminant_members = Vec::new();
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    if !plain_type.is_size_specifier {
                        is_tagged_union = false;
                    }
                }
                StructureTableEntryType::Discriminant(_) => {
                    discriminant_members.push(j);
                }
                StructureTableEntryType::Array(_) => {
                    is_tagged_union = false;
                }
                StructureTableEntryType::Union(_) => (),
            };
        }
        if discriminant_members.len() != 1 {
            is_tagged_union = false;
        }

        let table_is_public = table_closure_deps
            .any(ClosureDepsFlags::PUBLIC_DEFINITION | ClosureDepsFlags::EXTERN_MAX_SIZE);
        let need_definition = table_closure_deps.any(ClosureDepsFlags::ANY_DEFINITION);
        if !need_definition {
            is_tagged_union = false;
        }
        let definition_is_public = table_closure_deps.any(ClosureDepsFlags::PUBLIC_DEFINITION);
        let table_name = Self::format_structure_name(table, conditional);
        let contains_array = self.structure_contains_array(table);
        let references_inbuf = if need_definition {
            self.structure_references_inbuf(table)
        } else {
            false
        };
        let need_impl = table_closure_deps.any(
            ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                | ClosureDepsFlags::ANY_SIZE
                | ClosureDepsFlags::EXTERN_MAX_SIZE,
        );
        let need_impl = need_impl
            || (contains_array && table_closure_deps.any(ClosureDepsFlags::ANY_TRY_CLONE))
            || (references_inbuf && table_closure_deps.any(ClosureDepsFlags::ANY_INTO_BUFS_OWNER));

        // If the size is fixed, the maximum on the marshalled size equals the fixed size and only a
        // single helper named accordingly will be provided.
        let need_max_size_impl = table_closure_deps.any(ClosureDepsFlags::ANY_MAX_SIZE)
            || (table_closure_deps.any(ClosureDepsFlags::ANY_SIZE)
                && Self::structure_has_fixed_size(table).0);

        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }

        if !need_definition {
            writeln!(out, "#[allow(unused)]")?;
        }

        if !contains_array {
            assert!(!references_inbuf);
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;
        } else if !references_inbuf {
            writeln!(out, "#[derive(Debug, PartialEq, Eq)]")?;
        } else {
            writeln!(out, "#[derive(Debug, PartialEq)]")?;
        }

        if is_tagged_union {
            let discriminant_member = discriminant_members[0];
            let discriminant = &table.entries[discriminant_member].entry_type;
            let discriminant = Self::to_structure_discriminant_entry_type(discriminant);
            let discriminant_base = match discriminant.resolved_discriminant_type.as_ref().unwrap()
            {
                StructureTableEntryResolvedDiscriminantType::Constants(i) => self
                    .tables
                    .structures
                    .get_constants(*i)
                    .resolved_base
                    .unwrap(),
                StructureTableEntryResolvedDiscriminantType::Type(i) => {
                    self.tables.structures.get_type(*i).underlying_type.unwrap()
                }
            };

            if enable_enum_transmute || enable_in_place_unmarshal {
                writeln!(
                    out,
                    "#[repr(C, {})]",
                    Self::predefined_type_to_rust(discriminant_base)
                )?;
            } else {
                writeln!(
                    out,
                    "#[repr({})]",
                    Self::predefined_type_to_rust(discriminant_base)
                )?;
            }
            if table_is_public {
                write!(out, "pub ")?
            }

            let gen_params_spec = if contains_array {
                if references_inbuf {
                    if enable_allocator_api {
                        ("<'a, A: Clone + Allocator>", "<'a, A>")
                    } else {
                        ("<'a>", "<'a>")
                    }
                } else if enable_allocator_api {
                    ("<A: Clone + Allocator>", "<A>")
                } else {
                    ("", "")
                }
            } else {
                ("", "")
            };
            writeln!(
                out,
                "enum {}{} {{",
                Self::camelize(&table_name),
                gen_params_spec.0
            )?;
            self.gen_tagged_union_def(
                &mut out.make_indent(),
                table,
                &table_deps,
                discriminant_member,
                definition_is_public,
                conditional,
                enable_allocator_api,
            )?;
            writeln!(out, "}}")?;

            if need_impl {
                writeln!(out)?;
                if !table_deps.is_unconditional_true() {
                    writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
                }
                writeln!(
                    out,
                    "impl{} {}{} {{",
                    gen_params_spec.0,
                    Self::camelize(&table_name),
                    gen_params_spec.1
                )?;
                let mut iout = out.make_indent();

                let mut first = true;
                if table_closure_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE) {
                    first = false;
                    self.gen_structure_marshalled_max_size(&mut iout, table, conditional)?;
                }

                if table_closure_deps.any(ClosureDepsFlags::ANY_SIZE) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_tagged_union_marshalled_size(
                        &mut iout,
                        table,
                        table_closure_deps,
                        &table_deps,
                        discriminant_member,
                        false,
                        conditional,
                        enable_allocator_api,
                    )?;
                }

                if table_closure_deps.any(ClosureDepsFlags::ANY_MARSHAL) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_tagged_union_marshal(
                        &mut iout,
                        table,
                        table_closure_deps,
                        &table_deps,
                        discriminant_member,
                        false,
                        conditional,
                        enable_allocator_api,
                        enable_enum_transmute,
                    )?;
                }

                if table_closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_tagged_union_unmarshal_intern(
                        &mut iout,
                        table,
                        table_closure_deps,
                        &table_deps,
                        &table_name,
                        discriminant_member,
                        false,
                        conditional,
                        enable_allocator_api,
                        enable_in_place_unmarshal,
                    )?;
                }

                if table_closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_structure_unmarshal(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                        enable_in_place_unmarshal,
                    )?;
                }

                if contains_array && table_closure_deps.any(ClosureDepsFlags::ANY_TRY_CLONE) {
                    if !first {
                        writeln!(iout)?;
                    }
                    first = false;
                    self.gen_tagged_union_try_clone(
                        &mut iout,
                        table,
                        table_closure_deps,
                        &table_deps,
                        &table_name,
                        discriminant_member,
                        conditional && discriminant.discriminant_type_conditional,
                        enable_allocator_api,
                    )?;
                }

                if references_inbuf && table_closure_deps.any(ClosureDepsFlags::ANY_INTO_BUFS_OWNER)
                {
                    if !first {
                        writeln!(iout)?;
                    }

                    self.gen_tagged_union_into_bufs_owner_intern(
                        &mut iout,
                        table,
                        table_closure_deps,
                        &table_deps,
                        &table_name,
                        discriminant_member,
                        conditional && discriminant.discriminant_type_conditional,
                        enable_allocator_api,
                        enable_in_place_into_bufs_owner,
                    )?;

                    if table_closure_deps.any(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER) {
                        writeln!(&mut iout)?;
                        self.gen_structure_into_bufs_owner(
                            &mut iout,
                            table,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                            enable_in_place_into_bufs_owner,
                        )?;
                    }
                }
                writeln!(out, "}}")?;
            }

            if need_max_size_impl {
                writeln!(out)?;
                self.gen_structure_marshalled_max_size_impl(
                    out,
                    table,
                    conditional,
                    enable_allocator_api,
                )?;
            }

            if table_closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                let discriminant_type = discriminant.resolved_discriminant_type.as_ref().unwrap();
                if match discriminant_type {
                    StructureTableEntryResolvedDiscriminantType::Constants(index) => {
                        let discriminant_table = self.tables.structures.get_constants(*index);
                        discriminant_table
                            .closure_deps
                            .any(ClosureDepsFlags::ANY_DEFINITION)
                    }
                    StructureTableEntryResolvedDiscriminantType::Type(index) => {
                        let discriminant_table = self.tables.structures.get_type(*index);
                        let discriminant_enable_conditional = conditional
                            && discriminant.discriminant_type_conditional
                            || discriminant.discriminant_type_enable_conditional;
                        if discriminant_enable_conditional {
                            discriminant_table
                                .closure_deps_conditional
                                .any(ClosureDepsFlags::ANY_DEFINITION)
                        } else {
                            discriminant_table
                                .closure_deps
                                .any(ClosureDepsFlags::ANY_DEFINITION)
                        }
                    }
                } {
                    writeln!(out)?;
                    self.gen_tagged_union_to_discriminant(
                        out,
                        table,
                        table_closure_deps,
                        &table_name,
                        discriminant_member,
                        conditional && discriminant.discriminant_type_conditional,
                        enable_allocator_api,
                        enable_enum_transmute,
                    )?;
                }
            }

            if conditional && table.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                assert!(discriminant.discriminant_type_conditional);
                // Emit conversion primitives between the conditional and non-conditional
                // variants.
                writeln!(out)?;
                self.gen_tagged_union_non_cond_cond_conversions(
                    out,
                    table,
                    discriminant_member,
                    false,
                    enable_allocator_api,
                )?;
            }

            if table_closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) && enable_in_place_unmarshal
            {
                writeln!(out)?;
                self.gen_tagged_union_layout_repr_struct(
                    out,
                    table,
                    table_closure_deps,
                    &table_name,
                    discriminant_member,
                    conditional,
                    enable_allocator_api,
                )?;
            }
        } else {
            if table_is_public {
                write!(out, "pub ")?
            }

            let gen_params_spec = if need_definition && contains_array {
                if references_inbuf {
                    if enable_allocator_api {
                        ("<'a, A: Clone + Allocator>", "<'a, A>")
                    } else {
                        ("<'a>", "<'a>")
                    }
                } else if enable_allocator_api {
                    ("<A: Clone + Allocator>", "<A>")
                } else {
                    ("", "")
                }
            } else {
                ("", "")
            };

            writeln!(
                out,
                "struct {}{} {{",
                Self::camelize(&table_name),
                gen_params_spec.0
            )?;
            let mut iout = out.make_indent();
            let pub_spec = if definition_is_public { "pub " } else { "" };

            if need_definition {
                for j in 0..table.entries.len() {
                    let entry = &table.entries[j];
                    let name = Self::format_structure_member_name(&entry.name);
                    match &entry.entry_type {
                        StructureTableEntryType::Plain(plain_type) => {
                            let deps = entry.deps.factor_by_common_of(&table_deps);
                            if !deps.is_unconditional_true() {
                                writeln!(
                                    &mut iout,
                                    "#[cfg({})]",
                                    Self::format_dep_conjunction(&deps)
                                )?;
                            }
                            if plain_type.is_size_specifier || is_array_size_specifier_member(j) {
                                continue;
                            }

                            let enable_conditional = if plain_type.base_type_enable_conditional {
                                true
                            } else if plain_type.base_type_conditional {
                                conditional
                            } else {
                                false
                            };
                            let type_spec = self.format_structure_member_plain_type(
                                plain_type.resolved_base_type.as_ref().unwrap(),
                                enable_conditional,
                                false,
                                enable_allocator_api,
                            );
                            writeln!(&mut iout, "{}{}: {},", pub_spec, name, type_spec)?;
                        }
                        StructureTableEntryType::Discriminant(_) => {
                            // The discriminant is handled once the first of the
                            // union members referencing it is encountered.
                            continue;
                        }
                        StructureTableEntryType::Union(union_type) => {
                            let entry = union_type.resolved_discriminant.unwrap();
                            let entry = &table.entries[entry];
                            let discriminant =
                                Self::to_structure_discriminant_entry_type(&entry.entry_type);
                            if j != discriminant.discriminated_union_members[0] {
                                continue;
                            }
                            assert!(entry.deps.is_unconditional_true());
                            let name = Self::format_structure_member_name(&entry.name);
                            let type_spec = Self::format_structure_discriminant_member_enum_name(
                                table,
                                conditional,
                                entry,
                            );
                            let type_spec = Self::camelize(&type_spec);
                            let gen_params_spec =
                                if self.tagged_union_contains_array(table, discriminant) {
                                    if enable_allocator_api {
                                        if self.tagged_union_references_inbuf(table, discriminant) {
                                            "<'a, A>"
                                        } else {
                                            "<A>"
                                        }
                                    } else {
                                        if self.tagged_union_references_inbuf(table, discriminant) {
                                            "<'a>"
                                        } else {
                                            ""
                                        }
                                    }
                                } else {
                                    ""
                                };
                            writeln!(
                                &mut iout,
                                "{}{}: {}{},",
                                pub_spec, name, type_spec, gen_params_spec
                            )?;
                        }
                        StructureTableEntryType::Array(array_type) => {
                            let deps = entry.deps.factor_by_common_of(&table_deps);
                            if !deps.is_unconditional_true() {
                                writeln!(
                                    &mut iout,
                                    "#[cfg({})]",
                                    Self::format_dep_conjunction(&deps)
                                )?;
                            }
                            let type_spec = self.format_structure_member_array_type(
                                array_type.resolved_element_type.as_ref().unwrap(),
                                conditional | array_type.element_type_enable_conditional,
                                false,
                                enable_allocator_api,
                            );
                            writeln!(&mut iout, "{}{}: {},", pub_spec, name, type_spec)?;
                        }
                    };
                }
            }
            writeln!(out, "}}")?;

            if need_impl {
                writeln!(out)?;
                if !table_deps.is_unconditional_true() {
                    writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
                }
                writeln!(
                    out,
                    "impl{} {}{} {{",
                    gen_params_spec.0,
                    Self::camelize(&table_name),
                    gen_params_spec.1
                )?;
                let mut iout = out.make_indent();
                let mut first = true;

                if table_closure_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE) {
                    first = false;
                    self.gen_structure_marshalled_max_size(&mut iout, table, conditional)?;
                }

                // In case the structure has fixed size, the
                // marshalled_max_size() does serve as a marshalled_size() (and
                // would be named accordingly). It might have been emitted in
                // the context of handling the ANY_MAX_SIZE closure dependencies
                // already.
                let (size_is_fixed, _) = Self::structure_has_fixed_size(table);
                if table_closure_deps.any(ClosureDepsFlags::ANY_SIZE)
                    && !(size_is_fixed && table_closure_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE))
                {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_structure_marshalled_size(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                    )?;
                }

                if table_closure_deps.any(ClosureDepsFlags::ANY_MARSHAL) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_structure_marshal(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                    )?;
                }

                if table_closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;

                    self.gen_structure_unmarshal_intern(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                        enable_in_place_unmarshal,
                    )?;
                }

                if table_closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_structure_unmarshal(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                        enable_in_place_unmarshal,
                    )?;
                }

                if contains_array && table_closure_deps.any(ClosureDepsFlags::ANY_TRY_CLONE) {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    self.gen_structure_try_clone(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                    )?;
                }

                if references_inbuf && table_closure_deps.any(ClosureDepsFlags::ANY_INTO_BUFS_OWNER)
                {
                    if !first {
                        writeln!(iout)?;
                    }

                    self.gen_structure_into_bufs_owner_intern(
                        &mut iout,
                        table,
                        conditional,
                        enable_allocator_api,
                        enable_in_place_into_bufs_owner,
                    )?;

                    if table_closure_deps.any(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER) {
                        writeln!(&mut iout)?;
                        self.gen_structure_into_bufs_owner(
                            &mut iout,
                            table,
                            conditional,
                            enable_allocator_api,
                            enable_in_place_into_bufs_owner,
                        )?;
                    }
                }

                writeln!(out, "}}")?;
            }

            if need_max_size_impl {
                writeln!(out)?;
                self.gen_structure_marshalled_max_size_impl(
                    out,
                    table,
                    conditional,
                    enable_allocator_api,
                )?;
            }

            // Now define all discriminant members' corresponding enum types.
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let discriminant = match &entry.entry_type {
                    StructureTableEntryType::Discriminant(discriminant) => discriminant,
                    _ => continue,
                };

                assert!(entry.deps.is_unconditional_true());
                if conditional
                    && !discriminant.discriminant_type_conditional
                    && table.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION)
                {
                    // Enum definition already emitted in the context of handling
                    // the containing structure with conditionals disabled.
                    continue;
                }

                let closure_deps = if !conditional {
                    let closure_deps = borrow::Cow::Borrowed(&table.closure_deps);
                    // If the sibling containing structure with conditionals enabled needs
                    // it as well, build the union deps.
                    if !discriminant.discriminant_type_conditional {
                        let mut closure_deps = closure_deps.into_owned();
                        closure_deps
                            .merge_from(borrow::Cow::Borrowed(&table.closure_deps_conditional));
                        borrow::Cow::Owned(closure_deps)
                    } else {
                        closure_deps
                    }
                } else {
                    borrow::Cow::Borrowed(&table.closure_deps_conditional)
                };
                if !closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                    continue;
                }

                let discriminant_base =
                    match discriminant.resolved_discriminant_type.as_ref().unwrap() {
                        StructureTableEntryResolvedDiscriminantType::Constants(i) => self
                            .tables
                            .structures
                            .get_constants(*i)
                            .resolved_base
                            .unwrap(),
                        StructureTableEntryResolvedDiscriminantType::Type(i) => {
                            self.tables.structures.get_type(*i).underlying_type.unwrap()
                        }
                    };

                let mut make_public = definition_is_public;
                // If the sibling containing structure with conditionals enabled needs
                // it, and is public, make the member's enum public as well.
                if !make_public && closure_deps.any(ClosureDepsFlags::PUBLIC_DEFINITION) {
                    make_public = true;
                }

                writeln!(out)?;
                let table_deps = closure_deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
                if !table_deps.is_unconditional_true() {
                    writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
                }

                let type_name =
                    Self::format_structure_discriminant_member_enum_name(table, conditional, entry);
                let type_spec = Self::camelize(&type_name);
                let contains_array = self.tagged_union_contains_array(table, discriminant);
                let references_inbuf = self.tagged_union_references_inbuf(table, discriminant);
                let gen_params_spec = if self.tagged_union_contains_array(table, discriminant) {
                    if self.tagged_union_references_inbuf(table, discriminant) {
                        if enable_allocator_api {
                            ("<'a, A: Clone + Allocator>", "<'a, A>")
                        } else {
                            ("<'a>", "<'a>")
                        }
                    } else if enable_allocator_api {
                        ("<A: Clone + Allocator>", "<A>")
                    } else {
                        ("", "")
                    }
                } else {
                    ("", "")
                };

                if !contains_array {
                    assert!(!references_inbuf);
                    writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;
                } else if !references_inbuf {
                    writeln!(out, "#[derive(Debug, PartialEq, Eq)]")?;
                } else {
                    writeln!(out, "#[derive(Debug, PartialEq)]")?;
                }

                if enable_enum_transmute || enable_in_place_unmarshal {
                    writeln!(
                        out,
                        "#[repr(C, {})]",
                        Self::predefined_type_to_rust(discriminant_base)
                    )?;
                } else {
                    writeln!(
                        out,
                        "#[repr({})]",
                        Self::predefined_type_to_rust(discriminant_base)
                    )?;
                }
                let pub_spec = if make_public { "pub " } else { "" };
                writeln!(
                    out,
                    "{}enum {}{} {{",
                    pub_spec, type_spec, gen_params_spec.0
                )?;
                self.gen_tagged_union_def(
                    &mut out.make_indent(),
                    table,
                    &table_deps,
                    j,
                    make_public,
                    conditional && discriminant.discriminant_type_conditional,
                    enable_allocator_api,
                )?;
                writeln!(out, "}}")?;

                let need_impl = closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL)
                    || (contains_array && closure_deps.any(ClosureDepsFlags::ANY_TRY_CLONE))
                    || (references_inbuf
                        && closure_deps.any(ClosureDepsFlags::ANY_INTO_BUFS_OWNER));
                if need_impl {
                    writeln!(out)?;
                    if !table_deps.is_unconditional_true() {
                        writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
                    }
                    writeln!(
                        out,
                        "impl{} {}{} {{",
                        gen_params_spec.0, type_spec, gen_params_spec.1
                    )?;
                    let mut first = true;
                    let mut iout = out.make_indent();
                    if closure_deps.any(ClosureDepsFlags::ANY_SIZE) {
                        if !first {
                            writeln!(iout)?;
                        }
                        first = false;
                        self.gen_tagged_union_marshalled_size(
                            &mut iout,
                            table,
                            &closure_deps,
                            &table_deps,
                            j,
                            true,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                        )?;
                    }

                    if closure_deps.any(ClosureDepsFlags::ANY_MARSHAL) {
                        if !first {
                            writeln!(iout)?;
                        }
                        first = false;
                        self.gen_tagged_union_marshal(
                            &mut iout,
                            table,
                            table_closure_deps,
                            &table_deps,
                            j,
                            true,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                            enable_enum_transmute,
                        )?;
                    }

                    if closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) {
                        if !first {
                            writeln!(iout)?;
                        }
                        first = false;
                        self.gen_tagged_union_unmarshal_intern(
                            &mut iout,
                            table,
                            &closure_deps,
                            &table_deps,
                            &type_name,
                            j,
                            true,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                            enable_in_place_unmarshal,
                        )?;
                    }

                    if contains_array && closure_deps.any(ClosureDepsFlags::ANY_TRY_CLONE) {
                        if !first {
                            writeln!(iout)?;
                        }
                        first = false;
                        self.gen_tagged_union_try_clone(
                            &mut iout,
                            table,
                            &closure_deps,
                            &table_deps,
                            &type_name,
                            j,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                        )?;
                    }

                    if references_inbuf && closure_deps.any(ClosureDepsFlags::ANY_INTO_BUFS_OWNER) {
                        if !first {
                            writeln!(iout)?;
                        }

                        self.gen_tagged_union_into_bufs_owner_intern(
                            &mut iout,
                            table,
                            &closure_deps,
                            &table_deps,
                            &type_name,
                            j,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                            enable_in_place_into_bufs_owner,
                        )?;
                    }
                    writeln!(out, "}}")?;
                }

                if table_closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                    let discriminant_type =
                        discriminant.resolved_discriminant_type.as_ref().unwrap();
                    if match discriminant_type {
                        StructureTableEntryResolvedDiscriminantType::Constants(index) => {
                            let discriminant_table = self.tables.structures.get_constants(*index);
                            discriminant_table
                                .closure_deps
                                .any(ClosureDepsFlags::ANY_DEFINITION)
                        }
                        StructureTableEntryResolvedDiscriminantType::Type(index) => {
                            let discriminant_table = self.tables.structures.get_type(*index);
                            let discriminant_enable_conditional = conditional
                                && discriminant.discriminant_type_conditional
                                || discriminant.discriminant_type_enable_conditional;
                            if discriminant_enable_conditional {
                                discriminant_table
                                    .closure_deps_conditional
                                    .any(ClosureDepsFlags::ANY_DEFINITION)
                            } else {
                                discriminant_table
                                    .closure_deps
                                    .any(ClosureDepsFlags::ANY_DEFINITION)
                            }
                        }
                    } {
                        writeln!(out)?;
                        self.gen_tagged_union_to_discriminant(
                            out,
                            table,
                            &closure_deps,
                            &type_name,
                            j,
                            conditional && discriminant.discriminant_type_conditional,
                            enable_allocator_api,
                            enable_enum_transmute,
                        )?;
                    }
                }

                if conditional && table.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                    assert!(discriminant.discriminant_type_conditional);
                    // Emit conversion primitives between the conditional and non-conditional
                    // variants.
                    writeln!(out)?;
                    self.gen_tagged_union_non_cond_cond_conversions(
                        out,
                        table,
                        j,
                        true,
                        enable_allocator_api,
                    )?;
                }

                if closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) && enable_in_place_unmarshal {
                    writeln!(out)?;
                    self.gen_tagged_union_layout_repr_struct(
                        out,
                        table,
                        &closure_deps,
                        &type_name,
                        j,
                        conditional,
                        enable_allocator_api,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn gen_structure<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        index: StructuresPartTablesStructureIndex,
        enable_allocator_api: bool,
        enable_enum_transmute: bool,
        enable_in_place_unmarshal: bool,
        enable_in_place_into_bufs_owner: bool,
    ) -> Result<(), io::Error> {
        let table = self.tables.structures.get_structure(index);
        self._gen_structure(
            out,
            &table,
            false,
            enable_allocator_api,
            enable_enum_transmute,
            enable_in_place_unmarshal,
            enable_in_place_into_bufs_owner,
        )?;
        if table.conditional {
            self._gen_structure(
                out,
                &table,
                true,
                enable_allocator_api,
                enable_enum_transmute,
                enable_in_place_unmarshal,
                enable_in_place_into_bufs_owner,
            )?;
        }

        Ok(())
    }
}
