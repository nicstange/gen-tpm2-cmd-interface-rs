// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;
use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use crate::tcg_tpm2::structures::table_common::ClosureDeps;
use crate::tcg_tpm2::structures::union_table::UnionTableEntryType;
use structures::structure_table::{
    StructureTable, StructureTableEntryResolvedBaseType, StructureTableEntryType,
};
use structures::table_common::ClosureDepsFlags;
use structures::tables::UnionSelectorIterator;

use super::super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn gen_structure_into_bufs_owner_intern<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        conditional: bool,
        enable_in_place_into_bufs_owner: bool,
    ) -> Result<(), io::Error> {
        let table_closure_deps = if !conditional {
            &table.closure_deps
        } else {
            &table.closure_deps_conditional
        };
        let table_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::all());

        let mut into_bufs_owner_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_INTO_BUFS_OWNER);
        into_bufs_owner_deps.factor_by_common_of(&table_deps);
        if !into_bufs_owner_deps.is_implied_by(&table_deps) {
            writeln!(
                out,
                "#[cfg({})]",
                Self::format_deps(&into_bufs_owner_deps)
            )?;
        }
        if !enable_in_place_into_bufs_owner {
            let array_size_specifier_members =
                Self::find_structure_array_size_specifier_members(table);
            let is_array_size_specifier_member = |j: usize| -> bool {
                array_size_specifier_members
                    .binary_search_by_key(&j, |e| e.0)
                    .is_ok()
            };

            let table_name = Self::camelize(&Self::format_structure_name(table, conditional));
            writeln!(
                out,
                "fn into_bufs_owner_intern(self) -> Result<{}<'static>, TpmErr> {{",
                table_name
            )?;
            let mut iout = out.make_indent();
            // Step1: destructure self with limited lifetime 'a.
            writeln!(&mut iout, "let Self {{")?;
            let mut iiout = iout.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let (name, deps) = match &entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => {
                        if plain_type.is_size_specifier || is_array_size_specifier_member(j) {
                            continue;
                        }
                        (borrow::Cow::Borrowed(entry.name.as_str()), &entry.deps)
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
                        if !self.tagged_union_references_inbuf(table, discriminant) {
                            continue;
                        }
                        (borrow::Cow::Borrowed(entry.name.as_str()), &entry.deps)
                    }
                    _ => (borrow::Cow::Borrowed(entry.name.as_str()), &entry.deps),
                };

                let deps = deps.factor_by_common_of(&table_deps);
                let deps = deps.factor_by_common_of(&into_bufs_owner_deps);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                writeln!(&mut iiout, "{},", Self::format_structure_member_name(&name))?;
            }
            writeln!(&mut iout, "}} = self;")?;

            // Step 2: own members as needed
            writeln!(&mut iout)?;
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&table_deps);
                let deps = deps.factor_by_common_of(&into_bufs_owner_deps);
                match &entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => {
                        let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                        if !self.structure_plain_member_references_inbuf(base_type) {
                            continue;
                        }
                        let name = Self::format_structure_member_name(&entry.name);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };
                        writeln!(
                            &mut iiout,
                            "let {} = {}.into_bufs_owner_intern()?;",
                            name, name
                        )?;
                        if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "}}")?;
                        }
                    }
                    StructureTableEntryType::Array(array_type) => {
                        match array_type.resolved_element_type.as_ref().unwrap() {
                            StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                if predefined.bits == 8 && !predefined.signed {
                                    let name = Self::format_structure_member_name(&entry.name);
                                    let mut iiout = if !deps.is_unconditional_true() {
                                        writeln!(
                                            &mut iout,
                                            "#[cfg({})]",
                                            Self::format_dep_conjunction(&deps)
                                        )?;
                                        writeln!(&mut iout, "{{")?;
                                        iout.make_indent()
                                    } else {
                                        iout.make_same_indent()
                                    };
                                    writeln!(&mut iiout, "let {} = {}.into_owned()?;", name, name)?;
                                    if !deps.is_unconditional_true() {
                                        writeln!(&mut iout, "}}")?;
                                    }
                                }
                            }
                            _ => {
                                if self.structure_plain_member_references_inbuf(
                                    array_type.resolved_element_type.as_ref().unwrap(),
                                ) {
                                    let name = Self::format_structure_member_name(&entry.name);
                                    let mut iiout = if !deps.is_unconditional_true() {
                                        writeln!(
                                            &mut iout,
                                            "#[cfg({})]",
                                            Self::format_dep_conjunction(&deps)
                                        )?;
                                        writeln!(&mut iout, "{{")?;
                                        iout.make_indent()
                                    } else {
                                        iout.make_same_indent()
                                    };
                                    writeln!(&mut iiout, "let mut {}_orig = {};", name, name)?;
                                    writeln!(&mut iiout, "let mut {} = Vec::new();", name)?;
                                    writeln!(
                                        &mut iiout,
                                        "{}.try_reserve_exact({}_orig.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;",
                                        name, name
                                    )?;
                                    writeln!(
                                        &mut iiout,
                                        "for element in {}_orig.drain(..) {{",
                                        name
                                    )?;
                                    writeln!(
                                        &mut iiout.make_indent(),
                                        "{}.push(element.into_bufs_owner_intern()?);",
                                        name
                                    )?;
                                    writeln!(&mut iiout, "}}")?;
                                    if !deps.is_unconditional_true() {
                                        writeln!(&mut iout, "}}")?;
                                    }
                                }
                            }
                        };
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
                        if !self.tagged_union_references_inbuf(table, discriminant) {
                            continue;
                        }
                        let name = Self::format_structure_member_name(&entry.name);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };
                        writeln!(
                            &mut iiout,
                            "let {} = {}.into_bufs_owner_intern()?;",
                            name, name
                        )?;
                        if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "}}")?;
                        }
                    }
                };
            }

            // Step 3: reconstruct a Self with 'static lifetime.
            writeln!(&mut iout)?;
            writeln!(&mut iout, "Ok({} {{", table_name)?;
            let mut iiout = iout.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let (name, deps) = match &entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => {
                        if plain_type.is_size_specifier || is_array_size_specifier_member(j) {
                            continue;
                        }
                        (borrow::Cow::Borrowed(entry.name.as_str()), &entry.deps)
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
                        if !self.tagged_union_references_inbuf(table, discriminant) {
                            continue;
                        }
                        (borrow::Cow::Borrowed(entry.name.as_str()), &entry.deps)
                    }
                    _ => (borrow::Cow::Borrowed(entry.name.as_str()), &entry.deps),
                };

                let deps = deps.factor_by_common_of(&table_deps);
                let deps = deps.factor_by_common_of(&into_bufs_owner_deps);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                writeln!(&mut iiout, "{},", Self::format_structure_member_name(&name))?;
            }
            writeln!(&mut iout, "}})")?;
            writeln!(out, "}}")?;
        } else {
            writeln!(
                out,
                "fn into_bufs_owner_intern(&mut self) -> Result<(), TpmErr> {{"
            )?;
            // Own all buffers in-place, self with limited lifetime 'a will subsequently get
            // transmuted to 'static lifetime.
            let mut iout = out.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&table_deps);
                let deps = deps.factor_by_common_of(&into_bufs_owner_deps);
                match &entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => {
                        let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                        if !self.structure_plain_member_references_inbuf(base_type) {
                            continue;
                        }
                        let name = Self::format_structure_member_name(&entry.name);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };
                        writeln!(&mut iiout, "self.{}.into_bufs_owner_intern()?;", name)?;
                        if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "}}")?;
                        }
                    }
                    StructureTableEntryType::Array(array_type) => {
                        match array_type.resolved_element_type.as_ref().unwrap() {
                            StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                if predefined.bits == 8 && !predefined.signed {
                                    let name = Self::format_structure_member_name(&entry.name);
                                    let mut iiout = if !deps.is_unconditional_true() {
                                        writeln!(
                                            &mut iout,
                                            "#[cfg({})]",
                                            Self::format_dep_conjunction(&deps)
                                        )?;
                                        writeln!(&mut iout, "{{")?;
                                        iout.make_indent()
                                    } else {
                                        iout.make_same_indent()
                                    };
                                    writeln!(
                                        &mut iiout,
                                        "self.{} = mem::take(&mut self.{}).into_owned()?;",
                                        name, name
                                    )?;
                                    if !deps.is_unconditional_true() {
                                        writeln!(&mut iout, "}}")?;
                                    }
                                }
                            }
                            _ => {
                                if self.structure_plain_member_references_inbuf(
                                    array_type.resolved_element_type.as_ref().unwrap(),
                                ) {
                                    let name = Self::format_structure_member_name(&entry.name);
                                    let mut iiout = if !deps.is_unconditional_true() {
                                        writeln!(
                                            &mut iout,
                                            "#[cfg({})]",
                                            Self::format_dep_conjunction(&deps)
                                        )?;
                                        writeln!(&mut iout, "{{")?;
                                        iout.make_indent()
                                    } else {
                                        iout.make_same_indent()
                                    };
                                    writeln!(
                                        &mut iiout,
                                        "for element in self.{}.iter_mut() {{",
                                        name
                                    )?;
                                    writeln!(
                                        &mut iiout.make_indent(),
                                        "element.into_bufs_owner_intern()?;"
                                    )?;
                                    writeln!(&mut iiout, "}}")?;
                                    if !deps.is_unconditional_true() {
                                        writeln!(&mut iout, "}}")?;
                                    }
                                }
                            }
                        };
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
                        if !self.tagged_union_references_inbuf(table, discriminant) {
                            continue;
                        }
                        let name = Self::format_structure_member_name(&entry.name);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };
                        writeln!(&mut iiout, "self.{}.into_bufs_owner_intern()?;", name)?;
                        if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "}}")?;
                        }
                    }
                };
            }

            writeln!(&mut iout)?;
            writeln!(&mut iout, "Ok(())")?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gen_tagged_union_into_bufs_owner_intern<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        table_deps: &ConfigDepsDisjunction,
        tagged_union_name: &str,
        discriminant_member: usize,
        conditional: bool,
        enable_in_place_into_bufs_owner: bool,
    ) -> Result<(), io::Error> {
        let discriminant_entry = &table.entries[discriminant_member];
        assert!(discriminant_entry.deps.is_unconditional_true());
        let discriminant =
            Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);
        let discriminant_type = discriminant.resolved_discriminant_type.as_ref().unwrap();
        let discriminant_enable_conditional = if discriminant.discriminant_type_enable_conditional {
            true
        } else if discriminant.discriminant_type_conditional {
            conditional
        } else {
            false
        };

        let mut into_bufs_owner_deps =
            closure_deps.collect_config_deps(ClosureDepsFlags::ANY_INTO_BUFS_OWNER);
        into_bufs_owner_deps.factor_by_common_of(table_deps);
        if !into_bufs_owner_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&into_bufs_owner_deps))?;
        }

        let tagged_union_name = Self::camelize(tagged_union_name);
        if !enable_in_place_into_bufs_owner {
            writeln!(
                out,
                "fn into_bufs_owner_intern(self) -> Result<{}<'static>, TpmErr> {{",
                tagged_union_name
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "match self {{")?;
            let mut iiout = iout.make_indent();
            for selector in UnionSelectorIterator::new(
                &self.tables.structures,
                *discriminant_type,
                discriminant_enable_conditional,
            ) {
                let deps = selector.config_deps().factor_by_common_of(table_deps);
                let deps = deps.factor_by_common_of(table_deps);
                let deps = deps.factor_by_common_of(&into_bufs_owner_deps);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let selected_union_members = self.get_structure_selected_union_members(table, discriminant, &selector);
                let enum_member_name = self.format_tagged_union_member_name(&selector);
                let enum_member_name = Self::camelize(&enum_member_name);
                if selected_union_members.is_empty() {
                    writeln!(
                        &mut iiout,
                        "Self::{} => {}::{},",
                        &enum_member_name, tagged_union_name, enum_member_name
                    )?;
                    continue;
                };

                let selected_union_members_match_spec = selected_union_members
                    .iter()
                    .map(|(u, _, _)| {
                        Self::format_structure_member_name(&table.entries[*u].name).into_owned()
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                if discriminant.discriminated_union_members.len() == 1 {
                    writeln!(
                        &mut iiout,
                        "Self::{}({}) => {{",
                        &enum_member_name, selected_union_members_match_spec
                    )?;
                } else {
                    writeln!(
                        &mut iiout,
                        "Self::{}{{{}}} => {{",
                        &enum_member_name, selected_union_members_match_spec
                    )?;
                }

                let mut iiiout = iiout.make_indent();
                let mut first = true;
                for (u, union_table_index, selected_member_index) in selected_union_members.iter() {
                    let union_entry_name =
                        Self::format_structure_member_name(&table.entries[*u].name);
                    let union_table = self.tables.structures.get_union(*union_table_index);
                    let selected_member = &union_table.entries[*selected_member_index];
                    match &selected_member.entry_type {
                        UnionTableEntryType::Plain(plain_type) => {
                            let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                            if self.structure_plain_member_references_inbuf(base_type) {
                                if !first {
                                    writeln!(&mut iiiout)?;
                                }
                                first = false;
                                writeln!(
                                    &mut iiiout,
                                    "let {} = {}.into_bufs_owner_intern()?;",
                                    union_entry_name, union_entry_name
                                )?;
                            }
                        }
                        UnionTableEntryType::Array(array_type) => {
                            let element_type = array_type.resolved_element_type.as_ref().unwrap();
                            match element_type {
                                StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                    if predefined.bits == 8 && !predefined.signed {
                                        if !first {
                                            writeln!(&mut iiiout)?;
                                        }
                                        first = false;
                                        writeln!(
                                            &mut iiiout,
                                            "let {} = {}.into_owned()?;",
                                            union_entry_name, union_entry_name
                                        )?;
                                    }
                                }
                                _ => {
                                    if self.structure_plain_member_references_inbuf(element_type) {
                                        if !first {
                                            writeln!(&mut iiiout)?;
                                        }
                                        first = false;
                                        writeln!(
                                            &mut iiiout,
                                            "let mut {}_orig = {};",
                                            union_entry_name, union_entry_name
                                        )?;
                                        writeln!(
                                            &mut iiiout,
                                            "let mut {} = Vec::new();",
                                            union_entry_name
                                        )?;
                                        writeln!(
                                            &mut iiiout,
                                            "{}.try_reserve_exact({}_orig.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;",
                                            union_entry_name, union_entry_name
                                        )?;
                                        writeln!(
                                            &mut iiiout,
                                            "for element in {}_orig.drain(..) {{",
                                            union_entry_name
                                        )?;
                                        writeln!(
                                            &mut iiiout.make_indent(),
                                            "{}.push(element.into_bufs_owner_intern()?);",
                                            union_entry_name
                                        )?;
                                        writeln!(&mut iiiout, "}}")?;
                                    }
                                }
                            };
                        }
                    };
                }
                if discriminant.discriminated_union_members.len() == 1 {
                    writeln!(
                        &mut iiiout,
                        "Ok({}::{}({}))",
                        tagged_union_name, enum_member_name, selected_union_members_match_spec
                    )?;
                } else {
                    writeln!(&mut iiiout)?;
                    writeln!(
                        &mut iiiout,
                        "Ok({}::{}{{{}}})",
                        tagged_union_name, enum_member_name, selected_union_members_match_spec
                    )?;
                }
                writeln!(&mut iiout, "}},")?;
            }
            writeln!(&mut iout, "}}")?;
            writeln!(out, "}}")?;
        } else {
            writeln!(
                out,
                "fn into_bufs_owner_intern(&mut self) -> Result<(), TpmErr> {{"
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "match self {{")?;
            let mut iiout = iout.make_indent();
            for selector in UnionSelectorIterator::new(
                &self.tables.structures,
                *discriminant_type,
                discriminant_enable_conditional,
            ) {
                let deps = selector.config_deps().factor_by_common_of(table_deps);
                let deps = deps.factor_by_common_of(table_deps);
                let deps = deps.factor_by_common_of(&into_bufs_owner_deps);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let selected_union_members = self.get_structure_selected_union_members(table, discriminant, &selector);
                let enum_member_name = self.format_tagged_union_member_name(&selector);
                let enum_member_name = Self::camelize(&enum_member_name);
                if selected_union_members.is_empty() {
                    writeln!(&mut iiout, "Self::{} => (),", &enum_member_name)?;
                    continue;
                };

                let selected_union_members_match_spec = selected_union_members
                    .iter()
                    .map(|(u, union_table_index, selected_member_index)| {
                        let match_spec =
                            Self::format_structure_member_name(&table.entries[*u].name)
                                .into_owned();
                        let union_table = self.tables.structures.get_union(*union_table_index);
                        let selected_member = &union_table.entries[*selected_member_index];
                        // In case the selected union member's type doesn't own a buffer (possibly
                        // indirectly), the match specifier will not be needed. Mark it as such
                        // then, otherwise Rust will emit warnings.
                        let match_is_unused = match &selected_member.entry_type {
                            UnionTableEntryType::Plain(plain_type) => {
                                let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                                !self.structure_plain_member_references_inbuf(base_type)
                            }
                            UnionTableEntryType::Array(array_type) => {
                                let element_type =
                                    array_type.resolved_element_type.as_ref().unwrap();
                                match element_type {
                                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                        predefined.bits != 8 || predefined.signed
                                    }
                                    _ => {
                                        !self.structure_plain_member_references_inbuf(element_type)
                                    }
                                }
                            }
                        };
                        if !match_is_unused {
                            match_spec
                        } else if discriminant.discriminated_union_members.len() == 1 {
                            "_".to_owned()
                        } else {
                            match_spec + ": _"
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                if discriminant.discriminated_union_members.len() == 1 {
                    writeln!(
                        &mut iiout,
                        "Self::{}({}) => {{",
                        &enum_member_name, selected_union_members_match_spec
                    )?;
                } else {
                    writeln!(
                        &mut iiout,
                        "Self::{}{{{}}} => {{",
                        &enum_member_name, selected_union_members_match_spec
                    )?;
                }

                let mut iiiout = iiout.make_indent();
                let mut first = true;
                for (u, union_table_index, selected_member_index) in selected_union_members.iter() {
                    let union_entry_name =
                        Self::format_structure_member_name(&table.entries[*u].name);
                    let union_table = self.tables.structures.get_union(*union_table_index);
                    let selected_member = &union_table.entries[*selected_member_index];
                    match &selected_member.entry_type {
                        UnionTableEntryType::Plain(plain_type) => {
                            let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                            if self.structure_plain_member_references_inbuf(base_type) {
                                if !first {
                                    writeln!(&mut iiiout)?;
                                }
                                first = false;
                                writeln!(
                                    &mut iiiout,
                                    "{}.into_bufs_owner_intern()?;",
                                    union_entry_name
                                )?;
                            }
                        }
                        UnionTableEntryType::Array(array_type) => {
                            let element_type = array_type.resolved_element_type.as_ref().unwrap();
                            match element_type {
                                StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                    if predefined.bits == 8 && !predefined.signed {
                                        if !first {
                                            writeln!(&mut iiiout)?;
                                        }
                                        first = false;
                                        writeln!(
                                            &mut iiiout,
                                            "*{} = mem::take({}).into_owned()?;",
                                            union_entry_name, union_entry_name
                                        )?;
                                    }
                                }
                                _ => {
                                    if self.structure_plain_member_references_inbuf(element_type) {
                                        if !first {
                                            writeln!(&mut iiiout)?;
                                        }
                                        first = false;
                                        writeln!(
                                            &mut iiiout,
                                            "for element in {}.iter_mut() {{",
                                            union_entry_name
                                        )?;
                                        writeln!(
                                            &mut iiiout.make_indent(),
                                            "element.into_bufs_owner_intern()?;"
                                        )?;
                                        writeln!(&mut iiiout, "}}")?;
                                    }
                                }
                            };
                        }
                    };
                }
                writeln!(&mut iiout, "}},")?;
            }
            writeln!(&mut iout, "}};")?;
            writeln!(&mut iout)?;
            writeln!(&mut iout, "Ok(())")?;
            writeln!(out, "}}")?;
        }
        Ok(())
    }

    pub(super) fn gen_structure_into_bufs_owner<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        conditional: bool,
        enable_in_place_into_bufs_owner: bool,
    ) -> Result<(), io::Error> {
        let table_closure_deps = if !conditional {
            &table.closure_deps
        } else {
            &table.closure_deps_conditional
        };
        let table_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::all());

        let mut into_bufs_owner_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER);
        into_bufs_owner_deps.factor_by_common_of(&table_deps);
        if !into_bufs_owner_deps.is_implied_by(&table_deps) {
            writeln!(
                out,
                "#[cfg({})]",
                Self::format_deps(&into_bufs_owner_deps)
            )?;
        }

        // Structures returned from public unmarshal interfaces live in Box<>es.
        let self_is_boxed = table_closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL);
        let table_name = Self::camelize(&Self::format_structure_name(table, conditional));
        if !enable_in_place_into_bufs_owner {
            if !self_is_boxed {
                writeln!(
                    out,
                    "pub fn into_bufs_owner(self) -> Result<{}<'static>, TpmErr> {{",
                    table_name
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "self.into_bufs_owner_intern()")?;
                writeln!(out, "}}")?;
            } else {
                writeln!(out, "pub fn into_bufs_owner(self: Box<Self>) -> Result<Box<{}<'static>>, TpmErr> {{",
                         table_name)?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "let this = *self;")?;
                writeln!(&mut iout,
                         "Ok(Box::try_new(this.into_bufs_owner_intern()?).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?)")?;
                writeln!(out, "}}")?;
            }
        } else if !self_is_boxed {
            writeln!(
                out,
                "pub fn into_bufs_owner(mut self) -> Result<{}<'static>, TpmErr> {{",
                table_name
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "self.into_bufs_owner_intern()?;")?;
            writeln!(
                &mut iout,
                "Ok(unsafe {{ mem::transmute::<Self, {}<'static>>(self) }})",
                table_name
            )?;
            writeln!(out, "}}")?;
        } else {
            writeln!(out, "pub fn into_bufs_owner(mut self: Box<Self>) -> Result<Box<{}<'static>>, TpmErr> {{",
                     table_name)?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "self.into_bufs_owner_intern()?;")?;
            writeln!(
                &mut iout,
                "Ok(unsafe {{ mem::transmute::<Box<Self>, Box<{}<'static>>>(self) }})",
                table_name
            )?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }
}
