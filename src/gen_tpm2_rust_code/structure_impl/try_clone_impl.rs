// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

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
    #[allow(clippy::too_many_arguments)]
    pub(super) fn gen_tagged_union_try_clone<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        table_deps: &ConfigDepsDisjunction,
        tagged_union_name: &str,
        discriminant_member: usize,
        conditional: bool,
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

        let mut try_clone_deps = closure_deps.collect_config_deps(ClosureDepsFlags::ANY_TRY_CLONE);
        try_clone_deps.factor_by_common_of(table_deps);
        if !try_clone_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&try_clone_deps))?;
        }

        let tagged_union_name = Self::camelize(tagged_union_name);

        let pub_spec = if closure_deps.any(ClosureDepsFlags::EXTERN_TRY_CLONE) {
            "pub "
        } else {
            ""
        };

        // Structures returned from public unmarshal interfaces live in Box<>es, do the same here
        // for consistency.
        let references_inbuf = self.structure_references_inbuf(table);
        let result_spec = if references_inbuf {
            tagged_union_name.clone() + "<'static>"
        } else {
            "Self".to_owned()
        };

        writeln!(
            out,
            "fn try_clone_intern(&self) -> Result<{}, TpmErr> {{",
            result_spec
        )?;
        let mut iout = out.make_indent();
        writeln!(&mut iout, "match self {{")?;
        let mut iiout = iout.make_indent();
        let result_spec = if references_inbuf {
            tagged_union_name.clone()
        } else {
            "Self".to_owned()
        };
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant_type,
            discriminant_enable_conditional,
        ) {
            let deps = selector.config_deps().factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(&try_clone_deps);
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
            // Create a local clone of each array member.
            for (u, union_table_index, selected_member_index) in selected_union_members.iter() {
                let union_entry_name = Self::format_structure_member_name(&table.entries[*u].name);
                let union_table = self.tables.structures.get_union(*union_table_index);
                let selected_member = &union_table.entries[*selected_member_index];
                match &selected_member.entry_type {
                    UnionTableEntryType::Plain(_) => (),
                    UnionTableEntryType::Array(array_type) => {
                        if !first {
                            writeln!(&mut iiiout)?;
                        }
                        first = false;
                        writeln!(
                            &mut iiiout,
                            "let {}_orig = {};",
                            union_entry_name, union_entry_name
                        )?;
                        writeln!(&mut iiiout, "let mut {} = Vec::new();", union_entry_name)?;
                        writeln!(
                            &mut iiiout,
                            "{}.try_reserve_exact({}_orig.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;",
                            union_entry_name, union_entry_name
                        )?;
                        let element_type = array_type.resolved_element_type.as_ref().unwrap();
                        match element_type {
                            StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                writeln!(
                                    &mut iiiout,
                                    "{}.extend_from_slice(&{}_orig);",
                                    union_entry_name, union_entry_name
                                )?;
                                if predefined.bits == 8 && !predefined.signed {
                                    writeln!(
                                        &mut iiiout,
                                        "let {} = TpmBuffer::Owned({});",
                                        union_entry_name, union_entry_name
                                    )?;
                                }
                            }
                            StructureTableEntryResolvedBaseType::Structure(index) => {
                                let structure_table = self.tables.structures.get_structure(*index);
                                if self.structure_contains_array(&structure_table) {
                                    writeln!(
                                        &mut iiiout,
                                        "for element in {}_orig.iter() {{",
                                        union_entry_name
                                    )?;
                                    writeln!(
                                        &mut iiiout.make_indent(),
                                        "{}.push(element.try_clone_intern()?);",
                                        union_entry_name
                                    )?;
                                    writeln!(&mut iiiout, "}}")?;
                                } else {
                                    writeln!(
                                        &mut iiiout,
                                        "{}.extend_from_slice(&{}_orig);",
                                        union_entry_name, union_entry_name
                                    )?;
                                }
                            }
                            _ => {
                                writeln!(
                                    &mut iiiout,
                                    "{}.extend_from_slice(&{}_orig);",
                                    union_entry_name, union_entry_name
                                )?;
                            }
                        };
                    }
                };
            }
            if !first {
                writeln!(&mut iiiout)?;
            }

            let content_seps = if discriminant.discriminated_union_members.len() == 1 {
                ("(", ")")
            } else {
                (" {", "}")
            };
            writeln!(
                &mut iiiout,
                "Ok({}::{}{}",
                &result_spec, enum_member_name, content_seps.0
            )?;

            let mut iiiiout = iiiout.make_indent();
            for (u, union_table_index, selected_member_index) in selected_union_members.iter() {
                let union_entry_name = Self::format_structure_member_name(&table.entries[*u].name);
                let union_table = self.tables.structures.get_union(*union_table_index);
                let selected_member = &union_table.entries[*selected_member_index];
                let dst_spec = if discriminant.discriminated_union_members.len() != 1 {
                    union_entry_name.clone().into_owned() + ": "
                } else {
                    "".to_owned()
                };
                match &selected_member.entry_type {
                    UnionTableEntryType::Plain(plain_type) => {
                        let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                        if self.structure_plain_member_contains_array(base_type) {
                            writeln!(
                                &mut iiiiout,
                                "{}{}.try_clone_intern()?,",
                                dst_spec, union_entry_name
                            )?;
                        } else {
                            writeln!(&mut iiiiout, "{}*{},", dst_spec, union_entry_name)?;
                        }
                    }
                    UnionTableEntryType::Array(_) => {
                        writeln!(&mut iiiiout, "{},", union_entry_name)?;
                    }
                };
            }

            writeln!(&mut iiiout, "{})", content_seps.1)?;
            writeln!(&mut iiout, "}},")?;
        }

        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;


        if closure_deps.any(ClosureDepsFlags::EXTERN_TRY_CLONE) {
            writeln!(out)?;
            let mut try_clone_deps = closure_deps.collect_config_deps(ClosureDepsFlags::EXTERN_TRY_CLONE);
            try_clone_deps.factor_by_common_of(table_deps);
            if !try_clone_deps.is_implied_by(table_deps) {
                dbg!(&try_clone_deps);
                dbg!(&table_deps);
                writeln!(out, "#[cfg({})]", Self::format_deps(&try_clone_deps))?;
            }

            // Structures returned from public unmarshal interfaces live in Box<>es, do the same here
            // for consistency.
            let self_is_boxed = closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL);
            if self_is_boxed {
                writeln!(
                    out,
                    "pub fn try_clone(&self) -> Result<Box<{}>, TpmErr> {{",
                    result_spec
                )?;
                writeln!(
                    &mut out.make_indent(),
                    "Ok(Box::try_new(self.try_clone_intern()?).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?)",
                )?;
                writeln!(out, "}}")?;
            } else {
                writeln!(
                    out,
                    "{}fn try_clone(&self) -> Result<{}, TpmErr> {{",
                    pub_spec, result_spec
                )?;
                writeln!(
                    &mut out.make_indent(),
                    "self.try_clone_intern()",
                )?;
                writeln!(out, "}}")?;
            }
        }
        Ok(())
    }

    pub(super) fn gen_structure_try_clone<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        conditional: bool,
    ) -> Result<(), io::Error> {
        let table_closure_deps = if !conditional {
            &table.closure_deps
        } else {
            &table.closure_deps_conditional
        };
        let table_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::all());

        let mut try_clone_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_TRY_CLONE);
        try_clone_deps.factor_by_common_of(&table_deps);
        if !try_clone_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&try_clone_deps))?;
        }

        let references_inbuf = self.structure_references_inbuf(table);
        let table_name = Self::camelize(&Self::format_structure_name(table, conditional));
        let result_spec = if references_inbuf {
            table_name.clone() + "<'static>"
        } else {
            "Self".to_owned()
        };

        writeln!(
            out,
            "fn try_clone_intern(&self) -> Result<{}, TpmErr> {{",
            result_spec
        )?;
        let mut iout = out.make_indent();
        let mut first = true;
        // Create a local clone of each array member.
        for entry in table.entries.iter() {
            if let StructureTableEntryType::Array(array_type) = &entry.entry_type {
                if !first {
                    writeln!(&mut iout)?;
                }
                first = false;

                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&table_deps);
                let deps = deps.factor_by_common_of(&try_clone_deps);
                let mut iiout = if !deps.is_unconditional_true() {
                    writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                    writeln!(&mut iout, "{{")?;
                    iout.make_indent()
                } else {
                    iout.make_same_indent()
                };

                let name = Self::format_structure_member_name(&entry.name);
                writeln!(&mut iiout, "let mut {} = Vec::new();", name)?;
                writeln!(
                    &mut iiout,
                    "{}.try_reserve_exact(self.{}.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;",
                    name, name
                )?;
                let element_type = array_type.resolved_element_type.as_ref().unwrap();
                match element_type {
                    StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                        writeln!(&mut iout, "{}.extend_from_slice(&self.{});", name, name)?;
                        if predefined.bits == 8 && !predefined.signed {
                            writeln!(&mut iout, "let {} = TpmBuffer::Owned({});", name, name)?;
                        }
                    }
                    StructureTableEntryResolvedBaseType::Structure(index) => {
                        let structure_table = self.tables.structures.get_structure(*index);
                        if self.structure_contains_array(&structure_table) {
                            writeln!(&mut iout, "for element in self.{}.iter() {{", name)?;
                            writeln!(
                                &mut iout.make_indent(),
                                "{}.push(element.try_clone_intern()?);",
                                name
                            )?;
                            writeln!(&mut iout, "}}")?;
                        } else {
                            writeln!(&mut iout, "{}.extend_from_slice(&self.{});", name, name)?;
                        }
                    }
                    _ => {
                        writeln!(&mut iout, "{}.extend_from_slice(&self.{});", name, name)?;
                    }
                };
                if !deps.is_unconditional_true() {
                    writeln!(&mut iout, "}}")?;
                }
            }
        }

        let array_size_specifier_members = Self::find_structure_array_size_specifier_members(table);
        let is_array_size_specifier_member = |j: usize| -> bool {
            array_size_specifier_members
                .binary_search_by_key(&j, |e| e.0)
                .is_ok()
        };

        if !first {
            writeln!(&mut iout)?;
        }
        let result_spec = if references_inbuf {
            table_name
        } else {
            "Self".to_owned()
        };
        writeln!(&mut iout, "Ok({} {{", result_spec)?;
        let mut iiout = iout.make_indent();
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            let deps = &entry.deps;
            let deps = deps.factor_by_common_of(&table_deps);
            let deps = deps.factor_by_common_of(&try_clone_deps);
            let name = Self::format_structure_member_name(&entry.name);
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    if plain_type.is_size_specifier || is_array_size_specifier_member(j) {
                        continue;
                    }
                    if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "#[cfg({})]",
                            Self::format_dep_conjunction(&deps)
                        )?;
                    }
                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                    if self.structure_plain_member_contains_array(base_type) {
                        writeln!(&mut iiout, "{}: self.{}.try_clone_intern()?,", name, name)?;
                    } else {
                        writeln!(&mut iiout, "{}: self.{},", name, name)?;
                    }
                }
                StructureTableEntryType::Array(_) => {
                    if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "#[cfg({})]",
                            Self::format_dep_conjunction(&deps)
                        )?;
                    }
                    writeln!(&mut iiout, "{},", name)?;
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
                    if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "#[cfg({})]",
                            Self::format_dep_conjunction(&deps)
                        )?;
                    }

                    if self.tagged_union_contains_array(table, discriminant) {
                        writeln!(&mut iiout, "{}: self.{}.try_clone_intern()?,", name, name)?;
                    } else {
                        writeln!(&mut iiout, "{}: self.{},", name, name)?;
                    }
                }
            };
        }
        writeln!(&mut iout, "}})")?;
        writeln!(out, "}}")?;

        if table_closure_deps.any(ClosureDepsFlags::EXTERN_TRY_CLONE) {
            writeln!(out)?;
            let mut try_clone_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::EXTERN_TRY_CLONE);
            try_clone_deps.factor_by_common_of(&table_deps);
            if !try_clone_deps.is_implied_by(&table_deps) {
                dbg!(&try_clone_deps);
                dbg!(&table_deps);
                writeln!(out, "#[cfg({})]", Self::format_deps(&try_clone_deps))?;
            }

            // Structures returned from public unmarshal interfaces live in Box<>es, do the same here
            // for consistency.
            let self_is_boxed = table_closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL);
            if self_is_boxed {
                writeln!(
                    out,
                    "pub fn try_clone(&self) -> Result<Box<{}>, TpmErr> {{",
                    result_spec
                )?;
                writeln!(
                    &mut out.make_indent(),
                    "Ok(Box::try_new(self.try_clone_intern()?).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?)",
                )?;
                writeln!(out, "}}")?;
            } else {
                writeln!(
                    out,
                    "pub fn try_clone(&self) -> Result<{}, TpmErr> {{",
                    result_spec
                )?;
                writeln!(
                    &mut out.make_indent(),
                    "self.try_clone_intern()",
                )?;
                writeln!(out, "}}")?;
            }
        }

        Ok(())
    }
}
