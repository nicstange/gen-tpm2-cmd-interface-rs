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
    pub(super) fn gen_structure_stabilize_bufs<W: io::Write>(
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

        let mut stabilize_bufs_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_STABILIZE_BUFS);
        stabilize_bufs_deps.factor_by_common_of(&table_deps);
        if !stabilize_bufs_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&stabilize_bufs_deps))?;
        }

        let pub_spec = if table_closure_deps.any(ClosureDepsFlags::EXTERN_STABILIZE_BUFS) {
            "pub "
        } else {
            ""
        };

        writeln!(
            out,
            "{}fn stabilize(&mut self) -> Result<(), TpmErr> {{",
            pub_spec
        )?;
        let mut iout = out.make_indent();
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            let deps = &entry.deps;
            let deps = deps.factor_by_common_of(&table_deps);
            let deps = deps.factor_by_common_of(&stabilize_bufs_deps);
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    if !self.structure_plain_member_references_inbuf(
                        plain_type.resolved_base_type.as_ref().unwrap(),
                    ) {
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
                    writeln!(&mut iiout, "self.{}.stabilize()?;", name)?;
                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
                StructureTableEntryType::Array(array_type) => {
                    match array_type.resolved_element_type.as_ref().unwrap() {
                        StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                            if predefined.bits == 8 && !predefined.signed {
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
                                let name = Self::format_structure_member_name(&entry.name);
                                writeln!(&mut iiout, "self.{}.stabilize()?;", name)?;
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
                                writeln!(&mut iiout, "for element in self.{}.iter_mut() {{", name)?;
                                writeln!(&mut iiout.make_indent(), "element.stabilize()?;")?;
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
                    writeln!(&mut iiout, "self.{}.stabilize()?;", name)?;
                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
            };
        }
        writeln!(&mut iout, "Ok(())")?;
        writeln!(out, "}}")?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gen_tagged_union_stabilize_bufs<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        table_deps: &ConfigDepsDisjunction,
        discriminant_member: usize,
        is_structure_member_repr: bool,
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

        let mut stabilize_bufs_deps =
            closure_deps.collect_config_deps(ClosureDepsFlags::ANY_STABILIZE_BUFS);
        stabilize_bufs_deps.factor_by_common_of(table_deps);
        if !stabilize_bufs_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&stabilize_bufs_deps))?;
        }

        let pub_spec = if !is_structure_member_repr
            && closure_deps.any(ClosureDepsFlags::EXTERN_STABILIZE_BUFS)
        {
            "pub "
        } else {
            ""
        };

        writeln!(
            out,
            "{}fn stabilize(&mut self) -> Result<(), TpmErr> {{",
            pub_spec
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
            let deps = deps.factor_by_common_of(&stabilize_bufs_deps);
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
                        Self::format_structure_member_name(&table.entries[*u].name).into_owned();
                    let union_table = self.tables.structures.get_union(*union_table_index);
                    let selected_member = &union_table.entries[*selected_member_index];
                    // In case the selected union member's type doesn't own a buffer (possibly
                    // indirectly), the match specifier will not be needed. Mark it as such then,
                    // otherwise Rust will emit warnings.
                    let match_is_unused = match &selected_member.entry_type {
                        UnionTableEntryType::Plain(plain_type) => {
                            let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                            !self.structure_plain_member_references_inbuf(base_type)
                        }
                        UnionTableEntryType::Array(array_type) => {
                            let element_type = array_type.resolved_element_type.as_ref().unwrap();
                            match element_type {
                                StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                                    predefined.bits != 8 || predefined.signed
                                }
                                _ => !self.structure_plain_member_references_inbuf(element_type),
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
                let union_entry_name = Self::format_structure_member_name(&table.entries[*u].name);
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
                            writeln!(&mut iiiout, "{}.stabilize()?;", union_entry_name)?;
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
                                    writeln!(&mut iiiout, "{}.stabilize()?;", union_entry_name)?;
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
                                    writeln!(&mut iiiout.make_indent(), "element.stabilize()?;")?;
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
        Ok(())
    }
}
