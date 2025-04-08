// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures::{self, expr::ExprValue, union_table::UnionTableEntryType};

use structures::structure_table::StructureTableEntryResolvedBaseType;
use structures::table_common::ClosureDepsFlags;
use structures::tables::{StructuresPartTablesConstantsIndex, StructuresPartTablesUnionIndex};

use super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn gen_union<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        index: StructuresPartTablesUnionIndex,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error> {
        let table = self.tables.structures.get_union(index);
        assert!(!table
            .max_size_deps
            .any(ClosureDepsFlags::ANY_MAX_SIZE.complement()));
        let table_deps = table
            .max_size_deps
            .collect_config_deps(ClosureDepsFlags::all());
        if table_deps.is_empty() {
            return Ok(());
        }

        writeln!(out)?;
        if let Some(src_ref) = &table.info.src_ref {
            writeln!(out, "// {}, {} union", src_ref, &table.name)?;
        } else {
            writeln!(out, "// {} union", &table.name)?;
        }
        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }

        let pub_spec = if table.max_size_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE) {
            "pub "
        } else {
            ""
        };
        writeln!(
            out,
            "{}struct {} {{}}",
            pub_spec,
            Self::camelize(&table.name)
        )?;

        writeln!(out)?;
        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }
        writeln!(out, "impl {} {{", Self::camelize(&table.name))?;

        let is_compiletime_const = match table.max_size.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(_) => true,
            ExprValue::RuntimeConstant(_) => false,
            _ => unreachable!(),
        };

        let mut iout = out.make_indent();
        let size_type = self.determine_union_max_size_type(&table).map_err(|_| {
            eprintln!("error: {}: integer overflow in union size", &table.name);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        if is_compiletime_const {
            writeln!(
                &mut iout,
                "{}const fn marshalled_max_size() -> {} {{",
                pub_spec,
                Self::predefined_type_to_rust(size_type)
            )?;
        } else {
            writeln!(
                &mut iout,
                "{}fn marshalled_max_size(limits: &TpmLimits) -> Result<{}, ()> {{",
                pub_spec,
                Self::predefined_type_to_rust(size_type)
            )?;
        }
        let mut iiout = iout.make_indent();

        let mut_spec = if table.entries.is_empty() { "" } else { "mut " };
        writeln!(
            &mut iiout,
            "let {}size: {} = 0;",
            mut_spec,
            Self::predefined_type_to_rust(size_type)
        )?;

        // Do the members with sizes known at compile-time first in order to enable constant folding.
        let mut runtime_size_entries = Vec::new();
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            let mut deps = entry.deps.clone();
            match &entry.selector {
                Some(selector) => {
                    if let Some(index) = self.tables.structures.lookup_constant(selector) {
                        let constants_entry = self.tables.structures.get_constant(index);
                        deps.merge_from(&constants_entry.deps);
                        let index = StructuresPartTablesConstantsIndex::from(index);
                        let constants_table = self.tables.structures.get_constants(index);
                        deps.merge_from(&constants_table.structures_info.deps);
                    }
                }
                None => (),
            };
            let deps = deps.factor_by_common_of(&table_deps);

            match &entry.entry_type {
                UnionTableEntryType::Plain(plain_type) => {
                    let base_type = match &plain_type.resolved_base_type {
                        Some(base_type) => base_type,
                        None => continue,
                    };
                    if let StructureTableEntryResolvedBaseType::Structure(index) = base_type {
                        let member_table = self.tables.structures.get_structure(*index);
                        if !Self::structure_max_size_is_compiletime_const(&member_table) {
                            runtime_size_entries.push(j);
                            continue;
                        }
                    }

                    writeln!(&mut iiout)?;
                    let mut iiiout = if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "#[cfg({})]",
                            Self::format_dep_conjunction(&deps)
                        )?;
                        writeln!(&mut iiout, "{{")?;
                        iiout.make_indent()
                    } else {
                        iiout.make_same_indent()
                    };

                    let enable_conditional = plain_type.base_type_enable_conditional;
                    let member_max_size = self
                        .format_structure_member_plain_type_compiletime_max_size(
                            base_type,
                            enable_conditional,
                            size_type,
                            enable_allocator_api,
                        );
                    // ::max() is non-const, open-code it.
                    let member_name = Self::uncamelize(&entry.name);
                    writeln!(
                        &mut iiiout,
                        "let {}_size = {};",
                        &member_name, member_max_size
                    )?;
                    writeln!(&mut iiiout, "if {}_size > size {{", &member_name)?;
                    writeln!(&mut iiiout.make_indent(), "size = {}_size;", &member_name)?;
                    writeln!(&mut iiiout, "}}")?;

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iiout, "}}")?;
                    }
                }
                UnionTableEntryType::Array(array_type) => {
                    let array_size = &array_type.size;
                    match array_size.value.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(_) => (),
                        _ => {
                            runtime_size_entries.push(j);
                            continue;
                        }
                    };

                    let element_type = array_type.resolved_element_type.as_ref().unwrap();
                    if let StructureTableEntryResolvedBaseType::Structure(index) = element_type {
                        let element_table = self.tables.structures.get_structure(*index);
                        if !Self::structure_max_size_is_compiletime_const(&element_table) {
                            runtime_size_entries.push(j);
                            continue;
                        }
                    }

                    writeln!(&mut iiout)?;
                    let mut iiiout = if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "#[cfg({})]",
                            Self::format_dep_conjunction(&deps)
                        )?;
                        writeln!(&mut iiout, "{{")?;
                        iiout.make_indent()
                    } else {
                        iiout.make_same_indent()
                    };

                    let member_name = Self::uncamelize(&entry.name);
                    let array_size = self
                        .format_compiletime_const_expr_for_type(
                            array_size, size_type, "limits", None,
                        )
                        .unwrap();

                    let is_byte_array = match element_type {
                        StructureTableEntryResolvedBaseType::Predefined(p) => {
                            p.bits == 8 && !p.signed
                        }
                        _ => false,
                    };
                    if !is_byte_array {
                        let enable_conditional = array_type.element_type_enable_conditional;
                        let element_size = self
                            .format_structure_member_plain_type_compiletime_max_size(
                                element_type,
                                enable_conditional,
                                size_type,
                                enable_allocator_api,
                            );
                        writeln!(
                            &mut iiiout,
                            "let {}_size = {} * {};",
                            &member_name, element_size, array_size.0
                        )?;
                    } else {
                        writeln!(&mut iiiout, "let {}_size = {};", &member_name, array_size.0)?;
                    }
                    // ::max() is non-const, open-code it.
                    writeln!(&mut iiiout, "if {}_size > size {{", &member_name)?;
                    writeln!(&mut iiiout.make_indent(), "size = {}_size;", &member_name)?;
                    writeln!(&mut iiiout, "}}")?;

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iiout, "}}")?;
                    }
                }
            };
        }

        for j in runtime_size_entries.iter() {
            let entry = &table.entries[*j];
            let mut deps = entry.deps.clone();
            match &entry.selector {
                Some(selector) => {
                    if let Some(index) = self.tables.structures.lookup_constant(selector) {
                        let constants_entry = self.tables.structures.get_constant(index);
                        deps.merge_from(&constants_entry.deps);
                        let index = StructuresPartTablesConstantsIndex::from(index);
                        let constants_table = self.tables.structures.get_constants(index);
                        deps.merge_from(&constants_table.structures_info.deps);
                    }
                }
                None => (),
            };
            let deps = deps.factor_by_common_of(&table_deps);
            writeln!(&mut iiout)?;
            let mut iiiout = if !deps.is_unconditional_true() {
                writeln!(
                    &mut iiout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&deps)
                )?;
                writeln!(&mut iiout, "{{")?;
                iiout.make_indent()
            } else {
                iiout.make_same_indent()
            };

            match &entry.entry_type {
                UnionTableEntryType::Plain(plain_type) => {
                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                    let enable_conditional = plain_type.base_type_enable_conditional;
                    let member_max_size_name = Self::uncamelize(&entry.name) + "_size";
                    let member_max_size = self.format_structure_member_plain_type_max_size(
                        &mut iiiout,
                        &member_max_size_name,
                        base_type,
                        enable_conditional,
                        size_type,
                        &mut |out| writeln!(out, "return Err(());"),
                        enable_allocator_api,
                    )?;
                    // ::max() is non-const, open-code it.
                    if member_max_size != member_max_size_name {
                        writeln!(
                            &mut iiiout,
                            "let {} = {};",
                            &member_max_size_name, member_max_size
                        )?;
                    }
                    writeln!(&mut iiiout, "if {} > size {{", &member_max_size_name)?;
                    writeln!(
                        &mut iiiout.make_indent(),
                        "size = {};",
                        &member_max_size_name
                    )?;
                    writeln!(&mut iiiout, "}}")?;
                }
                UnionTableEntryType::Array(array_type) => {
                    let member_name = Self::uncamelize(&entry.name);
                    let array_size = &array_type.size;

                    let array_size = self.format_expr_for_type(
                        &mut iiiout,
                        array_size,
                        size_type,
                        "limits",
                        None,
                        &|_, _| unreachable!(),
                        &|out| writeln!(out, "return Err(());"),
                    )?;
                    writeln!(&mut iiiout, "let {}_size = {};", &member_name, array_size)?;

                    let element_type = array_type.resolved_element_type.as_ref().unwrap();
                    let enable_conditional = array_type.element_type_enable_conditional;
                    let is_byte_array = match element_type {
                        StructureTableEntryResolvedBaseType::Predefined(p) => {
                            p.bits == 8 && !p.signed
                        }
                        _ => false,
                    };
                    if !is_byte_array {
                        let element_max_size = self.format_structure_member_plain_type_max_size(
                            &mut iiiout,
                            (member_name.clone() + "_element_size").as_str(),
                            element_type,
                            enable_conditional,
                            size_type,
                            &mut |out| writeln!(out, "return Err(());"),
                            enable_allocator_api,
                        )?;
                        writeln!(
                            &mut iiiout,
                            "let {}_size = match {}_size.checked_mul({}) {{",
                            &member_name, &member_name, element_max_size
                        )?;
                        let mut iiiiout = iiiout.make_indent();
                        writeln!(&mut iiiiout, "Some(size) => size,")?;
                        writeln!(&mut iiiiout, "None => return Err(()),")?;
                        writeln!(&mut iiiout, "}}")?;
                    }

                    // ::max() is non-const, open-code it.
                    writeln!(&mut iiiout, "if {}_size > size {{", &member_name)?;
                    writeln!(&mut iiiout.make_indent(), "size = {}_size;", &member_name)?;
                    writeln!(&mut iiiout, "}}")?;
                }
            };
            if !deps.is_unconditional_true() {
                writeln!(&mut iiout, "}}")?;
            }
        }

        writeln!(&mut iiout)?;
        if is_compiletime_const {
            writeln!(&mut iiout, "size")?;
        } else {
            writeln!(&mut iiout, "Ok(size)")?;
        }
        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        Ok(())
    }
}
