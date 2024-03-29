// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use crate::tcg_tpm2::structures::expr::ExprOp;
use crate::tcg_tpm2::structures::structure_table::StructureTableEntryResolvedDiscriminantType;
use crate::tcg_tpm2::structures::table_common::ClosureDeps;
use crate::tcg_tpm2::structures::union_table::UnionTableEntryType;
use structures::expr::{Expr, ExprValue};
use structures::structure_table::{
    StructureTable, StructureTableEntryDiscriminantType, StructureTableEntryResolvedBaseType,
    StructureTableEntryType,
};
use structures::table_common::ClosureDepsFlags;
use structures::tables::{UnionSelectorIterator, UnionSelectorIteratorValue};

use super::super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(in super::super) fn structure_marshal_needs_limits(table: &StructureTable) -> bool {
        match table.size.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(_) | ExprValue::Dynamic => false,
            ExprValue::RuntimeConstant(_) | ExprValue::DynamicWithRuntimeConstantDep(_) => true,
        }
    }

    fn tagged_union_marshal_needs_limits(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
        conditional: bool,
    ) -> bool {
        self.tagged_union_size_needs_limits(table, discriminant, conditional)
    }

    fn gen_structure_member_plain_type_marshal<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        outbuf_name: &str,
        inbuf_name: &str,
        src_spec: &str,
        plain_type: &StructureTableEntryResolvedBaseType,
    ) -> Result<(), io::Error> {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => {
                writeln!(
                    out,
                    "let {} = marshal_{}({}, {})?;",
                    outbuf_name,
                    Self::predefined_type_to_rust(*p),
                    inbuf_name,
                    src_spec
                )?;
            }
            StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => {
                writeln!(
                    out,
                    "let {} = {}.marshal({})?;",
                    outbuf_name, src_spec, inbuf_name
                )?;
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                let need_limits = Self::structure_marshal_needs_limits(&table);
                let limits_arg = if need_limits { ", limits" } else { "" };
                writeln!(
                    out,
                    "let {} = {}.marshal({}{})?;",
                    outbuf_name, src_spec, inbuf_name, limits_arg
                )?;
            }
        };
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_structure_member_array_marshal<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        outbuf_name: &str,
        inbuf_name: &str,
        member_name: &str,
        src_spec: &str,
        element_type: &StructureTableEntryResolvedBaseType,
        array_size: &Expr,
    ) -> Result<(), io::Error> {
        let (is_primitive, is_byte_array) = match element_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => (true, p.bits == 8 && !p.signed),
            StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_)
            | StructureTableEntryResolvedBaseType::Structure(_) => (false, false),
        };

        // For fixed size arrays, confirm that the provided array's length
        // equals what is expected from the specificiation.
        match array_size.value.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(_) | ExprValue::RuntimeConstant(_) => {
                let error_rc_size = self
                    .tables
                    .structures
                    .lookup_constant("TPM_RC_SIZE");

                let len_spec = if is_byte_array { "size" } else { "len" };

                let (expected_len, _, _) = self.format_expr(
                    out,
                    array_size,
                    None,
                    "limits",
                    None,
                    &|_, _| unreachable!(),
                    &|out| -> Result<(), io::Error> {
                        writeln!(out, "return Err(TpmErr::InternalErr);")
                    },
                )?;
                writeln!(
                    out,
                    "let expected_{}_{} = match usize::try_from({}) {{",
                    member_name, len_spec, expected_len
                )?;
                let mut iout = out.make_indent();
                writeln!(
                    &mut iout,
                    "Ok(expected_{}_{}) => expected_{}_{},",
                    member_name, len_spec, member_name, len_spec
                )?;
                writeln!(&mut iout, "Err(_) => {{")?;
                writeln!(&mut iout.make_indent(), "return Err(TpmErr::InternalErr);")?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;
                writeln!(
                    out,
                    "if {}.len() != expected_{}_{} {{",
                    src_spec, member_name, len_spec
                )?;
                self.format_error_return(&mut out.make_indent(), None, error_rc_size.unwrap())?;
                writeln!(out, "}}")?;
            }
            _ => (),
        };

        if is_byte_array {
            writeln!(
                out,
                "let (produced, {}) = split_slice_at_mut({}, {}.len())?;",
                outbuf_name, inbuf_name, src_spec
            )?;
            writeln!(out, "produced.copy_from_slice(&{});", src_spec)?;
        } else {
            writeln!(out, "let mut {} = {};", outbuf_name, inbuf_name)?;
            writeln!(out, "for element in {}.iter() {{", src_spec)?;

            let src_spec = if is_primitive { "*element" } else { "element" };
            let mut iout = out.make_indent();
            self.gen_structure_member_plain_type_marshal(
                &mut iout,
                "remaining",
                outbuf_name,
                src_spec,
                element_type,
            )?;
            writeln!(&mut iout, "{} = remaining;", outbuf_name)?;
            writeln!(out, "}}")?;
        }
        Ok(())
    }

    pub(super) fn gen_structure_marshal<W: io::Write>(
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

        let mut marshal_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_MARSHAL);
        marshal_deps.factor_by_common_of(&table_deps);
        if !marshal_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&marshal_deps))?;
        }

        let pub_spec = if table_closure_deps.any(ClosureDepsFlags::EXTERN_MARSHAL) {
            "pub "
        } else {
            ""
        };

        let references_inbuf = self.structure_references_inbuf(table);
        let buf_lifetime = if !references_inbuf { "a" } else { "b" };

        let need_limits = Self::structure_marshal_needs_limits(table);
        let limits_arg = if need_limits {
            ", limits: &TpmLimits"
        } else {
            ""
        };

        writeln!(
            out,
            "{}fn marshal<'{}>(&self, buf: &'{} mut [u8]{}) -> Result<&'{} mut [u8], TpmErr> {{",
            pub_spec, buf_lifetime, buf_lifetime, limits_arg, buf_lifetime
        )?;

        let error_rc_size = self
            .tables
            .structures
            .lookup_constant("TPM_RC_SIZE");

        let array_size_specifier_members = Self::find_structure_array_size_specifier_members(table);
        let lookup_array_size_specifier_member =
            |j: usize| match array_size_specifier_members.binary_search_by_key(&j, |e| e.0) {
                Ok(pos) => Some(&array_size_specifier_members[pos].1),
                Err(_) => None,
            };

        // Verify that all dynamic array size expressions are simple, referring
        // to some local id directly.  Otherwise array size specifier members'
        // values cannot be reconstructed. Also, for each array size specifier
        // member, there must be at least one associated array member with
        // weaker (and thus, equal effectively) configuration dependencies.
        for array_size_specifier in array_size_specifier_members.iter() {
            let entry = &table.entries[array_size_specifier.0];
            let mut found_primary_array_member = false;
            for array_member_index in array_size_specifier.1.iter() {
                let array_entry = &table.entries[*array_member_index];
                if array_entry.deps.is_implied_by(&entry.deps) {
                    found_primary_array_member = true;
                }
                let array_type = match &array_entry.entry_type {
                    StructureTableEntryType::Array(array_type) => array_type,
                    _ => unreachable!(),
                };
                match &array_type.size.op {
                    ExprOp::Id(_) => (),
                    _ => {
                        eprintln!("error: table {}: {}: complex array size expressions not supported for marshalling",
                                  &table.name, &array_entry.name);
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };
            }

            if !found_primary_array_member {
                eprintln!("error: table {}: {}: no array member with matching config dependencies found for length specifier",
                          &table.name, &entry.name);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        }

        let find_array_size_specifier_primary_array =
            |j: usize, array_members: &Vec<usize>| -> usize {
                let entry = &table.entries[j];
                for array_member_index in array_members.iter() {
                    let array_entry = &table.entries[*array_member_index];
                    if array_entry.deps.is_implied_by(&entry.deps) {
                        return *array_member_index;
                    }
                }
                unreachable!()
            };

        let mut iout = out.make_indent();
        let mut first = true;

        // Check for all arrays, which are not selected as the primary one for
        // their associated length specifier member, if any, that their lengths
        // are consistent with the primary one each.
        for array_size_specifier in array_size_specifier_members.iter() {
            if array_size_specifier.1.len() == 1 {
                continue;
            }
            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

            let primary_array_member_index = find_array_size_specifier_primary_array(
                array_size_specifier.0,
                &array_size_specifier.1,
            );
            let primary_array_member_entry = &table.entries[primary_array_member_index];
            let primary_array_member_name =
                Self::format_structure_member_name(&primary_array_member_entry.name);
            let size_specifier_deps = &primary_array_member_entry.deps;
            let size_specifier_deps = size_specifier_deps.factor_by_common_of(&table_deps);
            let size_specifier_deps = size_specifier_deps.factor_by_common_of(&marshal_deps);

            let mut iiout = if !size_specifier_deps.is_unconditional_true() {
                writeln!(
                    &mut iout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&size_specifier_deps)
                )?;
                writeln!(&mut iout, "{{")?;
                iout.make_indent()
            } else {
                iout.make_same_indent()
            };

            for array_member_index in array_size_specifier.1.iter() {
                if *array_member_index == primary_array_member_index {
                    continue;
                }
                let array_member_entry = &table.entries[*array_member_index];
                let array_member_name =
                    Self::format_structure_member_name(&array_member_entry.name);
                let array_member_deps = &array_member_entry.deps;
                let array_member_deps = array_member_deps.factor_by_common_of(&table_deps);
                let mut array_member_deps = array_member_deps
                    .factor_by_common_of(&marshal_deps)
                    .into_owned();
                array_member_deps.factor_by(&size_specifier_deps);
                if !array_member_deps.is_unconditional_true() {
                    writeln!(
                        &mut iiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&array_member_deps)
                    )?;
                }
                writeln!(
                    &mut iiout,
                    "if self.{}.len() != self.{}.len() {{",
                    array_member_name, primary_array_member_name
                )?;
                self.format_error_return(&mut iiout.make_indent(), None, error_rc_size.unwrap())?;
                writeln!(&mut iiout, "}}")?;
            }

            if !size_specifier_deps.is_unconditional_true() {
                writeln!(&mut iout, "}}")?;
            }
        }

        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    let deps = &entry.deps;
                    let deps = deps.factor_by_common_of(&table_deps);
                    let deps = deps.factor_by_common_of(&marshal_deps);
                    let mut iiout = if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(&mut iout, "{{")?;
                        iout.make_indent()
                    } else {
                        iout.make_same_indent()
                    };

                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                    if plain_type.is_size_specifier {
                        let member_name = Self::format_structure_member_name(&entry.name);
                        let acc_size_name = "marshalled_".to_owned() + &member_name;
                        writeln!(&mut iiout, "let mut {}: usize = 0;", acc_size_name)?;
                        self.gen_structure_members_marshalled_size(
                            &mut iiout,
                            &acc_size_name,
                            table,
                            false,
                            j + 1,
                            &table_deps,
                            &marshal_deps,
                            conditional,
                            &|out| writeln!(out, "return Err(TpmErr::InternalErr);"),
                        )?;

                        let base_type = match base_type {
                            StructureTableEntryResolvedBaseType::Predefined(p) => *p,
                            StructureTableEntryResolvedBaseType::Constants(index) => {
                                let table = self.tables.structures.get_constants(*index);
                                *table.resolved_base.as_ref().unwrap()
                            }
                            StructureTableEntryResolvedBaseType::Type(index) => {
                                let table = self.tables.structures.get_type(*index);
                                *table.underlying_type.as_ref().unwrap()
                            }
                            _ => unreachable!(),
                        };

                        writeln!(&mut iiout)?;
                        writeln!(
                            &mut iiout,
                            "let {} = match {}::try_from({}) {{",
                            acc_size_name,
                            Self::predefined_type_to_rust(base_type),
                            acc_size_name
                        )?;
                        let mut iiiout = iiout.make_indent();
                        writeln!(&mut iiiout, "Ok({}) => {},", &acc_size_name, &acc_size_name)?;
                        writeln!(&mut iiiout, "Err(_) => {{")?;
                        self.format_error_return(&mut iiiout.make_indent(), None, error_rc_size.unwrap())?;
                        writeln!(&mut iiiout, "}},")?;
                        writeln!(&mut iiout, "}};")?;
                        writeln!(
                            &mut iiout,
                            "let buf = marshal_{}(buf, {})?;",
                            Self::predefined_type_to_rust(base_type),
                            &acc_size_name
                        )?;
                    } else if let Some(array_members) = lookup_array_size_specifier_member(j) {
                        let base_type = match base_type {
                            StructureTableEntryResolvedBaseType::Predefined(p) => *p,
                            StructureTableEntryResolvedBaseType::Constants(index) => {
                                let table = self.tables.structures.get_constants(*index);
                                *table.resolved_base.as_ref().unwrap()
                            }
                            StructureTableEntryResolvedBaseType::Type(index) => {
                                let table = self.tables.structures.get_type(*index);
                                *table.underlying_type.as_ref().unwrap()
                            }
                            _ => unreachable!(),
                        };

                        let member_name = Self::format_structure_member_name(&entry.name);
                        let array_member_index =
                            find_array_size_specifier_primary_array(j, array_members);
                        let array_member_entry = &table.entries[array_member_index];
                        let array_member_name =
                            Self::format_structure_member_name(&array_member_entry.name);
                        writeln!(
                            &mut iiout,
                            "let marshalled_{} = match {}::try_from(self.{}.len()) {{",
                            &member_name,
                            Self::predefined_type_to_rust(base_type),
                            &array_member_name
                        )?;
                        let mut iiiout = iiout.make_indent();
                        writeln!(
                            &mut iiiout,
                            "Ok(marshalled_{}) => marshalled_{},",
                            &member_name, &member_name
                        )?;
                        writeln!(&mut iiiout, "Err(_) => {{")?;
                        self.format_error_return(&mut iiiout.make_indent(), None, error_rc_size.unwrap())?;
                        writeln!(&mut iiiout, "}},")?;
                        writeln!(&mut iiout, "}};")?;
                        writeln!(
                            &mut iiout,
                            "let buf = marshal_{}(buf, marshalled_{})?;",
                            Self::predefined_type_to_rust(base_type),
                            &member_name
                        )?;
                    } else {
                        let src_spec =
                            "self.".to_owned() + &Self::format_structure_member_name(&entry.name);
                        self.gen_structure_member_plain_type_marshal(
                            &mut iiout, "buf", "buf", &src_spec, base_type,
                        )?;
                    }

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
                StructureTableEntryType::Discriminant(_) => {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    assert!(entry.deps.is_unconditional_true());
                    let src_spec =
                        "self.".to_owned() + &Self::format_structure_member_name(&entry.name);
                    writeln!(
                        &mut iout,
                        "let buf = {}.marshal_intern_selector(buf)?;",
                        src_spec
                    )?;
                }
                StructureTableEntryType::Array(array_type) => {
                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    let deps = &entry.deps;
                    let deps = deps.factor_by_common_of(&table_deps);
                    let deps = deps.factor_by_common_of(&marshal_deps);
                    let mut iiout = if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(&mut iout, "{{")?;
                        iout.make_indent()
                    } else {
                        iout.make_same_indent()
                    };

                    let member_name = Self::format_structure_member_name(&entry.name);
                    let src_spec = "self.".to_owned() + &member_name;
                    self.gen_structure_member_array_marshal(
                        &mut iiout,
                        "buf",
                        "buf",
                        &member_name,
                        &src_spec,
                        array_type.resolved_element_type.as_ref().unwrap(),
                        &array_type.size,
                    )?;

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
                StructureTableEntryType::Union(union_type) => {
                    let entry = union_type.resolved_discriminant.unwrap();
                    let entry = &table.entries[entry];
                    let discriminant =
                        Self::to_structure_discriminant_entry_type(&entry.entry_type);
                    if j != discriminant.discriminated_union_members[0] {
                        continue;
                    }

                    if !first {
                        writeln!(&mut iout)?;
                    }
                    first = false;
                    assert!(entry.deps.is_unconditional_true());

                    let enable_conditional = if discriminant.discriminant_type_enable_conditional {
                        true
                    } else if discriminant.discriminant_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    let need_limits = self.tagged_union_marshal_needs_limits(
                        table,
                        discriminant,
                        enable_conditional,
                    );
                    let limits_arg = if need_limits { ", limits" } else { "" };

                    let src_spec =
                        "self.".to_owned() + &Self::format_structure_member_name(&entry.name);

                    writeln!(
                        &mut iout,
                        "let buf = {}.marshal_intern_data(buf{})?;",
                        src_spec, limits_arg
                    )?;
                }
            };
        }

        if !first {
            writeln!(&mut iout)?;
        }
        writeln!(&mut iout, "Ok(buf)")?;
        writeln!(out, "}}")?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn gen_tagged_union_marshal<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        table_deps: &ConfigDepsDisjunction,
        discriminant_member: usize,
        is_structure_member_repr: bool,
        conditional: bool,
        enable_enum_transmute: bool,
    ) -> Result<(), io::Error> {
        let discriminant_entry = &table.entries[discriminant_member];
        assert!(discriminant_entry.deps.is_unconditional_true());
        let discriminant =
            Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);

        let mut marshal_deps = closure_deps.collect_config_deps(ClosureDepsFlags::ANY_MARSHAL);
        marshal_deps.factor_by_common_of(table_deps);

        let references_inbuf = self.structure_references_inbuf(table);
        let buf_lifetime = if !references_inbuf { "a" } else { "b" };

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
        let enable_conditional = conditional | discriminant.discriminant_type_enable_conditional;

        // If the tagged union does not represent a complete structure from the
        // interface specification but some set of union members only, then the
        // discriminant might be separated from the sequence of union members in
        // the containing structure. Provide a primitive for marshalling the
        // discriminant separately from the container.
        let mut first = true;
        if is_structure_member_repr {
            first = false;
            if !marshal_deps.is_implied_by(table_deps) {
                writeln!(out, "#[cfg({})]", Self::format_deps(&marshal_deps))?;
            }
            writeln!(
                out,
                "fn marshal_intern_selector<'{}>(&self, buf: &'{} mut [u8]) -> Result<&'{} mut [u8], TpmErr> {{",
                buf_lifetime, buf_lifetime, buf_lifetime
            )?;
            let mut iout = out.make_indent();
            if enable_enum_transmute {
                writeln!(
                    &mut iout,
                    "let selector = unsafe{{*(self as *const Self as *const {})}};",
                    Self::predefined_type_to_rust(discriminant_base)
                )?;
            } else {
                writeln!(&mut iout, "let selector = match self {{")?;
                let mut iiout = iout.make_indent();
                for selector in UnionSelectorIterator::new(
                    &self.tables.structures,
                    *discriminant.resolved_discriminant_type.as_ref().unwrap(),
                    enable_conditional,
                ) {
                    let deps = selector.config_deps().factor_by_common_of(table_deps);
                    let deps = deps.factor_by_common_of(&marshal_deps);
                    if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "#[cfg({})]",
                            Self::format_dep_conjunction(&deps)
                        )?;
                    }

                    let enum_member_name = self.format_tagged_union_member_name(&selector);
                    let enum_member_name = Self::camelize(&enum_member_name);

                    let selected_union_members =
                        self.get_structure_selected_union_members(table, discriminant, &selector);
                    let selected_union_members_match_spec = selected_union_members
                        .iter()
                        .map(|(u, _, _)| {
                            let match_spec =
                                Self::format_structure_member_name(&table.entries[*u].name)
                                    .into_owned();
                            if discriminant.discriminated_union_members.len() == 1 {
                                "_".to_owned()
                            } else {
                                match_spec + ": _"
                            }
                        })
                        .collect::<Vec<String>>()
                        .join(", ");

                    let selector_value = match selector {
                        UnionSelectorIteratorValue::Constant(_, constant_index) => constant_index,
                        UnionSelectorIteratorValue::Type(
                            _,
                            type_table_index,
                            type_table_entry_index,
                        ) => {
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

                    if selected_union_members.is_empty() {
                        writeln!(
                            &mut iiout,
                            "Self::{} => {},",
                            enum_member_name, selector_value.0
                        )?;
                    } else if discriminant.discriminated_union_members.len() == 1 {
                        writeln!(
                            &mut iiout,
                            "Self::{}({}) => {},",
                            enum_member_name, selected_union_members_match_spec, selector_value.0
                        )?;
                    } else {
                        writeln!(
                            &mut iiout,
                            "Self::{}{{{}}} => {},",
                            enum_member_name, selected_union_members_match_spec, selector_value.0
                        )?;
                    }
                }

                writeln!(&mut iout, "}};")?;
                writeln!(&mut iout)?;
            }
            writeln!(
                &mut iout,
                "marshal_{}(buf, selector)",
                Self::predefined_type_to_rust(discriminant_base)
            )?;

            writeln!(out, "}}")?;
        }

        // If the tagged union corresponds to a full structure from the
        // interface specification (as opposed to serving only as some structure
        // member's representation), then make the marshal() public, if
        // marshalling functionality is provided to extern.
        let make_public = if is_structure_member_repr {
            false
        } else {
            closure_deps.any(ClosureDepsFlags::EXTERN_MARSHAL)
        };
        let pub_spec = if make_public { "pub " } else { "" };

        let intern_spec = if is_structure_member_repr {
            "_intern_data"
        } else {
            ""
        };

        let need_limits = self.tagged_union_marshal_needs_limits(table, discriminant, conditional);
        let limits_arg = if need_limits {
            ", limits: &TpmLimits"
        } else {
            ""
        };

        if !first {
            writeln!(out)?;
        }
        if !marshal_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&marshal_deps))?;
        }
        writeln!(
            out,
            "{}fn marshal{}<'{}>(&self, buf: &'{} mut [u8]{}) -> Result<&'{} mut [u8], TpmErr> {{",
            pub_spec, intern_spec, buf_lifetime, buf_lifetime, limits_arg, buf_lifetime
        )?;
        let mut iout = out.make_indent();

        // If the tagged union corresponds to a full structure from the
        // interface specification (as opposed to serving only as some structure
        // member's representation), then the <size>= specifiers, if any, will
        // get marshalled alongside the discriminant as well. Emit code to
        // calculate any <size>= specifier values upfront, so that they can get
        // marshalled below, possibly after the discriminant value.
        if !is_structure_member_repr {
            let error_rc_size = self
                .tables
                .structures
                .lookup_constant("TPM_RC_SIZE");
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                match &entry.entry_type {
                    StructureTableEntryType::Discriminant(_) => {
                        assert_eq!(j, discriminant_member);
                    }
                    StructureTableEntryType::Plain(plain_type) => {
                        let deps = &entry.deps;
                        let deps = deps.factor_by_common_of(table_deps);
                        let deps = deps.factor_by_common_of(&marshal_deps);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };

                        assert!(plain_type.is_size_specifier);
                        let member_name = Self::format_structure_member_name(&entry.name);
                        let acc_size_name = "marshalled_".to_owned() + &member_name;
                        writeln!(&mut iiout, "let mut {}: usize = 0;", acc_size_name)?;
                        self.gen_structure_members_marshalled_size(
                            &mut iiout,
                            &acc_size_name,
                            table,
                            false,
                            j + 1,
                            table_deps,
                            &marshal_deps,
                            conditional,
                            &|out| writeln!(out, "return Err(TpmErr::InternalErr);"),
                        )?;

                        let base_type = match plain_type.resolved_base_type.as_ref().unwrap() {
                            StructureTableEntryResolvedBaseType::Predefined(p) => *p,
                            StructureTableEntryResolvedBaseType::Constants(index) => {
                                let table = self.tables.structures.get_constants(*index);
                                *table.resolved_base.as_ref().unwrap()
                            }
                            StructureTableEntryResolvedBaseType::Type(index) => {
                                let table = self.tables.structures.get_type(*index);
                                *table.underlying_type.as_ref().unwrap()
                            }
                            _ => unreachable!(),
                        };

                        writeln!(&mut iiout)?;
                        writeln!(
                            &mut iiout,
                            "let {} = match {}::try_from({}) {{",
                            acc_size_name,
                            Self::predefined_type_to_rust(base_type),
                            acc_size_name
                        )?;
                        let mut iiiout = iiout.make_indent();
                        writeln!(&mut iiiout, "Ok({}) => {},", &acc_size_name, &acc_size_name)?;
                        writeln!(&mut iiiout, "Err(_) => {{")?;
                        self.format_error_return(&mut iiiout.make_indent(), None, error_rc_size.unwrap())?;
                        writeln!(&mut iiiout, "}},")?;
                        writeln!(&mut iiout, "}};")?;
                        writeln!(&mut iiout)?;

                        if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "}}")?;
                        }
                    }
                    StructureTableEntryType::Union(_) => {
                        assert_eq!(j, discriminant.discriminated_union_members[0]);
                        break;
                    }
                    StructureTableEntryType::Array(_) => unreachable!(),
                };
            }
        }

        writeln!(&mut iout, "let buf = match self {{")?;
        let mut iiout = iout.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            enable_conditional,
        ) {
            let deps = selector.config_deps().factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(&marshal_deps);
            if !deps.is_unconditional_true() {
                writeln!(
                    &mut iiout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&deps)
                )?;
            }

            let enum_member_name = self.format_tagged_union_member_name(&selector);
            let enum_member_name = Self::camelize(&enum_member_name);

            let selected_union_members = self.get_structure_selected_union_members(table, discriminant, &selector);
            let selected_union_members_match_spec = selected_union_members
                .iter()
                .map(|(u, _, _)| {
                    Self::format_structure_member_name(&table.entries[*u].name).into_owned()
                })
                .collect::<Vec<String>>()
                .join(", ");

            if selected_union_members.is_empty() {
                writeln!(&mut iiout, "Self::{} => {{", enum_member_name)?;
            } else if discriminant.discriminated_union_members.len() == 1 {
                writeln!(
                    &mut iiout,
                    "Self::{}({}) => {{",
                    enum_member_name, selected_union_members_match_spec
                )?;
            } else {
                writeln!(
                    &mut iiout,
                    "Self::{}{{{}}} => {{",
                    enum_member_name, selected_union_members_match_spec
                )?;
            }

            let mut iiiout = iiout.make_indent();
            let mut first = true;

            // If the tagged union corresponds to a full structure from the
            // interface specification (as opposed to serving only as some
            // structure member's representation), then marshal the discriminant
            // and <size>= specifiers, if any, as well.
            if !is_structure_member_repr {
                for j in 0..table.entries.len() {
                    let entry = &table.entries[j];
                    match &entry.entry_type {
                        StructureTableEntryType::Discriminant(_) => {
                            assert_eq!(j, discriminant_member);

                            if !first {
                                writeln!(&mut iiiout)?;
                            }
                            first = false;

                            assert!(entry.deps.is_unconditional_true());

                            let selector_value = match selector {
                                UnionSelectorIteratorValue::Constant(_, constant_index) => {
                                    constant_index
                                }
                                UnionSelectorIteratorValue::Type(
                                    _,
                                    type_table_index,
                                    type_table_entry_index,
                                ) => {
                                    let type_table =
                                        self.tables.structures.get_type(type_table_index);
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
                            writeln!(&mut iiiout, "let selector = {};", selector_value.0)?;
                            writeln!(
                                &mut iiiout,
                                "let buf = marshal_{}(buf, selector)?;",
                                Self::predefined_type_to_rust(discriminant_base)
                            )?;
                        }
                        StructureTableEntryType::Plain(plain_type) => {
                            assert!(plain_type.is_size_specifier);

                            if !first {
                                writeln!(&mut iiiout)?;
                            }
                            first = false;

                            let deps = &entry.deps;
                            let deps = deps.factor_by_common_of(table_deps);
                            let deps = deps.factor_by_common_of(&marshal_deps);
                            let mut iiiiout = if !deps.is_unconditional_true() {
                                writeln!(
                                    &mut iiiout,
                                    "#[cfg({})]",
                                    Self::format_dep_conjunction(&deps)
                                )?;
                                writeln!(&mut iiiout, "{{")?;
                                iiiout.make_indent()
                            } else {
                                iiiout.make_same_indent()
                            };

                            // Write out the <size>= specifier value calculated
                            // once before the match on the discriminant.
                            let member_name = Self::format_structure_member_name(&entry.name);
                            let acc_size_name = "marshalled_".to_owned() + &member_name;

                            let base_type = match plain_type.resolved_base_type.as_ref().unwrap() {
                                StructureTableEntryResolvedBaseType::Predefined(p) => *p,
                                StructureTableEntryResolvedBaseType::Constants(index) => {
                                    let table = self.tables.structures.get_constants(*index);
                                    *table.resolved_base.as_ref().unwrap()
                                }
                                StructureTableEntryResolvedBaseType::Type(index) => {
                                    let table = self.tables.structures.get_type(*index);
                                    *table.underlying_type.as_ref().unwrap()
                                }
                                _ => unreachable!(),
                            };

                            writeln!(
                                &mut iiiiout,
                                "let buf = marshal_{}(buf, {})?;",
                                Self::predefined_type_to_rust(base_type),
                                &acc_size_name
                            )?;

                            if !deps.is_unconditional_true() {
                                writeln!(&mut iiiout, "}}")?;
                            }
                        }
                        StructureTableEntryType::Union(_) => {
                            assert_eq!(j, discriminant.discriminated_union_members[0]);
                            break;
                        }
                        StructureTableEntryType::Array(_) => unreachable!(),
                    };
                }
            }

            for (u, union_table_index, selected_member_index) in selected_union_members.iter() {
                if !first {
                    writeln!(&mut iiiout)?;
                }
                first = false;

                let union_entry = &table.entries[*u];
                assert!(union_entry.deps.is_unconditional_true());
                let union_table = self.tables.structures.get_union(*union_table_index);
                let selected_member = &union_table.entries[*selected_member_index];

                let member_name = Self::format_structure_member_name(&union_entry.name);
                match &selected_member.entry_type {
                    UnionTableEntryType::Plain(plain_type) => {
                        self.gen_structure_member_plain_type_marshal(
                            &mut iiiout,
                            "buf",
                            "buf",
                            &member_name,
                            plain_type.resolved_base_type.as_ref().unwrap(),
                        )?;
                    }
                    UnionTableEntryType::Array(array_type) => {
                        self.gen_structure_member_array_marshal(
                            &mut iiiout,
                            "buf",
                            "buf",
                            &member_name,
                            &member_name,
                            array_type.resolved_element_type.as_ref().unwrap(),
                            &array_type.size,
                        )?;
                    }
                };
            }

            if !first {
                writeln!(&mut iiiout)?;
            }
            writeln!(&mut iiiout, "buf")?;
            writeln!(&mut iiout, "}},")?;
        }

        writeln!(&mut iout, "}};")?;

        writeln!(&mut iout, "Ok(buf)")?;

        writeln!(out, "}}")?;

        Ok(())
    }
}
