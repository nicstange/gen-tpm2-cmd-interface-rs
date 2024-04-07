// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;
use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use crate::tcg_tpm2::structures::table_common::ClosureDeps;
use crate::tcg_tpm2::structures::union_table::UnionTableEntryType;
use structures::expr::{Expr, ExprValue};
use structures::predefined::{PredefinedTypeRef, PredefinedTypes};
use structures::structure_table::{
    StructureTable, StructureTableEntryDiscriminantType, StructureTableEntryResolvedBaseType,
    StructureTableEntryType,
};
use structures::table_common::ClosureDepsFlags;
use structures::tables::UnionSelectorIterator;
use structures::value_range::ValueRange;

use super::super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(in super::super) fn structure_has_fixed_size(table: &StructureTable) -> (bool, bool) {
        let (size_is_fixed, fixed_size_is_compiletime_constant) = match table.size.as_ref().unwrap()
        {
            ExprValue::CompiletimeConstant(_) => (true, true),
            ExprValue::RuntimeConstant(_) => (true, false),
            _ => (false, false),
        };
        (size_is_fixed, fixed_size_is_compiletime_constant)
    }

    fn structure_member_plain_type_has_fixed_size(
        &self,
        plain_type: &StructureTableEntryResolvedBaseType,
    ) -> (bool, bool) {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_)
            | StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => (true, true),
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                Self::structure_has_fixed_size(&table)
            }
        }
    }

    fn structure_member_plain_type_size_is_compiletime_const(
        &self,
        plain_type: &StructureTableEntryResolvedBaseType,
    ) -> bool {
        self.structure_member_plain_type_has_fixed_size(plain_type)
            .1
    }

    pub(in super::super) fn structure_max_size_is_compiletime_const(
        table: &StructureTable,
    ) -> bool {
        // If the structure has a fixed size, its calculated max_size and size
        // could be contradictionary with each other as far as compile-time
        // constness is concerned: in theory, there could be corner cases where
        // some array size depends on the runtime limits, but the size is also
        // bounded by some compile-time constant expression and vice-versa. For
        // well-definedness, always determine the maximum size's compile-time constness
        // from the fixed size in this case.
        let (has_fixed_size, fixed_size_is_compiletime_constant) =
            Self::structure_has_fixed_size(table);
        if has_fixed_size {
            fixed_size_is_compiletime_constant
        } else {
            match table.max_size.as_ref().unwrap() {
                ExprValue::CompiletimeConstant(_) => true,
                ExprValue::RuntimeConstant(_) => false,
                _ => unreachable!(),
            }
        }
    }

    pub(super) fn format_structure_member_plain_type_compiletime_fixed_size(
        &self,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
    ) -> (String, Option<PredefinedTypeRef>) {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => (
                format!("mem::size_of::<{}>()", Self::predefined_type_to_rust(*p)),
                None,
            ),
            StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_) => {
                assert!(!conditional);
                let type_spec = self.format_structure_member_plain_type(plain_type, false, true);
                let member_size_type = PredefinedTypes::find_type_with_repr(16, false).unwrap();
                (
                    format!("{}::marshalled_size()", type_spec),
                    Some(member_size_type),
                )
            }
            StructureTableEntryResolvedBaseType::Type(_) => {
                let type_spec =
                    self.format_structure_member_plain_type(plain_type, conditional, true);
                let member_size_type = PredefinedTypes::find_type_with_repr(16, false).unwrap();
                (
                    format!("{}::marshalled_size()", type_spec),
                    Some(member_size_type),
                )
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                // At this point only compiletime constant sizes are handled, runtime constant
                // sizes would require error handling.
                assert_eq!(Self::structure_has_fixed_size(&table), (true, true));
                let mut type_spec = table.name.to_ascii_lowercase();
                if conditional {
                    type_spec += "_wcv";
                }
                let member_size_type = self.determine_structure_max_size_type(&table).unwrap();
                (
                    format!("{}_marshalled_size()", type_spec),
                    Some(member_size_type),
                )
            }
        }
    }

    fn gen_structure_member_plain_type_fixed_size<W: io::Write, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        acc_dst_name: Option<&str>,
        dst_name: &str,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        handle_err: &HE,
    ) -> Result<(), io::Error>
    where
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_)
            | StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => {
                let (size, size_type) = self
                    .format_structure_member_plain_type_compiletime_fixed_size(
                        plain_type,
                        conditional,
                    );
                if size_type.is_none() {
                    writeln!(out, "let {}_size = {};", dst_name, &size)?;
                } else {
                    writeln!(
                        out,
                        "let {}_size = match usize::try_from({}) {{",
                        dst_name, size
                    )?;
                    let mut iout = out.make_indent();
                    writeln!(&mut iout, "Ok({}_size) => {}_size,", dst_name, dst_name)?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    handle_err(&mut iout.make_indent())?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                }
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                let (size_is_fixed, fixed_size_is_compiletime_constant) =
                    Self::structure_has_fixed_size(&table);
                assert!(size_is_fixed);
                if fixed_size_is_compiletime_constant {
                    let (size, size_type) = self
                        .format_structure_member_plain_type_compiletime_fixed_size(
                            plain_type,
                            conditional,
                        );
                    if size_type.is_none() {
                        writeln!(out, "let {}_size = {};", dst_name, &size)?;
                    } else {
                        writeln!(
                            out,
                            "let {}_size = match usize::try_from({}) {{",
                            dst_name, size
                        )?;
                        let mut iout = out.make_indent();
                        writeln!(&mut iout, "Ok({}_size) => {}_size,", dst_name, dst_name)?;
                        writeln!(&mut iout, "Err(_) => {{")?;
                        handle_err(&mut iout.make_indent())?;
                        writeln!(&mut iout, "}},")?;
                        writeln!(out, "}};")?;
                    }
                } else {
                    // Size is a runtime constant, its evaluation needs the limits and can fail.
                    let mut type_spec = table.name.to_ascii_lowercase();
                    if conditional {
                        type_spec += "_wcv";
                    }
                    writeln!(
                        out,
                        "let {}_size = match {}_marshalled_size(limits) {{",
                        dst_name, type_spec
                    )?;
                    let mut iout = out.make_indent();
                    writeln!(&mut iout, "Ok({}_size) => {}_size,", dst_name, dst_name)?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    handle_err(&mut iout.make_indent())?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                    writeln!(
                        out,
                        "let {}_size = match usize::try_from({}_size) {{",
                        dst_name, dst_name
                    )?;
                    let mut iout = out.make_indent();
                    writeln!(&mut iout, "Ok({}_size) => {}_size,", dst_name, dst_name)?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    handle_err(&mut iout.make_indent())?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                }
            }
        };

        if let Some(acc_dst_name) = acc_dst_name {
            writeln!(
                out,
                "{} = match {}.checked_add({}_size) {{",
                acc_dst_name, acc_dst_name, dst_name
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "Some({}) => {},", acc_dst_name, acc_dst_name)?;
            writeln!(&mut iout, "None => {{")?;
            handle_err(&mut iout.make_indent())?;
            writeln!(&mut iout, "}},")?;
            writeln!(out, "}};")?;
        }

        Ok(())
    }

    pub(in super::super) fn structure_marshalled_size_needs_limits(table: &StructureTable) -> bool {
        match table.size.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(_) => false,
            ExprValue::RuntimeConstant(_) => true,
            ExprValue::Dynamic => false,
            ExprValue::DynamicWithRuntimeConstantDep(_) => true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_structure_member_plain_type_size<W: io::Write, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        acc_dst_name: Option<&str>,
        dst_name: &str,
        member_ref: &str,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        handle_err: &HE,
    ) -> Result<(), io::Error>
    where
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_)
            | StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => {
                return self.gen_structure_member_plain_type_fixed_size(
                    out,
                    acc_dst_name,
                    dst_name,
                    plain_type,
                    conditional,
                    handle_err,
                );
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                let (size_is_fixed, _) = Self::structure_has_fixed_size(&table);
                if size_is_fixed {
                    return self.gen_structure_member_plain_type_fixed_size(
                        out,
                        acc_dst_name,
                        dst_name,
                        plain_type,
                        conditional,
                        handle_err,
                    );
                }

                // The structure's marshalled size is dynamic.
                let need_limits = Self::structure_marshalled_size_needs_limits(&table);
                let limits_spec = if need_limits { "limits" } else { "" };

                writeln!(
                    out,
                    "let {}_size = match {}.marshalled_size({}) {{",
                    dst_name, member_ref, limits_spec
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Ok({}_size) => {}_size,", dst_name, dst_name)?;
                writeln!(&mut iout, "Err(_) => {{")?;
                handle_err(&mut iout.make_indent())?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;
            }
        };

        if let Some(acc_dst_name) = acc_dst_name {
            writeln!(
                out,
                "{} = match {}.checked_add({}_size) {{",
                acc_dst_name, acc_dst_name, dst_name
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "Some({}) => {},", acc_dst_name, acc_dst_name)?;
            writeln!(&mut iout, "None => {{")?;
            handle_err(&mut iout.make_indent())?;
            writeln!(&mut iout, "}},")?;
            writeln!(out, "}};")?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_structure_member_array_size<W: io::Write, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        acc_dst_name: Option<&str>,
        dst_name: &str,
        member_ref: Option<&str>,
        element_type: &StructureTableEntryResolvedBaseType,
        array_size: &Expr,
        conditional: bool,
        handle_err: &HE,
    ) -> Result<(), io::Error>
    where
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        let (is_byte_array, element_size_is_fixed) = match element_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => (p.bits == 8 && !p.signed, true),
            StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => (false, true),
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                let (size_is_fixed, _) = Self::structure_has_fixed_size(&table);
                (false, size_is_fixed)
            }
        };

        let len_spec = if is_byte_array { "size" } else { "len" };
        if element_size_is_fixed {
            match array_size.value.as_ref().unwrap() {
                ExprValue::CompiletimeConstant(_) | ExprValue::RuntimeConstant(_) => {
                    let (array_size, _, _) = self
                        .format_expr(
                            out,
                            array_size,
                            None,
                            "limits",
                            None,
                            &|_, _| unreachable!(),
                            handle_err,
                        )
                        .map_err(|_| {
                            eprintln!("error: {}: integer overflow in array's size", table_name);
                            io::Error::from(io::ErrorKind::InvalidData)
                        })?;

                    writeln!(
                        out,
                        "let {}_{} = match usize::try_from({}) {{",
                        dst_name, len_spec, array_size
                    )?;
                    let mut iout = out.make_indent();
                    writeln!(
                        &mut iout,
                        "Ok({}_{}) => {}_{},",
                        dst_name, len_spec, dst_name, len_spec
                    )?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    handle_err(&mut iout.make_indent())?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                }
                ExprValue::Dynamic | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                    writeln!(
                        out,
                        "let {}_{} = {}.len();",
                        dst_name,
                        len_spec,
                        member_ref.unwrap()
                    )?;
                }
            };

            if !is_byte_array {
                self.gen_structure_member_plain_type_fixed_size(
                    out,
                    None,
                    &format!("{}_element", dst_name),
                    element_type,
                    conditional,
                    handle_err,
                )?;
                writeln!(
                    out,
                    "let {}_size = match {}_len.checked_mul({}_element_size) {{",
                    dst_name, dst_name, dst_name
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Some({}_size) => {}_size,", dst_name, dst_name)?;
                writeln!(&mut iout, "None => {{")?;
                handle_err(&mut iout.make_indent())?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;
            }
        } else {
            writeln!(out, "let mut {}_size: usize = 0;", dst_name)?;
            writeln!(out, "for element in {}.iter() {{", member_ref.unwrap())?;
            self.gen_structure_member_plain_type_size(
                &mut out.make_indent(),
                Some(&format!("{}_size", dst_name)),
                &format!("{}_element", dst_name),
                "element",
                element_type,
                conditional,
                handle_err,
            )?;
            writeln!(out, "}}")?;
        }

        if let Some(acc_dst_name) = acc_dst_name {
            writeln!(
                out,
                "{} = match {}.checked_add({}_size) {{",
                acc_dst_name, acc_dst_name, dst_name
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "Some({}) => {},", acc_dst_name, acc_dst_name)?;
            writeln!(&mut iout, "None => {{")?;
            handle_err(&mut iout.make_indent())?;
            writeln!(&mut iout, "}},")?;
            writeln!(out, "}};")?;
        }

        Ok(())
    }

    pub(super) fn tagged_union_size_needs_limits(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
        conditional: bool,
    ) -> bool {
        let discriminant_type = discriminant.resolved_discriminant_type.as_ref().unwrap();
        for selector in
            UnionSelectorIterator::new(&self.tables.structures, *discriminant_type, conditional)
        {
            for k in discriminant.discriminated_union_members.iter() {
                let union_member_entry = &table.entries[*k];
                let union_type =
                    Self::to_structure_union_entry_type(&union_member_entry.entry_type);
                let union_table_index = union_type.resolved_union_type.unwrap();
                let union_table = self.tables.structures.get_union(union_table_index);
                let union_entry = union_table.lookup_member(selector.name()).unwrap();
                let union_entry = &union_table.entries[union_entry];
                match &union_entry.entry_type {
                    UnionTableEntryType::Plain(plain_type) => {
                        let base_type = match plain_type.resolved_base_type.as_ref() {
                            Some(base_type) => base_type,
                            None => continue,
                        };
                        match base_type {
                            StructureTableEntryResolvedBaseType::Predefined(_) => (),
                            StructureTableEntryResolvedBaseType::Constants(_) => (),
                            StructureTableEntryResolvedBaseType::Bits(_) => (),
                            StructureTableEntryResolvedBaseType::Type(_) => (),
                            StructureTableEntryResolvedBaseType::Structure(index) => {
                                let table = self.tables.structures.get_structure(*index);
                                match table.size.as_ref().unwrap() {
                                    ExprValue::CompiletimeConstant(_) | ExprValue::Dynamic => (),
                                    ExprValue::RuntimeConstant(_)
                                    | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                                        return true;
                                    }
                                };
                            }
                        };
                    }
                    UnionTableEntryType::Array(array_type) => {
                        let element_type = array_type.resolved_element_type.as_ref().unwrap();
                        match element_type {
                            StructureTableEntryResolvedBaseType::Predefined(_) => (),
                            StructureTableEntryResolvedBaseType::Constants(_) => (),
                            StructureTableEntryResolvedBaseType::Bits(_) => (),
                            StructureTableEntryResolvedBaseType::Type(_) => (),
                            StructureTableEntryResolvedBaseType::Structure(index) => {
                                let table = self.tables.structures.get_structure(*index);
                                match table.size.as_ref().unwrap() {
                                    ExprValue::CompiletimeConstant(_) | ExprValue::Dynamic => (),
                                    ExprValue::RuntimeConstant(_)
                                    | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                                        return true;
                                    }
                                };
                            }
                        };

                        match array_type.size.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(_) | ExprValue::Dynamic => (),
                            ExprValue::RuntimeConstant(_)
                            | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                                return true;
                            }
                        };
                    }
                };
            }
        }

        false
    }

    pub(in super::super) fn format_structure_member_plain_type_compiletime_max_size(
        &self,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        size_type: PredefinedTypeRef,
    ) -> String {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_)
            | StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => {
                let (member_size, member_size_type) = self
                    .format_structure_member_plain_type_compiletime_fixed_size(
                        plain_type,
                        conditional,
                    );
                match member_size_type {
                    None => {
                        format!(
                            "{} as {}",
                            member_size,
                            Self::predefined_type_to_rust(size_type)
                        )
                    }
                    Some(member_size_type) => {
                        assert!(size_type.bits >= member_size_type.bits);
                        if member_size_type != size_type {
                            format!(
                                "{} as {}",
                                member_size,
                                Self::predefined_type_to_rust(size_type)
                            )
                        } else {
                            member_size
                        }
                    }
                }
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                let (size_is_fixed, fixed_size_is_compiletime_constant) =
                    Self::structure_has_fixed_size(&table);
                if size_is_fixed {
                    // At this point only compiletime constant sizes are
                    // handled, runtime constant sizes would require error
                    // handling.
                    assert!(fixed_size_is_compiletime_constant);
                    let (member_size, member_size_type) = self
                        .format_structure_member_plain_type_compiletime_fixed_size(
                            plain_type,
                            conditional,
                        );
                    match member_size_type {
                        None => {
                            format!(
                                "{} as {}",
                                member_size,
                                Self::predefined_type_to_rust(size_type)
                            )
                        }
                        Some(member_size_type) => {
                            assert!(size_type.bits >= member_size_type.bits);
                            if member_size_type != size_type {
                                format!(
                                    "{} as {}",
                                    member_size,
                                    Self::predefined_type_to_rust(size_type)
                                )
                            } else {
                                member_size
                            }
                        }
                    }
                } else {
                    // At this point only compiletime constant sizes are
                    // handled, runtime constant sizes would require error
                    // handling.
                    assert!(Self::structure_max_size_is_compiletime_const(&table));
                    let mut type_spec = table.name.to_ascii_lowercase();
                    if conditional {
                        type_spec += "_wcv";
                    }
                    let member_size_type = self.determine_structure_max_size_type(&table).unwrap();
                    assert!(size_type.bits >= member_size_type.bits);
                    let cast_spec = if member_size_type != size_type {
                        borrow::Cow::Owned(
                            " as ".to_owned() + Self::predefined_type_to_rust(size_type),
                        )
                    } else {
                        borrow::Cow::Borrowed("")
                    };
                    format!("{}_marshalled_max_size(){}", type_spec, cast_spec)
                }
            }
        }
    }

    pub(in super::super) fn format_structure_member_plain_type_max_size<W: io::Write, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        dst_name: &str,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        size_type: PredefinedTypeRef,
        handle_err: &mut HE,
    ) -> Result<String, io::Error>
    where
        HE: FnMut(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_)
            | StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => Ok(self
                .format_structure_member_plain_type_compiletime_max_size(
                    plain_type,
                    conditional,
                    size_type,
                )),
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                if Self::structure_max_size_is_compiletime_const(&table) {
                    return Ok(
                        self.format_structure_member_plain_type_compiletime_max_size(
                            plain_type,
                            conditional,
                            size_type,
                        ),
                    );
                };
                let mut type_spec = table.name.to_ascii_lowercase();
                if conditional {
                    type_spec += "_wcv";
                }
                let member_size_type = self.determine_structure_max_size_type(&table).unwrap();
                assert!(size_type.bits >= member_size_type.bits);
                let cast_spec = if member_size_type != size_type {
                    borrow::Cow::Owned(" as ".to_owned() + Self::predefined_type_to_rust(size_type))
                } else {
                    borrow::Cow::Borrowed("")
                };
                let (size_is_fixed, fixed_size_is_compiletime_constant) =
                    Self::structure_has_fixed_size(&table);
                assert!(!fixed_size_is_compiletime_constant);
                let max_size_name_spec = if size_is_fixed { "size" } else { "max_size" };
                writeln!(
                    out,
                    "let {} = match {}_marshalled_{}(limits) {{",
                    dst_name, type_spec, max_size_name_spec
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Ok({}) => {}{},", dst_name, dst_name, cast_spec)?;
                writeln!(&mut iout, "Err(_) => {{")?;
                handle_err(&mut iout.make_indent())?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;
                Ok(dst_name.to_owned())
            }
        }
    }

    pub(super) fn gen_structure_marshalled_max_size_impl<W: io::Write>(
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

        // If the size is fixed, the maximum on the marshalled size equals the
        // fixed size. There is no point in providing a separate helper for the
        // maximum possible size, emit only a single one and reflect this fact
        // in its naming.
        let (size_is_fixed, fixed_size_is_compiletime_const) =
            Self::structure_has_fixed_size(table);
        let max_size_name = if size_is_fixed { "size" } else { "max_size" };
        let max_size_deps_flags = if size_is_fixed {
            ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE
        } else {
            ClosureDepsFlags::ANY_MAX_SIZE
        };
        let mut max_size_deps = table_closure_deps.collect_config_deps(max_size_deps_flags);
        if !max_size_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&max_size_deps))?;
        }

        let mut type_spec = table.name.to_ascii_lowercase();
        if conditional {
            type_spec += "_wcv";
        }
        let size_type = self.determine_structure_max_size_type(table).map_err(|_| {
            eprintln!("error: {}: integer overflow in structure size", &table.name);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let max_size_is_compiletime_const = Self::structure_max_size_is_compiletime_const(table);
        assert!(!size_is_fixed || fixed_size_is_compiletime_const == max_size_is_compiletime_const);
        if max_size_is_compiletime_const {
            writeln!(
                out,
                "const fn {}_marshalled_{}() -> {} {{",
                type_spec,
                max_size_name,
                Self::predefined_type_to_rust(size_type)
            )?;
        } else {
            writeln!(
                out,
                "fn {}_marshalled_{}(limits: &TpmLimits) -> Result<{}, ()> {{",
                type_spec,
                max_size_name,
                Self::predefined_type_to_rust(size_type)
            )?;
        }
        let mut iout = out.make_indent();

        let mut_spec = if table.entries.is_empty() { "" } else { "mut " };
        writeln!(
            &mut iout,
            "let {}size: {} = 0;",
            mut_spec,
            Self::predefined_type_to_rust(size_type)
        )?;

        // Do the members with sizes known at compile-time first -- their
        // accumulated size is guaranteed not to overflow the size type.
        let mut runtime_size_entries = Vec::new();
        let mut first = true;
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            let deps = &entry.deps;
            let deps = deps.factor_by_common_of(&max_size_deps);
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                    if let StructureTableEntryResolvedBaseType::Structure(index) = base_type {
                        let member_table = self.tables.structures.get_structure(*index);
                        if !Self::structure_max_size_is_compiletime_const(&member_table) {
                            runtime_size_entries.push(j);
                            continue;
                        }
                    }

                    if first {
                        writeln!(&mut iout)?;
                    }
                    first = false;

                    let mut iiout = if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(&mut iout, "{{")?;
                        iout.make_indent()
                    } else {
                        iout.make_same_indent()
                    };

                    let enable_conditional = if plain_type.base_type_enable_conditional {
                        true
                    } else if plain_type.base_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    let plain_type = plain_type.resolved_base_type.as_ref().unwrap();
                    let member_max_size = self
                        .format_structure_member_plain_type_compiletime_max_size(
                            plain_type,
                            enable_conditional,
                            size_type,
                        );
                    writeln!(&mut iiout, "size += {};", member_max_size)?;

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
                StructureTableEntryType::Discriminant(discriminant) => {
                    if first {
                        writeln!(&mut iout)?;
                    }
                    first = false;

                    assert!(deps.is_unconditional_true());

                    let enable_conditional = if discriminant.discriminant_type_enable_conditional {
                        true
                    } else if discriminant.discriminant_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    let base_type = discriminant.resolved_discriminant_type.as_ref().unwrap();
                    let base_type = StructureTableEntryResolvedBaseType::from(*base_type);
                    let member_max_size = self
                        .format_structure_member_plain_type_compiletime_max_size(
                            &base_type,
                            enable_conditional,
                            size_type,
                        );
                    writeln!(&mut iout, "size += {};", member_max_size)?;
                }
                StructureTableEntryType::Union(union_type) => {
                    let union_table_index = union_type.resolved_union_type.as_ref().unwrap();
                    let union_table = self.tables.structures.get_union(*union_table_index);
                    match union_table.max_size.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(_) => (),
                        _ => {
                            runtime_size_entries.push(j);
                            continue;
                        }
                    };

                    if first {
                        writeln!(&mut iout)?;
                    }
                    first = false;

                    assert!(deps.is_unconditional_true());

                    let member_size_type =
                        self.determine_union_max_size_type(&union_table).unwrap();
                    let cast_spec = if member_size_type != size_type {
                        borrow::Cow::Owned(
                            " as ".to_owned() + Self::predefined_type_to_rust(size_type),
                        )
                    } else {
                        borrow::Cow::Borrowed("")
                    };
                    writeln!(
                        &mut iout,
                        "size += {}::marshalled_max_size(){};",
                        Self::camelize(&union_table.name),
                        cast_spec
                    )?;
                }
                StructureTableEntryType::Array(array_type) => {
                    let array_size = match &array_type.size_range {
                        Some(ValueRange::Range {
                            min_value: _,
                            max_value: Some(max_value),
                        }) => max_value,
                        _ => &array_type.size,
                    };
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

                    if first {
                        writeln!(&mut iout)?;
                    }
                    first = false;

                    let mut iiout = if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(&mut iout, "{{")?;
                        iout.make_indent()
                    } else {
                        iout.make_same_indent()
                    };

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
                        let enable_conditional = if array_type.element_type_enable_conditional {
                            true
                        } else if array_type.element_type_conditional {
                            conditional
                        } else {
                            false
                        };
                        let element_size = self
                            .format_structure_member_plain_type_compiletime_max_size(
                                element_type,
                                enable_conditional,
                                size_type,
                            );
                        writeln!(&mut iiout, "size += {} * {};", element_size, array_size.0)?;
                    } else {
                        writeln!(&mut iiout, "size += {};", array_size.0)?;
                    }

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
            };
        }

        for j in runtime_size_entries.iter() {
            let entry = &table.entries[*j];
            writeln!(&mut iout)?;
            let deps = &entry.deps;
            let deps = deps.factor_by_common_of(&max_size_deps);
            let mut iiout = if !deps.is_unconditional_true() {
                writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                writeln!(&mut iout, "{{")?;
                iout.make_indent()
            } else {
                iout.make_same_indent()
            };
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    let enable_conditional = if plain_type.base_type_enable_conditional {
                        true
                    } else if plain_type.base_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    let plain_type = plain_type.resolved_base_type.as_ref().unwrap();
                    let member_max_size_name =
                        Self::format_structure_member_name(&entry.name) + "_size";
                    let member_max_size = self.format_structure_member_plain_type_max_size(
                        &mut iiout,
                        &member_max_size_name,
                        plain_type,
                        enable_conditional,
                        size_type,
                        &mut |out| writeln!(out, "return Err(());"),
                    )?;
                    writeln!(
                        &mut iiout,
                        "size = size.checked_add({}).ok_or(())?;",
                        member_max_size
                    )?;
                }
                StructureTableEntryType::Discriminant(_) => unreachable!(),
                StructureTableEntryType::Union(union_type) => {
                    assert!(deps.is_unconditional_true());
                    let union_table_index = union_type.resolved_union_type.as_ref().unwrap();
                    let union_table = self.tables.structures.get_union(*union_table_index);
                    let member_size_type =
                        self.determine_union_max_size_type(&union_table).unwrap();
                    let cast_spec = if member_size_type != size_type {
                        borrow::Cow::Owned(
                            " as ".to_owned() + Self::predefined_type_to_rust(size_type),
                        )
                    } else {
                        borrow::Cow::Borrowed("")
                    };
                    let member_max_size_name =
                        Self::format_structure_member_name(&entry.name) + "_size";
                    writeln!(
                        &mut iiout,
                        "let {} = match {}::marshalled_max_size(limits) {{",
                        &member_max_size_name,
                        Self::camelize(&union_table.name)
                    )?;
                    let mut iiiout = iiout.make_indent();
                    writeln!(
                        &mut iiiout,
                        "Ok({}) => {}{},",
                        &member_max_size_name, &member_max_size_name, cast_spec
                    )?;
                    writeln!(&mut iiiout, "Err(_) => return Err(()),")?;
                    writeln!(&mut iiout, "}};")?;

                    writeln!(
                        &mut iiout,
                        "size = size.checked_add({}).ok_or(())?;",
                        member_max_size_name
                    )?;
                }
                StructureTableEntryType::Array(array_type) => {
                    let enable_conditional = if array_type.element_type_enable_conditional {
                        true
                    } else if array_type.element_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    let member_name = Self::format_structure_member_name(&entry.name);
                    let array_size = match &array_type.size_range {
                        Some(ValueRange::Range {
                            min_value: _,
                            max_value: Some(max_value),
                        }) => max_value,
                        _ => &array_type.size,
                    };
                    let array_size = self.format_expr_for_type(
                        &mut iiout,
                        array_size,
                        size_type,
                        "limits",
                        None,
                        &|_, _| unreachable!(),
                        &|out| writeln!(out, "return Err(());"),
                    )?;
                    writeln!(&mut iiout, "let {}_size = {};", &member_name, array_size)?;

                    let element_type = array_type.resolved_element_type.as_ref().unwrap();
                    let is_byte_array = match element_type {
                        StructureTableEntryResolvedBaseType::Predefined(p) => {
                            p.bits == 8 && !p.signed
                        }
                        _ => false,
                    };
                    if !is_byte_array {
                        let element_max_size = self.format_structure_member_plain_type_max_size(
                            &mut iiout,
                            &(member_name.clone() + "_element_size"),
                            element_type,
                            enable_conditional,
                            size_type,
                            &mut |out| writeln!(out, "return Err(());"),
                        )?;
                        writeln!(
                            &mut iiout,
                            "let {}_size = {}_size.checked_mul({}).ok_or(())?;",
                            &member_name, &member_name, element_max_size
                        )?;
                    }

                    writeln!(
                        &mut iiout,
                        "size = size.checked_add({}_size).ok_or(())?;",
                        member_name
                    )?;
                }
            };

            if !deps.is_unconditional_true() {
                writeln!(&mut iout, "}}",)?;
            }
        }

        if !table.entries.is_empty() {
            writeln!(&mut iout)?;
        }
        if max_size_is_compiletime_const {
            writeln!(&mut iout, "size")?;
        } else {
            writeln!(&mut iout, "Ok(size)")?;
        }

        writeln!(out, "}}")?;
        Ok(())
    }

    pub(super) fn gen_structure_marshalled_max_size<W: io::Write>(
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

        // If the size is fixed, the maximum on the marshalled size equals the
        // fixed size. There is no point in providing a separate helper for the
        // maximum possible size, emit only a single one and reflect this fact
        // in its naming.
        let (size_is_fixed, fixed_size_is_compiletime_const) =
            Self::structure_has_fixed_size(table);
        let max_size_name = if size_is_fixed { "size" } else { "max_size" };
        let max_size_deps_flags = if size_is_fixed {
            ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::EXTERN_MAX_SIZE
        } else {
            ClosureDepsFlags::EXTERN_MAX_SIZE
        };
        let mut max_size_deps = table_closure_deps.collect_config_deps(max_size_deps_flags);
        max_size_deps.factor_by_common_of(&table_deps);
        if !max_size_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&max_size_deps))?;
        }

        let pub_spec = if (size_is_fixed
            && table_closure_deps
                .any(ClosureDepsFlags::EXTERN_MAX_SIZE | ClosureDepsFlags::EXTERN_SIZE))
            || (!size_is_fixed && table_closure_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE))
        {
            "pub "
        } else {
            ""
        };

        let mut type_spec = table.name.to_ascii_lowercase();
        if conditional {
            type_spec += "_wcv";
        }
        let size_type = self.determine_structure_max_size_type(table).map_err(|_| {
            eprintln!("error: {}: integer overflow in structure size", &table.name);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let max_size_is_compiletime_const = Self::structure_max_size_is_compiletime_const(table);
        assert!(!size_is_fixed || fixed_size_is_compiletime_const == max_size_is_compiletime_const);
        if max_size_is_compiletime_const {
            writeln!(
                out,
                "{}const fn marshalled_{}() -> {} {{",
                pub_spec,
                max_size_name,
                Self::predefined_type_to_rust(size_type)
            )?;
            writeln!(out.make_indent(), "{}_marshalled_size()", type_spec)?;
            writeln!(out, "}}")?;
        } else {
            writeln!(
                out,
                "{}fn marshalled_{}(limits: &TpmLimits) -> Result<{}, ()> {{",
                pub_spec,
                max_size_name,
                Self::predefined_type_to_rust(size_type)
            )?;
            writeln!(out.make_indent(), "{}_marshalled_size(limits)", type_spec)?;
            writeln!(out, "}}")?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gen_structure_members_marshalled_size<W: io::Write, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        acc_dst_name: &str,
        table: &StructureTable,
        is_tagged_union: bool,
        members_begin: usize,
        table_deps: &ConfigDepsDisjunction,
        size_deps: &ConfigDepsDisjunction,
        conditional: bool,
        handle_err: &HE,
    ) -> Result<(), io::Error>
    where
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        // Do the members with sizes known at compile-time first in order to enable
        // constant folding by the compiler.
        let mut runtime_size_entries = Vec::new();
        for j in members_begin..table.entries.len() {
            let entry = &table.entries[j];
            let deps = &entry.deps;
            let deps = deps.factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(size_deps);
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                    if !self.structure_member_plain_type_size_is_compiletime_const(base_type) {
                        runtime_size_entries.push(j);
                        continue;
                    }

                    let enable_conditional = if plain_type.base_type_enable_conditional {
                        true
                    } else if plain_type.base_type_conditional {
                        conditional
                    } else {
                        false
                    };

                    writeln!(out)?;
                    let mut iout = if !deps.is_unconditional_true() {
                        writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(out, "{{")?;
                        out.make_indent()
                    } else {
                        out.make_same_indent()
                    };
                    self.gen_structure_member_plain_type_fixed_size(
                        &mut iout,
                        Some(acc_dst_name),
                        &Self::format_structure_member_name(&entry.name),
                        base_type,
                        enable_conditional,
                        handle_err,
                    )?;
                    if !deps.is_unconditional_true() {
                        writeln!(out, "}}")?;
                    }
                }
                StructureTableEntryType::Discriminant(discriminant) => {
                    writeln!(out)?;
                    // Only the discriminant is being handled here, the data part is
                    // accounted for once the first of the union members
                    // referencing it is encountered.
                    assert!(entry.deps.is_unconditional_true());

                    let (type_spec, member_name) = if is_tagged_union {
                        (borrow::Cow::Borrowed("Self"), borrow::Cow::Borrowed(""))
                    } else {
                        let type_spec = Self::format_structure_discriminant_member_enum_name(
                            table,
                            conditional,
                            entry,
                        );
                        let type_spec = Self::camelize(&type_spec);

                        let references_inbuf =
                            self.tagged_union_references_inbuf(table, discriminant);
                        let type_spec = if references_inbuf {
                            type_spec + "::<'_>"
                        } else {
                            type_spec
                        };

                        let member_name =
                            Self::format_structure_member_name(&entry.name).into_owned() + "_";
                        (
                            borrow::Cow::Owned(type_spec),
                            borrow::Cow::Owned(member_name),
                        )
                    };

                    writeln!(out,
                             "let {}selector_size = match usize::try_from({}::marshalled_selector_size()) {{",
                             &member_name, type_spec)?;
                    let mut iout = out.make_indent();
                    writeln!(
                        &mut iout,
                        "Ok({}selector_size) => {}selector_size,",
                        &member_name, &member_name
                    )?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    handle_err(&mut iout.make_indent())?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;

                    writeln!(
                        out,
                        "{} = match {}.checked_add({}selector_size) {{",
                        acc_dst_name, acc_dst_name, &member_name
                    )?;
                    let mut iout = out.make_indent();
                    writeln!(&mut iout, "Some({}) => {},", acc_dst_name, acc_dst_name)?;
                    writeln!(&mut iout, "None => {{")?;
                    handle_err(&mut iout.make_indent())?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                }
                StructureTableEntryType::Union(union_type) => {
                    let entry = union_type.resolved_discriminant.unwrap();
                    let entry = &table.entries[entry];
                    let discriminant =
                        Self::to_structure_discriminant_entry_type(&entry.entry_type);
                    if j != discriminant.discriminated_union_members[0] {
                        continue;
                    }
                    runtime_size_entries.push(j);
                    continue;
                }
                StructureTableEntryType::Array(array_type) => {
                    let array_size = &array_type.size;
                    match array_size.value.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(_) => (),
                        _ => {
                            runtime_size_entries.push(j);
                            continue;
                        }
                    };

                    let element_type = array_type.resolved_element_type.as_ref().unwrap();
                    if !self.structure_member_plain_type_size_is_compiletime_const(element_type) {
                        runtime_size_entries.push(j);
                        continue;
                    }

                    let enable_conditional = if array_type.element_type_enable_conditional {
                        true
                    } else if array_type.element_type_conditional {
                        conditional
                    } else {
                        false
                    };

                    writeln!(out)?;
                    let mut iout = if !deps.is_unconditional_true() {
                        writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(out, "{{")?;
                        out.make_indent()
                    } else {
                        out.make_same_indent()
                    };
                    self.gen_structure_member_array_size(
                        &mut iout,
                        &table.name,
                        Some(acc_dst_name),
                        &Self::format_structure_member_name(&entry.name),
                        None,
                        element_type,
                        array_size,
                        enable_conditional,
                        handle_err,
                    )?;
                    if !deps.is_unconditional_true() {
                        writeln!(out, "}}")?;
                    }
                }
            };
        }

        for j in runtime_size_entries.iter() {
            let entry = &table.entries[*j];
            let deps = &entry.deps;
            let deps = deps.factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(size_deps);
            writeln!(out)?;
            let mut iout = if !deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                writeln!(out, "{{")?;
                out.make_indent()
            } else {
                out.make_same_indent()
            };
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();

                    let enable_conditional = if plain_type.base_type_enable_conditional {
                        true
                    } else if plain_type.base_type_conditional {
                        conditional
                    } else {
                        false
                    };

                    let member_name = Self::format_structure_member_name(&entry.name);
                    self.gen_structure_member_plain_type_size(
                        &mut iout,
                        Some(acc_dst_name),
                        &member_name,
                        ("self.".to_owned() + &member_name).as_str(),
                        base_type,
                        enable_conditional,
                        handle_err,
                    )?;
                }
                StructureTableEntryType::Discriminant(_) => {
                    unreachable!();
                }
                StructureTableEntryType::Union(union_type) => {
                    assert!(deps.is_unconditional_true());
                    let entry = union_type.resolved_discriminant.unwrap();
                    let entry = &table.entries[entry];
                    let discriminant =
                        Self::to_structure_discriminant_entry_type(&entry.entry_type);
                    assert_eq!(*j, discriminant.discriminated_union_members[0]);

                    let enable_conditional = if discriminant.discriminant_type_enable_conditional {
                        true
                    } else if discriminant.discriminant_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    let need_limits = self.tagged_union_size_needs_limits(
                        table,
                        discriminant,
                        enable_conditional,
                    );

                    let limits_spec = if need_limits { "limits" } else { "" };

                    let (member_name, member_spec) = if is_tagged_union {
                        (borrow::Cow::Borrowed(""), borrow::Cow::Borrowed(""))
                    } else {
                        let member_name = Self::format_structure_member_name(&entry.name);
                        let member_spec = member_name.clone().into_owned() + ".";
                        let member_name = member_name.into_owned() + "_";
                        (
                            borrow::Cow::Owned(member_name),
                            borrow::Cow::Owned(member_spec),
                        )
                    };

                    writeln!(
                        &mut iout,
                        "let {}data_size = match self.{}marshalled_data_size({}) {{",
                        &member_name, &member_spec, limits_spec
                    )?;
                    let mut iiout = iout.make_indent();
                    writeln!(
                        &mut iiout,
                        "Ok({}data_size) => {}data_size,",
                        &member_name, &member_name
                    )?;
                    writeln!(&mut iiout, "Err(_) => {{")?;
                    handle_err(&mut iiout.make_indent())?;
                    writeln!(&mut iiout, "}},")?;
                    writeln!(&mut iout, "}};")?;

                    writeln!(
                        &mut iout,
                        "{} = match {}.checked_add({}data_size) {{",
                        acc_dst_name, acc_dst_name, &member_name
                    )?;
                    let mut iiout = iout.make_indent();
                    writeln!(&mut iiout, "Some({}) => {},", acc_dst_name, acc_dst_name)?;
                    writeln!(&mut iiout, "None => {{")?;
                    handle_err(&mut iiout.make_indent())?;
                    writeln!(&mut iiout, "}},")?;
                    writeln!(&mut iout, "}};")?;
                }
                StructureTableEntryType::Array(array_type) => {
                    let array_size = &array_type.size;
                    let element_type = array_type.resolved_element_type.as_ref().unwrap();

                    let enable_conditional = if array_type.element_type_enable_conditional {
                        true
                    } else if array_type.element_type_conditional {
                        conditional
                    } else {
                        false
                    };

                    let member_name = Self::format_structure_member_name(&entry.name);
                    self.gen_structure_member_array_size(
                        &mut iout,
                        &table.name,
                        Some(acc_dst_name),
                        &member_name,
                        Some(("self.".to_owned() + &member_name).as_str()),
                        element_type,
                        array_size,
                        enable_conditional,
                        handle_err,
                    )?;
                }
            };

            if !deps.is_unconditional_true() {
                writeln!(out, "}}")?;
            }
        }

        Ok(())
    }

    pub(super) fn gen_structure_marshalled_size<W: io::Write>(
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

        let (size_is_fixed, _) = Self::structure_has_fixed_size(table);
        if size_is_fixed {
            // The marshalled_max_size() does serve as a marshalled_size() (and
            // would be named accordingly), because the structure's marshalled
            // size is fixed and independent of the contents. It might have been
            // emitted in the context of handling the ANY_MAX_SIZE closure
            // dependencies already.
            if table_closure_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE) {
                return Ok(());
            } else {
                return self.gen_structure_marshalled_max_size(out, table, conditional);
            }
        }

        let mut size_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_SIZE);
        size_deps.factor_by_common_of(&table_deps);
        if !size_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&size_deps))?;
        }
        let pub_spec = if table_closure_deps.any(ClosureDepsFlags::EXTERN_SIZE) {
            "pub "
        } else {
            ""
        };

        let need_limits = Self::structure_marshalled_size_needs_limits(table);
        if need_limits {
            writeln!(
                out,
                "{}fn marshalled_size(&self, limits: &TpmLimits) -> Result<usize, ()> {{",
                pub_spec
            )?;
        } else {
            writeln!(
                out,
                "{}fn marshalled_size(&self) -> Result<usize, ()> {{",
                pub_spec
            )?;
        }

        let mut iout = out.make_indent();
        writeln!(&mut iout, "let mut size: usize = 0;")?;
        self.gen_structure_members_marshalled_size(
            &mut iout,
            "size",
            table,
            false,
            0,
            &table_deps,
            &size_deps,
            conditional,
            &|out| writeln!(out, "return Err(());"),
        )?;
        writeln!(&mut iout)?;
        writeln!(&mut iout, "Ok(size)")?;
        writeln!(out, "}}")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn gen_tagged_union_marshalled_size<W: io::Write>(
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

        let mut size_deps = closure_deps.collect_config_deps(ClosureDepsFlags::ANY_SIZE);
        size_deps.factor_by_common_of(table_deps);

        // The discriminant might be separated from the sequence of union
        // members in the containing structure. Provide separate internal
        // primitives for determining the discriminant's and selected data's
        // sizes separately each. This enables the marshalling code to calculate
        // <size>= specifier members inbetween the discriminant and the union
        // members, if any.
        if !size_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&size_deps))?;
        }
        let base_type = StructureTableEntryResolvedBaseType::from(*discriminant_type);
        let discriminant_size = self.format_structure_member_plain_type_compiletime_fixed_size(
            &base_type,
            discriminant_enable_conditional,
        );
        writeln!(
            out,
            "const fn marshalled_selector_size() -> {} {{",
            Self::predefined_type_to_rust(discriminant_size.1.unwrap())
        )?;
        writeln!(&mut out.make_indent(), "{}", discriminant_size.0)?;
        writeln!(out, "}}")?;
        writeln!(out)?;

        let need_limits = self.tagged_union_size_needs_limits(table, discriminant, conditional);
        let limits_arg = if need_limits {
            ", limits: &TpmLimits"
        } else {
            ""
        };

        if !size_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&size_deps))?;
        }
        writeln!(
            out,
            "fn marshalled_data_size(&self{}) -> Result<usize, ()> {{",
            limits_arg
        )?;
        let mut iout = out.make_indent();
        writeln!(&mut iout, "let mut size: usize = 0;")?;
        writeln!(&mut iout, "match self {{")?;
        let mut iiout = iout.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant_type,
            discriminant_enable_conditional,
        ) {
            let deps = selector.config_deps().factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(&size_deps);
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
                    // In case the selected union member's type has a fixed
                    // size, the match specifier will not be needed for the size
                    // calculation. Mark it as such then, otherwise Rust will
                    // emit warnings.
                    let match_is_unused = match &selected_member.entry_type {
                        UnionTableEntryType::Plain(plain_type) => {
                            let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                            self.structure_member_plain_type_has_fixed_size(base_type).0
                        }
                        UnionTableEntryType::Array(array_type) => {
                            match array_type.size.value.as_ref().unwrap() {
                                ExprValue::CompiletimeConstant(_)
                                | ExprValue::RuntimeConstant(_) => (),
                                ExprValue::Dynamic
                                | ExprValue::DynamicWithRuntimeConstantDep(_) => unreachable!(),
                            };
                            let element_type = array_type.resolved_element_type.as_ref().unwrap();
                            self.structure_member_plain_type_has_fixed_size(element_type)
                                .0
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
                if !first {
                    writeln!(&mut iiiout)?;
                }
                first = false;

                let union_entry_name = Self::format_structure_member_name(&table.entries[*u].name);
                let union_table = self.tables.structures.get_union(*union_table_index);
                let selected_member = &union_table.entries[*selected_member_index];
                match &selected_member.entry_type {
                    UnionTableEntryType::Plain(plain_type) => {
                        let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                        self.gen_structure_member_plain_type_size(
                            &mut iiiout,
                            Some("size"),
                            &union_entry_name,
                            &union_entry_name,
                            base_type,
                            plain_type.base_type_enable_conditional,
                            &|out| writeln!(out, "return Err(());"),
                        )?;
                    }
                    UnionTableEntryType::Array(array_type) => {
                        let element_type = array_type.resolved_element_type.as_ref().unwrap();
                        self.gen_structure_member_array_size(
                            &mut iiiout,
                            &union_table.name,
                            Some("size"),
                            &union_entry_name,
                            Some(&union_entry_name),
                            element_type,
                            &array_type.size,
                            array_type.element_type_enable_conditional,
                            &|out| writeln!(out, "return Err(());"),
                        )?;
                    }
                };
            }

            writeln!(&mut iiout, "}},")?;
        }

        writeln!(&mut iout, "}};")?;

        writeln!(&mut iout)?;
        writeln!(&mut iout, "Ok(size)")?;
        writeln!(out, "}}")?;
        writeln!(out)?;

        // If the tagged union corresponds to a full structure from the
        // interface specification (as opposed to serving only as some structure
        // member's representation), then provide as marshalled_size() for the
        // structure as a whole.
        if !is_structure_member_repr {
            let pub_spec = if closure_deps.any(ClosureDepsFlags::EXTERN_SIZE) {
                "pub "
            } else {
                ""
            };

            let limits_arg = if need_limits {
                ", limits: &TpmLimits"
            } else {
                ""
            };

            if !size_deps.is_implied_by(table_deps) {
                writeln!(out, "#[cfg({})]", Self::format_deps(&size_deps))?;
            }
            writeln!(
                out,
                "{}fn marshalled_size(&self{}) -> Result<usize, ()> {{",
                pub_spec, limits_arg
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "let mut size: usize = 0;")?;
            self.gen_structure_members_marshalled_size(
                &mut iout,
                "size",
                table,
                true,
                0,
                table_deps,
                &size_deps,
                conditional,
                &|out| writeln!(out, "return Err(());"),
            )?;
            writeln!(&mut iout)?;
            writeln!(&mut iout, "Ok(size)")?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }
}
