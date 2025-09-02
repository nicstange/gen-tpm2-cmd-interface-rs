// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;
use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use crate::tcg_tpm2::structures::structure_table::StructureTableEntryResolvedDiscriminantType;
use crate::tcg_tpm2::structures::table_common::ClosureDeps;
use crate::tcg_tpm2::structures::union_table::UnionTableEntryType;
use structures::expr::{Expr, ExprValue};
use structures::predefined::{PredefinedTypeRef, PredefinedTypes};
use structures::structure_table::{
    StructureTable, StructureTableEntryDiscriminantType, StructureTableEntryResolvedBaseType,
    StructureTableEntryType,
};
use structures::table_common::ClosureDepsFlags;
use structures::tables::{
    StructuresPartTablesConstantIndex, UnionSelectorIterator, UnionSelectorIteratorValue,
};
use structures::union_table::UnionTable;
use structures::value_range::ValueRange;

use super::super::{Tpm2InterfaceRustCodeGenerator, code_writer};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    fn expr_needs_limits(e: &Expr) -> bool {
        matches!(
            e.value.as_ref().unwrap(),
            ExprValue::RuntimeConstant(_) | ExprValue::DynamicWithRuntimeConstantDep(_)
        )
    }

    fn value_range_needs_limits(range: &ValueRange) -> bool {
        match range {
            ValueRange::Discrete(values) => {
                for value in values.iter() {
                    if Self::expr_needs_limits(value) {
                        return true;
                    }
                }
                false
            }
            ValueRange::Range {
                min_value,
                max_value,
            } => {
                if let Some(value) = min_value {
                    if Self::expr_needs_limits(value) {
                        return true;
                    }
                }
                if let Some(value) = max_value {
                    if Self::expr_needs_limits(value) {
                        return true;
                    }
                }
                false
            }
        }
    }

    fn structure_plain_member_unmarshal_needs_limits(
        &self,
        resolved_plain_type: &StructureTableEntryResolvedBaseType,
    ) -> bool {
        match resolved_plain_type {
            StructureTableEntryResolvedBaseType::Predefined(_) => false,
            StructureTableEntryResolvedBaseType::Constants(i) => {
                let table = self.tables.structures.get_constants(*i);
                !Self::constants_are_compiletime_const(&table)
            }
            StructureTableEntryResolvedBaseType::Bits(_) => false,
            StructureTableEntryResolvedBaseType::Type(i) => {
                let table = self.tables.structures.get_type(*i);
                !Self::type_values_are_compiletime_const(&table)
            }
            StructureTableEntryResolvedBaseType::Structure(i) => {
                self.structure_unmarshal_needs_limits(&self.tables.structures.get_structure(*i))
            }
        }
    }

    fn union_member_unmarshal_needs_limits(&self, entry_type: &UnionTableEntryType) -> bool {
        match entry_type {
            UnionTableEntryType::Plain(plain_type) => {
                if let Some(plain_type) = plain_type.resolved_base_type.as_ref() {
                    self.structure_plain_member_unmarshal_needs_limits(plain_type)
                } else {
                    false
                }
            }
            UnionTableEntryType::Array(array_type) => {
                if Self::expr_needs_limits(&array_type.size) {
                    return true;
                }
                let element_type = array_type.resolved_element_type.as_ref().unwrap();
                self.structure_plain_member_unmarshal_needs_limits(element_type)
            }
        }
    }

    fn union_unmarshal_needs_limits(
        &self,
        discriminant_type: &StructureTableEntryResolvedDiscriminantType,
        union_table: &UnionTable,
    ) -> bool {
        for selector in
            UnionSelectorIterator::new(&self.tables.structures, *discriminant_type, true)
        {
            let entry = union_table.lookup_member(selector.name()).unwrap();
            let entry = &union_table.entries[entry];
            if self.union_member_unmarshal_needs_limits(&entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn structure_member_unmarshal_needs_limits(
        &self,
        table: &StructureTable,
        entry_type: &StructureTableEntryType,
    ) -> bool {
        match entry_type {
            StructureTableEntryType::Plain(plain_type) => {
                if let Some(range) = &plain_type.range {
                    if Self::value_range_needs_limits(range) {
                        return true;
                    }
                }
                self.structure_plain_member_unmarshal_needs_limits(
                    plain_type.resolved_base_type.as_ref().unwrap(),
                )
            }
            StructureTableEntryType::Discriminant(discriminant_type) => {
                let discriminant_type = discriminant_type
                    .resolved_discriminant_type
                    .as_ref()
                    .unwrap();
                let discriminant_type =
                    StructureTableEntryResolvedBaseType::from(*discriminant_type);
                self.structure_plain_member_unmarshal_needs_limits(&discriminant_type)
            }
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
                self.union_unmarshal_needs_limits(discriminant_type, &union_table)
            }
            StructureTableEntryType::Array(array_type) => {
                if Self::expr_needs_limits(&array_type.size) {
                    return true;
                }
                if let Some(range) = &array_type.size_range {
                    if Self::value_range_needs_limits(range) {
                        return true;
                    }
                }
                let element_type = array_type.resolved_element_type.as_ref().unwrap();
                self.structure_plain_member_unmarshal_needs_limits(element_type)
            }
        }
    }

    pub(in super::super) fn structure_unmarshal_needs_limits(
        &self,
        table: &StructureTable,
    ) -> bool {
        for entry in table.entries.iter() {
            if self.structure_member_unmarshal_needs_limits(table, &entry.entry_type) {
                return true;
            }
        }
        false
    }

    fn tagged_union_unmarshal_needs_limits(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
    ) -> bool {
        for k in discriminant.discriminated_union_members.iter() {
            let union_member_entry = &table.entries[*k];
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            if self.union_unmarshal_needs_limits(
                discriminant.resolved_discriminant_type.as_ref().unwrap(),
                &union_table,
            ) {
                return true;
            }
        }
        false
    }

    fn structure_plain_member_needs_drop(
        &self,
        resolved_plain_type: &StructureTableEntryResolvedBaseType,
    ) -> bool {
        self.structure_plain_member_contains_array(resolved_plain_type)
    }

    fn union_member_needs_drop(&self, entry_type: &UnionTableEntryType) -> bool {
        self.union_member_contains_array(entry_type)
    }

    fn structure_member_needs_drop(
        &self,
        table: &StructureTable,
        entry_type: &StructureTableEntryType,
    ) -> bool {
        self.structure_member_contains_array(table, entry_type)
    }

    fn tagged_union_needs_drop(
        &self,
        table: &StructureTable,
        discriminant: &StructureTableEntryDiscriminantType,
    ) -> bool {
        self.tagged_union_contains_array(table, discriminant)
    }

    fn tagged_union_member_needs_drop(
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
            if self.union_member_needs_drop(&union_entry.entry_type) {
                return true;
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_structure_member_plain_type_unmarshal<W: io::Write, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        outbuf_name: &str,
        inbuf_name: &str,
        dst_spec: Option<&str>,
        member_name: &str,
        plain_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        err_cleanup: &EC,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error>
    where
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        let need_limits = self.structure_plain_member_unmarshal_needs_limits(plain_type);
        match plain_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => {
                writeln!(
                    out,
                    "let ({}, unmarshalled_{}) = match unmarshal_{}({}) {{",
                    outbuf_name,
                    &member_name,
                    Self::predefined_type_to_rust(*p),
                    inbuf_name
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Ok(r) => r,")?;
                writeln!(&mut iout, "Err(e) => {{")?;
                let mut iiout = iout.make_indent();
                err_cleanup(&mut iiout)?;
                writeln!(&mut iiout, "return Err(e);")?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;
            }
            StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_) => {
                let type_spec = self.format_structure_member_plain_type(
                    plain_type,
                    conditional,
                    true,
                    enable_allocator_api,
                );
                let limits_arg = if need_limits { ", limits" } else { "" };
                writeln!(
                    out,
                    "let ({}, unmarshalled_{}) = match {}::unmarshal({}{}) {{",
                    outbuf_name, &member_name, type_spec, inbuf_name, limits_arg
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Ok(r) => r,")?;
                writeln!(&mut iout, "Err(e) => {{")?;
                let mut iiout = iout.make_indent();
                err_cleanup(&mut iiout)?;
                writeln!(&mut iiout, "return Err(e);")?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;

                if let Some(dst_spec) = dst_spec {
                    writeln!(
                        out,
                        "unsafe{{{}.write(unmarshalled_{})}};",
                        dst_spec, &member_name
                    )?;
                }
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let type_spec = self.format_structure_member_plain_type(
                    plain_type,
                    conditional,
                    true,
                    enable_allocator_api,
                );
                let limits_arg = if need_limits { ", limits" } else { "" };

                let table = self.tables.structures.get_structure(*index);
                let decrypted_head_buf_arg = if self.structure_is_cryptable(&table) {
                    "None, "
                } else {
                    ""
                };

                let allocator_arg =
                    if self.structure_contains_nonbyte_array(&table) && enable_allocator_api {
                        ", alloc"
                    } else {
                        ""
                    };

                if let Some(dst_spec) = dst_spec {
                    writeln!(
                        out,
                        "let {} = match {}::unmarshal_intern({}, {}{}{}{}) {{",
                        outbuf_name,
                        type_spec,
                        dst_spec,
                        decrypted_head_buf_arg,
                        inbuf_name,
                        limits_arg,
                        allocator_arg,
                    )?;
                } else {
                    writeln!(
                        out,
                        "let ({}, unmarshalled_{}) = match {}::unmarshal_intern({}{}{}{}) {{",
                        outbuf_name,
                        &member_name,
                        type_spec,
                        decrypted_head_buf_arg,
                        inbuf_name,
                        limits_arg,
                        allocator_arg,
                    )?;
                }
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Ok(r) => r,")?;
                writeln!(&mut iout, "Err(e) => {{")?;
                let mut iiout = iout.make_indent();
                err_cleanup(&mut iiout)?;
                writeln!(&mut iiout, "return Err(e);")?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;
            }
        };
        Ok(())
    }

    fn format_structure_member_cmp_cast(e: String, t: PredefinedTypeRef, p: bool) -> String {
        if p {
            e + " as " + Self::predefined_type_to_rust(t)
        } else {
            "(".to_owned() + &e + ") as " + Self::predefined_type_to_rust(t)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn format_structure_member_cmp<W: io::Write, FI, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        j: usize,
        c: &str,
        e: &Expr,
        format_local_id_ref: &FI,
        err_cleanup: &EC,
    ) -> Result<String, io::Error>
    where
        FI: Fn(usize, Option<PredefinedTypeRef>) -> Result<(String, PredefinedTypeRef, bool), ()>,
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        let (mut m, mt, mp) = format_local_id_ref(j, None).unwrap();
        let (mut e, et, ep) = self.format_expr(
            out,
            e,
            Some(mt),
            "limits",
            None,
            &|_, _| unreachable!(),
            &|out| -> Result<(), io::Error> {
                err_cleanup(out)?;
                writeln!(out, "return Err(TpmErr::InternalErr);")?;
                Ok(())
            },
        )?;
        let t = PredefinedTypes::find_common_type(mt, et).ok_or_else(|| {
            eprintln!(
                "error: {}: integer overflow in {} comparison",
                table_name, entry_name
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        if t != mt {
            m = Self::format_structure_member_cmp_cast(m, t, mp);
        }
        if t != et {
            e = Self::format_structure_member_cmp_cast(e, t, ep);
        }
        Ok(format!("{} {} {}", m, c, e))
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_structure_member_value_range_validation_discrete<W: io::Write, FI, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        j: usize,
        values: &[Expr],
        error_rc: StructuresPartTablesConstantIndex,
        format_local_id_ref: &FI,
        err_cleanup: &EC,
    ) -> Result<(), io::Error>
    where
        FI: Fn(usize, Option<PredefinedTypeRef>) -> Result<(String, PredefinedTypeRef, bool), ()>,
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        if values.is_empty() {
            err_cleanup(out)?;
            self.format_error_return(out, None, error_rc)?;
        } else {
            let c = self.format_structure_member_cmp(
                out,
                table_name,
                entry_name,
                j,
                "!=",
                &values[0],
                format_local_id_ref,
                err_cleanup,
            )?;
            writeln!(out, "if {} {{", c)?;
            let mut iout = out.make_indent();
            self.gen_structure_member_value_range_validation_discrete(
                &mut iout,
                table_name,
                entry_name,
                j,
                &values[1..],
                error_rc,
                format_local_id_ref,
                err_cleanup,
            )?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_member_value_range_validation<W: io::Write, FI, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        j: usize,
        range: &ValueRange,
        error_rc: StructuresPartTablesConstantIndex,
        format_local_id_ref: &FI,
        err_cleanup: &EC,
    ) -> Result<(), io::Error>
    where
        FI: Fn(usize, Option<PredefinedTypeRef>) -> Result<(String, PredefinedTypeRef, bool), ()>,
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        match range {
            ValueRange::Discrete(values) => self
                .gen_structure_member_value_range_validation_discrete(
                    out,
                    table_name,
                    entry_name,
                    j,
                    values.as_slice(),
                    error_rc,
                    format_local_id_ref,
                    err_cleanup,
                ),
            ValueRange::Range {
                min_value,
                max_value,
            } => {
                if let Some(min_value) = min_value {
                    let c = self.format_structure_member_cmp(
                        out,
                        table_name,
                        entry_name,
                        j,
                        "<",
                        min_value,
                        format_local_id_ref,
                        err_cleanup,
                    )?;
                    writeln!(out, "if {} {{", c)?;
                    let mut iout = out.make_indent();
                    err_cleanup(&mut iout)?;
                    self.format_error_return(&mut iout, None, error_rc)?;
                    writeln!(out, "}}")?;
                }
                if let Some(max_value) = max_value {
                    let c = self.format_structure_member_cmp(
                        out,
                        table_name,
                        entry_name,
                        j,
                        ">",
                        max_value,
                        format_local_id_ref,
                        err_cleanup,
                    )?;
                    writeln!(out, "if {} {{", c)?;
                    let mut iout = out.make_indent();
                    err_cleanup(&mut iout)?;
                    self.format_error_return(&mut iout, None, error_rc)?;
                    writeln!(out, "}}")?;
                }
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn format_array_len_cmp<W: io::Write, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        array_len_name: &str,
        array_len_type: PredefinedTypeRef,
        c: &str,
        e: &Expr,
        err_cleanup: &EC,
    ) -> Result<String, io::Error>
    where
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        let (mut e, et, ep) = self.format_expr(
            out,
            e,
            Some(array_len_type),
            "limits",
            None,
            &|_, _| unreachable!(),
            &|out| -> Result<(), io::Error> {
                err_cleanup(out)?;
                writeln!(out, "return Err(TpmErr::InternalErr);")?;
                Ok(())
            },
        )?;
        let t = PredefinedTypes::find_common_type(array_len_type, et).ok_or_else(|| {
            eprintln!(
                "error: {}: integer overflow in {} array length comparison",
                table_name, entry_name
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

        let array_len = if t != array_len_type {
            borrow::Cow::Owned(Self::format_structure_member_cmp_cast(
                array_len_name.to_owned(),
                t,
                true,
            ))
        } else {
            borrow::Cow::Borrowed(array_len_name)
        };
        if t != et {
            e = Self::format_structure_member_cmp_cast(e, t, ep);
        }
        Ok(format!("{} {} {}", array_len, c, e))
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_array_len_range_validation_discrete<W: io::Write, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        array_len_name: &str,
        array_len_type: PredefinedTypeRef,
        values: &[Expr],
        error_rc: StructuresPartTablesConstantIndex,
        err_cleanup: &EC,
    ) -> Result<(), io::Error>
    where
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        if values.is_empty() {
            err_cleanup(out)?;
            self.format_error_return(out, None, error_rc)?;
        } else {
            let c = self.format_array_len_cmp(
                out,
                table_name,
                entry_name,
                array_len_name,
                array_len_type,
                "!=",
                &values[0],
                err_cleanup,
            )?;
            writeln!(out, "if {} {{", c)?;
            let mut iout = out.make_indent();
            self.gen_array_len_range_validation_discrete(
                &mut iout,
                table_name,
                entry_name,
                array_len_name,
                array_len_type,
                &values[1..],
                error_rc,
                err_cleanup,
            )?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_array_len_range_validation<W: io::Write, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        array_len_name: &str,
        array_len_type: PredefinedTypeRef,
        range: &ValueRange,
        error_rc: StructuresPartTablesConstantIndex,
        err_cleanup: &EC,
    ) -> Result<(), io::Error>
    where
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        match range {
            ValueRange::Discrete(values) => self.gen_array_len_range_validation_discrete(
                out,
                table_name,
                entry_name,
                array_len_name,
                array_len_type,
                values.as_slice(),
                error_rc,
                err_cleanup,
            ),
            ValueRange::Range {
                min_value,
                max_value,
            } => {
                if let Some(min_value) = min_value {
                    let c = self.format_array_len_cmp(
                        out,
                        table_name,
                        entry_name,
                        array_len_name,
                        array_len_type,
                        "<",
                        min_value,
                        err_cleanup,
                    )?;
                    writeln!(out, "if {} {{", c)?;
                    let mut iout = out.make_indent();
                    err_cleanup(&mut iout)?;
                    self.format_error_return(&mut iout, None, error_rc)?;
                    writeln!(out, "}}")?;
                }
                if let Some(max_value) = max_value {
                    let c = self.format_array_len_cmp(
                        out,
                        table_name,
                        entry_name,
                        array_len_name,
                        array_len_type,
                        ">",
                        max_value,
                        err_cleanup,
                    )?;
                    writeln!(out, "if {} {{", c)?;
                    let mut iout = out.make_indent();
                    err_cleanup(&mut iout)?;
                    self.format_error_return(&mut iout, None, error_rc)?;
                    writeln!(out, "}}")?;
                }
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_structure_member_array_unmarshal<W: io::Write, FI, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table_name: &str,
        entry_name: &str,
        outbuf_name: &str,
        inbuf_name: &str,
        dst_spec: Option<&str>,
        member_name: &str,
        element_type: &StructureTableEntryResolvedBaseType,
        conditional: bool,
        array_size: &Expr,
        array_size_range: Option<&ValueRange>,
        error_rc_size: StructuresPartTablesConstantIndex,
        format_expr_local_id_ref: &FI,
        err_cleanup: &EC,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error>
    where
        FI: Fn(usize, Option<PredefinedTypeRef>) -> Result<(String, PredefinedTypeRef, bool), ()>,
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        let error_rc_insufficient = self
            .tables
            .structures
            .lookup_constant("TPM_RC_INSUFFICIENT")
            .unwrap();
        let error_rc_memory = self
            .tables
            .structures
            .lookup_constant("TPM_RC_MEMORY")
            .unwrap();

        let is_byte_array = match element_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => p.bits == 8 && !p.signed,
            StructureTableEntryResolvedBaseType::Constants(_)
            | StructureTableEntryResolvedBaseType::Bits(_)
            | StructureTableEntryResolvedBaseType::Type(_)
            | StructureTableEntryResolvedBaseType::Structure(_) => false,
        };

        let len_spec = if is_byte_array { "size" } else { "len" };

        let (array_len, array_len_type, _) = self
            .format_expr(
                out,
                array_size,
                None,
                "limits",
                None,
                format_expr_local_id_ref,
                &|out| {
                    err_cleanup(out)?;
                    writeln!(out, "return Err(TpmErr::InternalErr);")?;
                    Ok(())
                },
            )
            .map_err(|_| {
                eprintln!(
                    "error: {}: integer overflow in {} array's size",
                    table_name, entry_name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        writeln!(
            out,
            "let {}_{}: {} = {};",
            member_name,
            len_spec,
            Self::predefined_type_to_rust(array_len_type),
            array_len
        )?;

        if let Some(array_size_range) = array_size_range {
            self.gen_array_len_range_validation(
                out,
                table_name,
                entry_name,
                &format!("{}_{}", member_name, len_spec),
                array_len_type,
                array_size_range,
                error_rc_size,
                err_cleanup,
            )?;
        }
        writeln!(
            out,
            "let {}_{} = match usize::try_from({}_{}) {{",
            member_name, len_spec, member_name, len_spec
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "Ok({}_{}) => {}_{},",
            member_name, len_spec, member_name, len_spec
        )?;
        writeln!(&mut iout, "Err(_) => {{")?;
        let mut iiout = iout.make_indent();
        err_cleanup(&mut iiout)?;
        self.format_error_return(&mut iiout, None, error_rc_insufficient)?;
        writeln!(&mut iout, "}},")?;
        writeln!(out, "}};")?;

        if is_byte_array {
            writeln!(
                out,
                "let (unmarshalled_{}, {}) = match split_slice_at({}, {}_size) {{",
                member_name, outbuf_name, inbuf_name, member_name,
            )?;
            let mut iout = out.make_indent();
            writeln!(
                &mut iout,
                "Ok((unmarshalled_{}, {})) => (unmarshalled_{}, {}),",
                member_name, outbuf_name, member_name, outbuf_name,
            )?;
            writeln!(&mut iout, "Err(e) => {{",)?;
            let mut iiout = iout.make_indent();
            err_cleanup(&mut iiout)?;
            writeln!(&mut iiout, "return Err(e);")?;
            writeln!(&mut iout, "}},",)?;
            writeln!(out, "}};")?;

            writeln!(
                out,
                "let unmarshalled_{} = TpmBuffer::from(unmarshalled_{});",
                member_name, member_name
            )?;
            if let Some(dst_spec) = dst_spec {
                writeln!(
                    out,
                    "unsafe{{{}.write(unmarshalled_{}.into())}};",
                    dst_spec, member_name
                )?;
            }
        } else {
            let type_spec = self.format_structure_member_plain_type(
                element_type,
                conditional,
                false,
                enable_allocator_api,
            );
            let elements_need_drop = self.structure_plain_member_needs_drop(element_type);
            writeln!(
                out,
                "let mut unmarshalled_{}: Vec<{}{}> = Vec::{};",
                member_name,
                type_spec,
                enable_allocator_api.then_some(", A").unwrap_or(""),
                enable_allocator_api
                    .then_some("new_in(alloc.clone()")
                    .unwrap_or("new()")
            )?;
            writeln!(
                out,
                "if unmarshalled_{}.try_reserve_exact({}_len).is_err() {{",
                member_name, member_name
            )?;
            let mut iout = out.make_indent();
            err_cleanup(&mut iout)?;
            self.format_error_return(&mut iout, None, error_rc_memory)?;
            writeln!(out, "}}")?;

            if let Some(dst_spec) = dst_spec {
                writeln!(
                    out,
                    "let unmarshalled_{}_uninit = unmarshalled_{}.spare_capacity_mut();",
                    member_name, member_name
                )?;
                writeln!(out, "let mut {} = {};", outbuf_name, inbuf_name)?;
                writeln!(out, "for i in 0..{}_len {{", member_name)?;
                let mut iout = out.make_indent();
                writeln!(
                    &mut iout,
                    "let element_uninit = unmarshalled_{}_uninit[i].as_mut_ptr();",
                    member_name
                )?;
                self.gen_structure_member_plain_type_unmarshal(
                    &mut iout,
                    "remaining",
                    outbuf_name,
                    Some("element_uninit"),
                    "element",
                    element_type,
                    conditional,
                    &|out| {
                        if elements_need_drop {
                            writeln!(out, "for j in 0..i {{")?;
                            let mut iout = out.make_indent();
                            writeln!(
                                &mut iout,
                                "let element_uninit = unmarshalled_{}_uninit[j].as_mut_ptr();",
                                member_name
                            )?;
                            writeln!(&mut iout, "unsafe{{element_uninit.drop_in_place()}};")?;
                            writeln!(out, "}}")?
                        }
                        err_cleanup(out)?;
                        Ok(())
                    },
                    enable_allocator_api,
                )?;
                writeln!(&mut iout, "{} = remaining;", outbuf_name)?;
                writeln!(out, "}}")?;
                writeln!(
                    out,
                    "unsafe{{unmarshalled_{}.set_len({}_len)}};",
                    member_name, member_name
                )?;
                writeln!(
                    out,
                    "unsafe{{{}.write(unmarshalled_{})}};",
                    dst_spec, member_name
                )?;
            } else {
                writeln!(out, "let mut {} = {};", outbuf_name, inbuf_name)?;
                writeln!(out, "for _i in 0..{}_len {{", member_name)?;
                let mut iout = out.make_indent();
                self.gen_structure_member_plain_type_unmarshal(
                    &mut iout,
                    "remaining",
                    outbuf_name,
                    None,
                    "element",
                    element_type,
                    conditional,
                    &|out| {
                        err_cleanup(out)?;
                        Ok(())
                    },
                    enable_allocator_api,
                )?;
                writeln!(
                    &mut iout,
                    "unmarshalled_{}.push(unmarshalled_element);",
                    member_name
                )?;
                writeln!(&mut iout, "{} = remaining;", outbuf_name)?;
                writeln!(out, "}}")?;
            }
        }
        Ok(())
    }

    fn format_structure_member_expr_id_ref(
        &self,
        table: &StructureTable,
        j: usize,
        _target_type_hint: Option<PredefinedTypeRef>,
    ) -> Result<(String, PredefinedTypeRef, bool), ()> {
        let entry = &table.entries[j];
        let member_name = Self::format_structure_member_name(&entry.name);
        match &entry.entry_type {
            StructureTableEntryType::Plain(plain_type) => {
                let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                match base_type {
                    StructureTableEntryResolvedBaseType::Predefined(p) => {
                        let id_ref = format!("unmarshalled_{}", member_name);
                        Ok((id_ref, *p, false))
                    }
                    StructureTableEntryResolvedBaseType::Constants(index) => {
                        let table = self.tables.structures.get_constants(*index);
                        let base_type = table.resolved_base.as_ref().unwrap();
                        if table.enum_like {
                            let id_ref = format!(
                                "unmarshalled_{} as {}",
                                member_name,
                                Self::predefined_type_to_rust(*base_type)
                            );
                            Ok((id_ref, *base_type, false))
                        } else {
                            let id_ref = format!("unmarshalled_{}.value", member_name);
                            Ok((id_ref, *base_type, false))
                        }
                    }
                    StructureTableEntryResolvedBaseType::Type(index) => {
                        let table = self.tables.structures.get_type(*index);
                        let base_type = table.underlying_type.as_ref().unwrap();
                        if table.enum_like {
                            let id_ref = format!(
                                "unmarshalled_{} as {}",
                                member_name,
                                Self::predefined_type_to_rust(*base_type)
                            );
                            Ok((id_ref, *base_type, false))
                        } else {
                            let id_ref = format!("unmarshalled_{}.value", member_name);
                            Ok((id_ref, *base_type, false))
                        }
                    }
                    StructureTableEntryResolvedBaseType::Bits(_) => unreachable!(),
                    StructureTableEntryResolvedBaseType::Structure(_) => unreachable!(),
                }
            }
            StructureTableEntryType::Discriminant(discriminant) => {
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
                let id_ref = format!("unmarshalled_{}", member_name);
                Ok((id_ref, discriminant_base, false))
            }
            StructureTableEntryType::Array(_) => unreachable!(),
            StructureTableEntryType::Union(_) => unreachable!(),
        }
    }

    fn gen_structure_size_spec_checks<W: io::Write, EC>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        table_deps: &ConfigDepsDisjunction,
        unmarshal_deps: &ConfigDepsDisjunction,
        error_rc_size: StructuresPartTablesConstantIndex,
        err_cleanup: &EC,
    ) -> Result<(), io::Error>
    where
        EC: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        // Finally, i.e. after a strucuture's contents have been unmarshalled,
        // sweep through all <size>= members and verify the respective amount of
        // specified buffer space has been consumed.
        for entry in &table.entries {
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    if !plain_type.is_size_specifier {
                        continue;
                    }

                    writeln!(out)?;
                    let deps = &entry.deps;
                    let deps = deps.factor_by_common_of(table_deps);
                    let deps = deps.factor_by_common_of(unmarshal_deps);
                    let mut iout = if !deps.is_unconditional_true() {
                        // Unions are always of variable length, so there's
                        // no preceeding input buffer length check, and in
                        // particular no cfg block has been left open.
                        writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(out, "{{")?;
                        out.make_indent()
                    } else {
                        out.make_same_indent()
                    };

                    let member_name = Self::format_structure_member_name(&entry.name);
                    writeln!(
                        &mut iout,
                        "if unmarshalled_{} != buf_len_at_{} - buf.len() {{",
                        &member_name, &member_name
                    )?;
                    let mut iiout = iout.make_indent();
                    err_cleanup(&mut iiout)?;
                    self.format_error_return(&mut iiout, None, error_rc_size)?;
                    writeln!(&mut iout, "}}")?;

                    if !deps.is_unconditional_true() {
                        writeln!(out, "}}")?;
                    }
                }
                _ => continue,
            };
        }
        Ok(())
    }

    pub(super) fn gen_structure_unmarshal_intern<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        conditional: bool,
        enable_allocator_api: bool,
        enable_in_place_unmarshal: bool,
    ) -> Result<(), io::Error> {
        let table_closure_deps = if !conditional {
            &table.closure_deps
        } else {
            &table.closure_deps_conditional
        };
        let table_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::all());

        let mut unmarshal_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_UNMARSHAL);
        unmarshal_deps.factor_by_common_of(&table_deps);
        if !unmarshal_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&unmarshal_deps))?;
        }

        let references_inbuf = self.structure_references_inbuf(table);
        let lifetime_decl = if !references_inbuf { "<'a>" } else { "" };
        let allocator_arg = if self.structure_contains_nonbyte_array(table) && enable_allocator_api
        {
            ", alloc: &A"
        } else {
            ""
        };

        let need_limits = self.structure_unmarshal_needs_limits(table);
        let limits_arg = if need_limits {
            ", limits: &TpmLimits"
        } else {
            ""
        };

        let is_cryptable = self.structure_is_cryptable(table);
        let (decrypted_head_buf_arg_decl, unencrypted_tail_buf_arg_decl) = if is_cryptable {
            (
                "decrypted_head_buf: Option<&'a [u8]>, ",
                "unencrypted_tail_buf: &'a [u8]",
            )
        } else {
            ("", "buf: &'a [u8]")
        };

        if enable_in_place_unmarshal {
            writeln!(
                out,
                "fn unmarshal_intern{}(dst: *mut Self, {}{}{}{}) -> Result<&'a [u8], TpmErr> {{",
                lifetime_decl,
                decrypted_head_buf_arg_decl,
                unencrypted_tail_buf_arg_decl,
                limits_arg,
                allocator_arg
            )?;
        } else {
            writeln!(
                out,
                "fn unmarshal_intern{}({}{}{}{}) -> Result<(&'a [u8], Self), TpmErr> {{",
                lifetime_decl,
                decrypted_head_buf_arg_decl,
                unencrypted_tail_buf_arg_decl,
                limits_arg,
                allocator_arg
            )?;
        }

        let array_size_specifier_members = Self::find_structure_array_size_specifier_members(table);
        let is_array_size_specifier_member = |j: usize| {
            array_size_specifier_members
                .binary_search_by_key(&j, |e| e.0)
                .is_ok()
        };

        let format_expr_local_id_ref = |j: usize,
                                        target_type_hint: Option<PredefinedTypeRef>|
         -> Result<(String, PredefinedTypeRef, bool), ()> {
            self.format_structure_member_expr_id_ref(table, j, target_type_hint)
        };

        let gen_drop_previous_members = |out: &mut code_writer::IndentedCodeWriter<'_, W>,
                                         mut cur: usize|
         -> Result<(), io::Error> {
            if !enable_in_place_unmarshal {
                return Ok(());
            }
            while cur > 0 {
                cur -= 1;
                let entry = &table.entries[cur];
                match &entry.entry_type {
                    StructureTableEntryType::Discriminant(_) => (),
                    StructureTableEntryType::Union(union_entry) => {
                        // If the last union member discriminated by the associated
                        // discriminant, the tagged union had been fully constructed.
                        let entry = union_entry.resolved_discriminant.unwrap();
                        let entry = &table.entries[entry];
                        assert!(entry.deps.is_unconditional_true());
                        let discriminant =
                            Self::to_structure_discriminant_entry_type(&entry.entry_type);
                        if cur != *discriminant.discriminated_union_members.last().unwrap() {
                            continue;
                        }
                        if !self.tagged_union_needs_drop(table, discriminant) {
                            continue;
                        }
                        let name = Self::format_structure_member_name(&entry.name);
                        writeln!(
                            out,
                            "unsafe{{ptr::addr_of_mut!((*dst).{}).drop_in_place()}};",
                            name
                        )?;
                    }
                    _ => {
                        if !self.structure_member_needs_drop(table, &entry.entry_type) {
                            continue;
                        }

                        let deps = &entry.deps;
                        let deps = deps.factor_by_common_of(&table_deps);
                        let deps = deps.factor_by_common_of(&unmarshal_deps);
                        let mut iout = if !deps.is_unconditional_true() {
                            writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(out, "{{")?;
                            out.make_indent()
                        } else {
                            out.make_same_indent()
                        };

                        let name = Self::format_structure_member_name(&entry.name);
                        writeln!(
                            &mut iout,
                            "unsafe{{ptr::addr_of_mut!((*dst).{}).drop_in_place()}};",
                            name
                        )?;

                        if !deps.is_unconditional_true() {
                            writeln!(out, "}}")?;
                        }
                    }
                };
            }
            Ok(())
        };

        let error_rc_value = table
            .resolved_error_rc
            .or_else(|| self.tables.structures.lookup_constant("TPM_RC_VALUE"));
        let error_rc_size = table
            .resolved_error_rc
            .or_else(|| self.tables.structures.lookup_constant("TPM_RC_SIZE"));

        let mut members: Vec<borrow::Cow<str>> = Vec::new();
        let mut iout = out.make_indent();
        let mut first = true;
        for j in 0..table.entries.len() {
            if !first {
                writeln!(&mut iout)?;
            }
            let entry = &table.entries[j];
            let member_name = Self::format_structure_member_name(&entry.name);
            match &entry.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    let deps = &entry.deps;
                    let deps = deps.factor_by_common_of(&table_deps);
                    let deps = deps.factor_by_common_of(&unmarshal_deps);
                    let mut iiout = if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(&mut iout, "{{")?;
                        iout.make_indent()
                    } else {
                        iout.make_same_indent()
                    };

                    let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                    let enable_conditional = if plain_type.base_type_enable_conditional {
                        true
                    } else if plain_type.base_type_conditional {
                        conditional
                    } else {
                        false
                    };
                    match base_type {
                        StructureTableEntryResolvedBaseType::Predefined(_)
                        | StructureTableEntryResolvedBaseType::Constants(_)
                        | StructureTableEntryResolvedBaseType::Bits(_)
                        | StructureTableEntryResolvedBaseType::Type(_) => {
                            self.gen_structure_member_plain_type_unmarshal(
                                &mut iiout,
                                "buf",
                                "buf",
                                None,
                                &member_name,
                                base_type,
                                enable_conditional,
                                &|out| gen_drop_previous_members(out, j),
                                enable_allocator_api,
                            )?;

                            if let Some(range) = &plain_type.range {
                                self.gen_member_value_range_validation(
                                    &mut iiout,
                                    &table.name,
                                    &entry.name,
                                    j,
                                    range,
                                    error_rc_value.unwrap(),
                                    &format_expr_local_id_ref,
                                    &|out| gen_drop_previous_members(out, j),
                                )?;
                            }

                            if !plain_type.is_size_specifier && !is_array_size_specifier_member(j) {
                                if enable_in_place_unmarshal {
                                    let dst_spec =
                                        format!("ptr::addr_of_mut!((*dst).{})", &member_name);
                                    writeln!(
                                        &mut iiout,
                                        "unsafe{{{}.write(unmarshalled_{})}};",
                                        dst_spec, &member_name
                                    )?;
                                } else {
                                    members.push(member_name);
                                }
                            } else if plain_type.is_size_specifier {
                                let (size_member_expr, _, _) =
                                    format_expr_local_id_ref(j, None).unwrap();
                                writeln!(
                                    &mut iiout,
                                    "let unmarshalled_{} = match usize::try_from({}) {{",
                                    member_name, size_member_expr
                                )?;
                                let mut iiiout = iiout.make_indent();
                                writeln!(
                                    &mut iiiout,
                                    "Ok(unmarshalled_{}) => unmarshalled_{},",
                                    member_name, member_name
                                )?;
                                writeln!(&mut iiiout, "Err(_) => {{")?;
                                let mut iiiiout = iiiout.make_indent();
                                gen_drop_previous_members(&mut iiiiout, j)?;
                                self.format_error_return(
                                    &mut iiiiout,
                                    None,
                                    error_rc_size.unwrap(),
                                )?;
                                writeln!(&mut iiiout, "}},")?;
                                writeln!(&mut iiout, "}};")?;
                                writeln!(
                                    &mut iiout,
                                    "if unmarshalled_{} == 0usize {{",
                                    member_name
                                )?;
                                let mut iiiout = iiout.make_indent();
                                gen_drop_previous_members(&mut iiiout, j)?;
                                self.format_error_return(
                                    &mut iiiout,
                                    None,
                                    error_rc_size.unwrap(),
                                )?;
                                writeln!(&mut iout, "}}")?;
                                writeln!(
                                    &mut iout,
                                    "let buf_len_at_{} = buf.len();",
                                    &member_name
                                )?;
                            }
                        }
                        StructureTableEntryResolvedBaseType::Structure(_) => {
                            let dst_spec = if enable_in_place_unmarshal {
                                Some(format!(
                                    "unsafe{{ptr::addr_of_mut!((*dst).{})}}",
                                    &member_name
                                ))
                            } else {
                                None
                            };
                            if is_cryptable && first {
                                writeln!(
                                    &mut iiout,
                                    "let (buf, unencrypted_tail_buf) = match decrypted_head_buf {{"
                                )?;
                                let mut iiiout = iiout.make_indent();
                                writeln!(
                                    &mut iiiout,
                                    "Some(decrypted_head_buf) => (decrypted_head_buf, Some(unencrypted_tail_buf)),"
                                )?;
                                writeln!(&mut iiiout, "None => (unencrypted_tail_buf, None),")?;
                                writeln!(&mut iiout, "}};")?;
                            }
                            assert!(plain_type.range.is_none());
                            self.gen_structure_member_plain_type_unmarshal(
                                &mut iiout,
                                "buf",
                                "buf",
                                dst_spec.as_deref(),
                                &member_name,
                                base_type,
                                enable_conditional,
                                &|out| gen_drop_previous_members(out, j),
                                enable_allocator_api,
                            )?;
                            if is_cryptable && first {
                                writeln!(
                                    &mut iiout,
                                    "let buf = unencrypted_tail_buf.unwrap_or(buf);"
                                )?;
                            }
                            if !enable_in_place_unmarshal {
                                members.push(member_name);
                            }
                        }
                    };

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "}}")?;
                    }
                }
                StructureTableEntryType::Discriminant(discriminant) => {
                    assert!(entry.deps.is_unconditional_true());

                    let selector_name = member_name + "_selector";

                    let type_spec = Self::format_structure_discriminant_member_enum_name(
                        table,
                        conditional,
                        entry,
                    );
                    let type_spec = Self::camelize(&type_spec);

                    let gen_params_spec = if self.tagged_union_contains_array(table, discriminant)
                        && enable_allocator_api
                    {
                        if self.tagged_union_references_inbuf(table, discriminant) {
                            "::<'_, A>"
                        } else {
                            "::<A>"
                        }
                    } else {
                        ""
                    };

                    writeln!(
                        &mut iout,
                        "let (buf, unmarshalled_{}) = match {}{}::unmarshal_intern_selector(buf) {{",
                        &selector_name, &type_spec, &gen_params_spec
                    )?;

                    let mut iiout = iout.make_indent();
                    writeln!(&mut iiout, "Ok(r) => r,")?;
                    writeln!(&mut iiout, "Err(e) => {{")?;
                    let mut iiiout = iiout.make_indent();
                    gen_drop_previous_members(&mut iiiout, j)?;
                    writeln!(&mut iiiout, "return Err(e);")?;
                    writeln!(&mut iiout, "}},")?;
                    writeln!(&mut iout, "}};")?;
                }
                StructureTableEntryType::Array(array_type) => {
                    let deps = &entry.deps;
                    let deps = deps.factor_by_common_of(&table_deps);
                    let deps = deps.factor_by_common_of(&unmarshal_deps);
                    let mut iiout = if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                        writeln!(&mut iout, "{{")?;
                        iout.make_indent()
                    } else {
                        iout.make_same_indent()
                    };

                    let element_type = array_type.resolved_element_type.as_ref().unwrap();
                    let enable_conditional = if array_type.element_type_enable_conditional {
                        true
                    } else if array_type.element_type_conditional {
                        conditional
                    } else {
                        false
                    };

                    let dst_spec = if enable_in_place_unmarshal {
                        Some(format!("ptr::addr_of_mut!((*dst).{})", &member_name))
                    } else {
                        None
                    };
                    self.gen_structure_member_array_unmarshal(
                        &mut iiout,
                        &table.name,
                        &entry.name,
                        "buf",
                        "buf",
                        dst_spec.as_deref(),
                        &member_name,
                        element_type,
                        enable_conditional,
                        &array_type.size,
                        array_type.size_range.as_ref(),
                        error_rc_size.unwrap(),
                        &format_expr_local_id_ref,
                        &|out| gen_drop_previous_members(out, j),
                        enable_allocator_api,
                    )?;
                    if !enable_in_place_unmarshal {
                        members.push(member_name);
                    }

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
                    assert!(entry.deps.is_unconditional_true());

                    let member_name = Self::format_structure_member_name(&entry.name);
                    let selector_name = member_name.clone() + "_selector";

                    let type_spec = Self::format_structure_discriminant_member_enum_name(
                        table,
                        conditional,
                        entry,
                    );
                    let type_spec = Self::camelize(&type_spec);

                    let contains_array = self.tagged_union_contains_array(table, discriminant);
                    let gen_params_spec = if contains_array {
                        if self.tagged_union_references_inbuf(table, discriminant) {
                            enable_allocator_api
                                .then_some("::<'_, _>")
                                .unwrap_or("::<'_>")
                        } else {
                            enable_allocator_api.then_some("::<_>").unwrap_or("")
                        }
                    } else {
                        ""
                    };
                    let allocator_arg = if self
                        .tagged_union_contains_nonbyte_array(table, discriminant)
                        && enable_allocator_api
                    {
                        ", alloc"
                    } else {
                        ""
                    };

                    let needs_limits =
                        self.tagged_union_unmarshal_needs_limits(table, discriminant);
                    let limits_arg = if needs_limits { ", limits" } else { "" };

                    if enable_in_place_unmarshal {
                        let dst_spec =
                            format!("unsafe{{ptr::addr_of_mut!((*dst).{})}}", &member_name);
                        writeln!(
                            &mut iout,
                            "let buf = match {}{}::unmarshal_intern({}, unmarshalled_{}, buf{}{}) {{",
                            type_spec,
                            gen_params_spec,
                            dst_spec,
                            &selector_name,
                            limits_arg,
                            allocator_arg
                        )?;
                    } else {
                        writeln!(
                            &mut iout,
                            "let (buf, unmarshalled_{}) = match {}{}::unmarshal_intern(unmarshalled_{}, buf{}{}) {{",
                            &member_name,
                            type_spec,
                            gen_params_spec,
                            &selector_name,
                            limits_arg,
                            allocator_arg
                        )?;
                        members.push(member_name);
                    }
                    let mut iiout = iout.make_indent();
                    writeln!(&mut iiout, "Ok(r) => r,")?;
                    writeln!(&mut iiout, "Err(e) => {{")?;
                    let mut iiiout = iiout.make_indent();
                    gen_drop_previous_members(&mut iiiout, j)?;
                    writeln!(&mut iiiout, "return Err(e);")?;
                    writeln!(&mut iiout, "}},")?;
                    writeln!(&mut iout, "}};")?;
                }
            };

            first = false;
        }

        self.gen_structure_size_spec_checks(
            &mut iout,
            table,
            &table_deps,
            &unmarshal_deps,
            error_rc_size.unwrap(),
            &|out| gen_drop_previous_members(out, table.entries.len()),
        )?;

        if !first {
            writeln!(&mut iout)?;
        }
        if enable_in_place_unmarshal {
            writeln!(&mut iout, "Ok(buf)")?;
        } else {
            let members = members
                .iter()
                .map(|m| format!("{}: unmarshalled_{}", m, m))
                .collect::<Vec<String>>()
                .join(", ");
            writeln!(&mut iout, "Ok((buf, Self{{{}}}))", members)?;
        }
        writeln!(out, "}}")?;

        Ok(())
    }

    fn format_tagged_union_member_layout_repr_type_spec(
        &self,
        table: &StructureTable,
        tagged_union_repr_name: &str,
        discriminant: &StructureTableEntryDiscriminantType,
        selector: &UnionSelectorIteratorValue,
        use_anon_lifetime: bool,
        enable_allocator_api: bool,
    ) -> String {
        // Depending on the number of discriminanted union members, the
        // individual enum variants' associated data is wrapped in a struct or not.
        if discriminant.discriminated_union_members.len() == 1 {
            let union_member_entry = discriminant.discriminated_union_members[0];
            let union_member_entry = &table.entries[union_member_entry];
            assert!(union_member_entry.deps.is_unconditional_true());
            let union_type = Self::to_structure_union_entry_type(&union_member_entry.entry_type);
            let union_table_index = union_type.resolved_union_type.unwrap();
            let union_table = self.tables.structures.get_union(union_table_index);
            let selected = union_table.lookup_member(selector.name()).unwrap();
            let selected = &union_table.entries[selected];
            match &selected.entry_type {
                UnionTableEntryType::Plain(plain_type) => match &plain_type.resolved_base_type {
                    None => unreachable!(),
                    Some(base_type) => self
                        .format_structure_member_plain_type(
                            base_type,
                            plain_type.base_type_enable_conditional,
                            use_anon_lifetime,
                            enable_allocator_api,
                        )
                        .into_owned(),
                },
                UnionTableEntryType::Array(array_type) => self.format_structure_member_array_type(
                    array_type.resolved_element_type.as_ref().unwrap(),
                    array_type.element_type_enable_conditional,
                    use_anon_lifetime,
                    enable_allocator_api,
                ),
            }
        } else {
            let name = self.format_tagged_union_member_name(selector);
            let name = Self::camelize(&name);
            let type_spec = tagged_union_repr_name.to_owned() + "_" + &name;
            let mut type_spec = Self::camelize(&type_spec);
            if self.tagged_union_member_contains_array(table, discriminant, selector.name()) {
                if self.tagged_union_member_references_inbuf(table, discriminant, selector.name()) {
                    if !use_anon_lifetime {
                        type_spec += enable_allocator_api.then_some("<'a, A>").unwrap_or("<'a>")
                    } else if enable_allocator_api {
                        type_spec += "::<'_, A>";
                    }
                } else if enable_allocator_api {
                    if !use_anon_lifetime {
                        type_spec += "<A>";
                    } else {
                        type_spec += "::<A>";
                    }
                }
            }
            type_spec
        }
    }

    pub(in super::super) fn gen_tagged_union_layout_repr_struct<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        tagged_union_name: &str,
        discriminant_member: usize,
        conditional: bool,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error> {
        let entry = &table.entries[discriminant_member];
        assert!(entry.deps.is_unconditional_true());
        let entry = &entry.entry_type;
        let discriminant = Self::to_structure_discriminant_entry_type(entry);
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

        let tagged_union_name = tagged_union_name.to_owned() + "_LAYOUT_REPR";
        let tagged_union_content_union_name = tagged_union_name.clone() + "_UNION";

        let layout_repr_deps = closure_deps.collect_config_deps(ClosureDepsFlags::ANY_UNMARSHAL);
        if !layout_repr_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&layout_repr_deps))?;
        }

        writeln!(out, "#[repr(C)]")?;
        writeln!(
            out,
            "struct {}{} {{",
            Self::camelize(&tagged_union_name),
            gen_params_spec.0
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "selector: {},",
            Self::predefined_type_to_rust(discriminant_base)
        )?;
        writeln!(
            &mut iout,
            "u: {}{},",
            Self::camelize(&tagged_union_content_union_name),
            gen_params_spec.1
        )?;
        writeln!(out, "}}")?;

        writeln!(out)?;
        if !layout_repr_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&layout_repr_deps))?;
        }
        writeln!(out, "#[repr(C)]")?;
        writeln!(
            out,
            "union {}{} {{",
            Self::camelize(&tagged_union_content_union_name),
            gen_params_spec.0
        )?;
        let mut iout = out.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            conditional | discriminant.discriminant_type_enable_conditional,
        ) {
            // No entry for data-less members.
            if self.tagged_union_member_is_empty(table, discriminant, selector.name()) {
                continue;
            }

            let deps = selector
                .config_deps()
                .factor_by_common_of(&layout_repr_deps);
            if !deps.is_unconditional_true() {
                writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
            }

            let name = self.format_tagged_union_member_name(&selector);
            let type_spec = self.format_tagged_union_member_layout_repr_type_spec(
                table,
                &tagged_union_name,
                discriminant,
                &selector,
                false,
                enable_allocator_api,
            );
            let needs_drop =
                self.tagged_union_member_needs_drop(table, discriminant, selector.name());
            if needs_drop {
                writeln!(
                    &mut iout,
                    "{}: mem::ManuallyDrop<{}>,",
                    Self::uncamelize(&name),
                    type_spec
                )?;
            } else {
                writeln!(&mut iout, "{}: {},", Self::uncamelize(&name), type_spec)?;
            }
        }
        writeln!(out, "}}")?;

        if discriminant.discriminated_union_members.len() != 1 {
            for selector in UnionSelectorIterator::new(
                &self.tables.structures,
                *discriminant.resolved_discriminant_type.as_ref().unwrap(),
                conditional | discriminant.discriminant_type_enable_conditional,
            ) {
                // No entry for data-less members.
                if self.tagged_union_member_is_empty(table, discriminant, selector.name()) {
                    continue;
                }

                writeln!(out)?;
                let mut deps = layout_repr_deps.clone();
                deps.limit_by(selector.config_deps());
                let deps = selector
                    .config_deps()
                    .factor_by_common_of(&layout_repr_deps);
                if !deps.is_unconditional_true() {
                    writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                }

                if !self.tagged_union_member_needs_drop(table, discriminant, selector.name()) {
                    writeln!(out, "#[derive(Clone, Copy, Debug)]")?;
                } else {
                    writeln!(out, "#[derive(Debug)]")?;
                }

                let gen_params_spec = if self.tagged_union_member_contains_array(
                    table,
                    discriminant,
                    selector.name(),
                ) {
                    if self.tagged_union_member_references_inbuf(
                        table,
                        discriminant,
                        selector.name(),
                    ) {
                        if enable_allocator_api {
                            "<'a, A: Clone + Allocator>"
                        } else {
                            "<'a>"
                        }
                    } else if enable_allocator_api {
                        "<A: Clone + Allocator>"
                    } else {
                        ""
                    }
                } else {
                    ""
                };

                let name = self.format_tagged_union_member_name(&selector);
                let name = tagged_union_name.clone() + "_" + &name;
                let name = Self::camelize(&name);
                writeln!(out, "#[repr(C)]")?;
                writeln!(out, "struct {}{} {{", &name, gen_params_spec)?;
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
                writeln!(out, "}}")?;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn gen_tagged_union_unmarshal_intern<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        table_deps: &ConfigDepsDisjunction,
        tagged_union_name: &str,
        discriminant_member: usize,
        is_structure_member_repr: bool,
        conditional: bool,
        enable_allocator_api: bool,
        enable_in_place_unmarshal: bool,
    ) -> Result<(), io::Error> {
        let discriminant_entry = &table.entries[discriminant_member];
        assert!(discriminant_entry.deps.is_unconditional_true());
        let discriminant =
            Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);

        let mut unmarshal_deps = closure_deps.collect_config_deps(ClosureDepsFlags::ANY_UNMARSHAL);
        unmarshal_deps.factor_by_common_of(table_deps);

        let contains_array = self.tagged_union_contains_array(table, discriminant);
        let references_inbuf =
            contains_array && self.tagged_union_references_inbuf(table, discriminant);
        let lifetime_decl = if !references_inbuf { "<'a>" } else { "" };

        let (discriminant_base, error_rc_value) =
            match discriminant.resolved_discriminant_type.as_ref().unwrap() {
                StructureTableEntryResolvedDiscriminantType::Constants(i) => {
                    let constants_table = self.tables.structures.get_constants(*i);
                    (
                        constants_table.resolved_base.unwrap(),
                        constants_table.resolved_error_rc,
                    )
                }
                StructureTableEntryResolvedDiscriminantType::Type(i) => {
                    let type_table = self.tables.structures.get_type(*i);
                    (
                        type_table.underlying_type.unwrap(),
                        type_table.resolved_error_rc,
                    )
                }
            };

        // If the tagged union does not represent a complete structure from the
        // interface specification but some set of union members only, then the
        // discriminant might be separated from the sequence of union members in
        // the containing structure. Provide a primitive for unmarshalling the
        // discriminant separately from the container.
        if is_structure_member_repr {
            if !unmarshal_deps.is_implied_by(table_deps) {
                writeln!(out, "#[cfg({})]", Self::format_deps(&unmarshal_deps))?;
            }

            writeln!(
                out,
                "fn unmarshal_intern_selector{}(buf: &'a [u8]) -> Result<(&'a [u8], {}), TpmErr> {{",
                lifetime_decl,
                Self::predefined_type_to_rust(discriminant_base)
            )?;

            let mut iout = out.make_indent();
            let member_name =
                Self::format_structure_member_name(&discriminant_entry.name) + "_selector";
            let discriminant_base =
                StructureTableEntryResolvedBaseType::Predefined(discriminant_base);
            self.gen_structure_member_plain_type_unmarshal(
                &mut iout,
                "buf",
                "buf",
                None,
                &member_name,
                &discriminant_base,
                false,
                &|_| Ok(()),
                enable_allocator_api,
            )?;
            writeln!(&mut iout, "Ok((buf, unmarshalled_{}))", &member_name)?;
            writeln!(out, "}}")?;
            writeln!(out)?;
        }

        let error_rc_value =
            error_rc_value.or_else(|| self.tables.structures.lookup_constant("TPM_RC_VALUE"));
        let error_rc_size =
            error_rc_value.or_else(|| self.tables.structures.lookup_constant("TPM_RC_SIZE"));

        let need_limits = self.tagged_union_unmarshal_needs_limits(table, discriminant);
        let limits_arg = if need_limits {
            ", limits: &TpmLimits"
        } else {
            ""
        };

        let allocator_arg = if self.tagged_union_contains_nonbyte_array(table, discriminant)
            && enable_allocator_api
        {
            ", alloc: &A"
        } else {
            ""
        };

        if !unmarshal_deps.is_implied_by(table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&unmarshal_deps))?;
        }
        // If this tagged union represents a complete structure definition as
        // found in the spec, unmarshal the discriminant and any <size>=
        // specifiers. Otherwise, i.e. if this tagged union had be introduced to
        // represent some structure's member(s), that's been handlded by the
        // caller.
        if enable_in_place_unmarshal {
            if is_structure_member_repr {
                writeln!(
                    out,
                    "fn unmarshal_intern{}(dst: *mut Self, selector: {}, buf: &'a [u8]{}{}) -> Result<&'a [u8], TpmErr> {{",
                    lifetime_decl,
                    Self::predefined_type_to_rust(discriminant_base),
                    limits_arg,
                    allocator_arg
                )?;
            } else {
                writeln!(
                    out,
                    "fn unmarshal_intern{}(dst: *mut Self, buf: &'a [u8]{}{}) -> Result<&'a [u8], TpmErr> {{",
                    lifetime_decl, limits_arg, allocator_arg
                )?;
            }
        } else if is_structure_member_repr {
            writeln!(
                out,
                "fn unmarshal_intern{}(selector: {}, buf: &'a [u8]{}{}) -> Result<(&'a [u8], Self), TpmErr> {{",
                lifetime_decl,
                Self::predefined_type_to_rust(discriminant_base),
                limits_arg,
                allocator_arg
            )?;
        } else {
            writeln!(
                out,
                "fn unmarshal_intern{}(buf: &'a [u8]{}{}) -> Result<(&'a [u8], Self), TpmErr> {{",
                lifetime_decl, limits_arg, allocator_arg
            )?;
        }

        let mut iout = out.make_indent();
        let mut first = true;
        if !is_structure_member_repr {
            let format_expr_local_id_ref =
                |j: usize,
                 target_type_hint: Option<PredefinedTypeRef>|
                 -> Result<(String, PredefinedTypeRef, bool), ()> {
                    self.format_structure_member_expr_id_ref(table, j, target_type_hint)
                };

            for j in 0..table.entries.len() {
                if !first {
                    writeln!(&mut iout)?;
                }
                first = false;
                let entry = &table.entries[j];
                let member_name = Self::format_structure_member_name(&entry.name);
                match &entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => {
                        let deps = &entry.deps;
                        let deps = deps.factor_by_common_of(table_deps);
                        let deps = deps.factor_by_common_of(&unmarshal_deps);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };

                        let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                        let enable_conditional = if plain_type.base_type_enable_conditional {
                            true
                        } else if plain_type.base_type_conditional {
                            conditional
                        } else {
                            false
                        };
                        match base_type {
                            StructureTableEntryResolvedBaseType::Predefined(_)
                            | StructureTableEntryResolvedBaseType::Constants(_)
                            | StructureTableEntryResolvedBaseType::Type(_) => (),
                            _ => unreachable!(),
                        };
                        self.gen_structure_member_plain_type_unmarshal(
                            &mut iiout,
                            "buf",
                            "buf",
                            None,
                            &member_name,
                            base_type,
                            enable_conditional,
                            &|_| Ok(()),
                            enable_allocator_api,
                        )?;
                        if let Some(range) = &plain_type.range {
                            self.gen_member_value_range_validation(
                                &mut iiout,
                                &table.name,
                                &entry.name,
                                j,
                                range,
                                error_rc_value.unwrap(),
                                &format_expr_local_id_ref,
                                &|_| Ok(()),
                            )?;
                        }

                        assert!(plain_type.is_size_specifier);
                        let (size_member_expr, _, _) = format_expr_local_id_ref(j, None).unwrap();
                        writeln!(
                            &mut iiout,
                            "let unmarshalled_{} = match usize::try_from({}) {{",
                            member_name, size_member_expr
                        )?;
                        let mut iiiout = iiout.make_indent();
                        writeln!(
                            &mut iiiout,
                            "Ok(unmarshalled_{}) => unmarshalled_{},",
                            member_name, member_name
                        )?;
                        writeln!(&mut iiiout, "Err(_) => {{")?;
                        let mut iiiiout = iiiout.make_indent();
                        self.format_error_return(&mut iiiiout, None, error_rc_size.unwrap())?;
                        writeln!(&mut iiiout, "}},")?;
                        writeln!(&mut iiout, "}};")?;
                        writeln!(&mut iiout, "if unmarshalled_{} == 0usize {{", member_name)?;
                        let mut iiiout = iiout.make_indent();
                        self.format_error_return(&mut iiiout, None, error_rc_size.unwrap())?;
                        writeln!(&mut iout, "}}")?;
                        writeln!(&mut iout, "let buf_len_at_{} = buf.len();", &member_name)?;

                        if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "}}")?;
                        }
                    }
                    StructureTableEntryType::Discriminant(_) => {
                        assert_eq!(discriminant_member, j);
                        let deps = &entry.deps;
                        let deps = deps.factor_by_common_of(table_deps);
                        let deps = deps.factor_by_common_of(&unmarshal_deps);
                        let mut iiout = if !deps.is_unconditional_true() {
                            writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                            writeln!(&mut iout, "{{")?;
                            iout.make_indent()
                        } else {
                            iout.make_same_indent()
                        };

                        let discriminant_base =
                            StructureTableEntryResolvedBaseType::Predefined(discriminant_base);
                        self.gen_structure_member_plain_type_unmarshal(
                            &mut iiout,
                            "buf",
                            "buf",
                            None,
                            &member_name,
                            &discriminant_base,
                            false,
                            &|_| Ok(()),
                            enable_allocator_api,
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
                        assert_eq!(j, discriminant.discriminated_union_members[0]);
                        break;
                    }
                    StructureTableEntryType::Array(_) => unreachable!(),
                };
            }
        }

        let selector_name = if !is_structure_member_repr {
            borrow::Cow::Owned(
                "unmarshalled_".to_owned()
                    + &Self::format_structure_member_name(&discriminant_entry.name),
            )
        } else {
            borrow::Cow::Borrowed("selector")
        };

        let tagged_union_repr_name = if enable_in_place_unmarshal {
            let tagged_union_repr_name = tagged_union_name.to_owned() + "_LAYOUT_REPR";
            let gen_params_spec = if contains_array {
                enable_allocator_api.then_some("<'a, A>").unwrap_or("<'a>")
            } else {
                ""
            };
            writeln!(
                &mut iout,
                "let dst = dst as *mut {}{};",
                Self::camelize(&tagged_union_repr_name),
                gen_params_spec,
            )?;
            writeln!(
                &mut iout,
                "unsafe{{ptr::addr_of_mut!((*dst).selector).write({})}};",
                &selector_name
            )?;
            writeln!(&mut iout, "let buf = match {} {{", &selector_name)?;
            Some(tagged_union_repr_name)
        } else {
            writeln!(&mut iout, "let (buf, r) = match {} {{", &selector_name)?;
            None
        };
        let mut iiout = iout.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            conditional | discriminant.discriminant_type_enable_conditional,
        ) {
            let deps = selector.config_deps().factor_by_common_of(table_deps);
            let deps = deps.factor_by_common_of(&unmarshal_deps);
            if !deps.is_unconditional_true() {
                writeln!(
                    &mut iiout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&deps)
                )?;
            }

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

            writeln!(&mut iiout, "value if value == {} => {{", selector_value.0)?;

            // No content union entry for data-less members.
            let name = self.format_tagged_union_member_name(&selector);
            if self.tagged_union_member_is_empty(table, discriminant, selector.name()) {
                if enable_in_place_unmarshal {
                    writeln!(&mut iiout.make_indent(), "buf")?;
                } else {
                    writeln!(
                        &mut iiout.make_indent(),
                        "(buf, Self::{})",
                        Self::camelize(&name)
                    )?;
                }
                writeln!(&mut iiout, "}},")?;
                continue;
            }

            let mut iiiout = iiout.make_indent();
            if enable_in_place_unmarshal {
                let tagged_union_repr_name = tagged_union_repr_name.as_ref().unwrap();
                let type_spec = self.format_tagged_union_member_layout_repr_type_spec(
                    table,
                    tagged_union_repr_name,
                    discriminant,
                    &selector,
                    true,
                    enable_allocator_api,
                );
                let needs_drop =
                    self.tagged_union_member_needs_drop(table, discriminant, selector.name());
                if needs_drop {
                    // The members that need dropping are (necessarily) wrapped in a ManuallyDrop<>
                    // in the layout representation union.
                    writeln!(
                        &mut iiiout,
                        "let dst = unsafe{{ptr::addr_of_mut!((*dst).u.{})}} as *mut {};",
                        Self::uncamelize(&name),
                        &type_spec
                    )?;
                } else {
                    writeln!(
                        &mut iiiout,
                        "let dst = unsafe{{ptr::addr_of_mut!((*dst).u.{})}};",
                        Self::uncamelize(&name)
                    )?;
                }
            }

            let gen_drop_previous_members = |out: &mut code_writer::IndentedCodeWriter<'_, W>,
                                             mut cur: usize|
             -> Result<(), io::Error> {
                if !enable_in_place_unmarshal {
                    return Ok(());
                }
                while cur > 0 {
                    cur -= 1;
                    let union_member_entry = discriminant.discriminated_union_members[cur];
                    let union_member_entry = &table.entries[union_member_entry];
                    assert!(union_member_entry.deps.is_unconditional_true());
                    let union_type =
                        Self::to_structure_union_entry_type(&union_member_entry.entry_type);
                    let union_table_index = union_type.resolved_union_type.unwrap();
                    let union_table = self.tables.structures.get_union(union_table_index);
                    let selected = union_table.lookup_member(selector.name()).unwrap();
                    let selected = &union_table.entries[selected];
                    if self.union_member_needs_drop(&selected.entry_type) {
                        if discriminant.discriminated_union_members.len() == 1 {
                            writeln!(out, "unsafe{{dst.drop_in_place()}};")?;
                        } else {
                            writeln!(
                                out,
                                "unsafe{{ptr::addr_of_mut!((*dst).{}).drop_in_place()}};",
                                Self::format_structure_member_name(&union_member_entry.name)
                            )?;
                        }
                    }
                }
                Ok(())
            };

            let mut variant_members: Vec<borrow::Cow<str>> = Vec::new();
            for j in 0..discriminant.discriminated_union_members.len() {
                if j != 0 {
                    writeln!(&mut iiiout)?;
                }

                let union_member_entry = discriminant.discriminated_union_members[j];
                let union_member_entry = &table.entries[union_member_entry];
                assert!(union_member_entry.deps.is_unconditional_true());
                let union_type =
                    Self::to_structure_union_entry_type(&union_member_entry.entry_type);
                let union_table_index = union_type.resolved_union_type.unwrap();
                let union_table = self.tables.structures.get_union(union_table_index);
                let selected = union_table.lookup_member(selector.name()).unwrap();
                let selected = &union_table.entries[selected];
                let member_name = Self::format_structure_member_name(&union_member_entry.name);

                match &selected.entry_type {
                    UnionTableEntryType::Plain(plain_type) => {
                        let base_type = match plain_type.resolved_base_type.as_ref() {
                            Some(base_type) => base_type,
                            None => continue,
                        };
                        let dst_spec = if enable_in_place_unmarshal {
                            let dst_spec = if discriminant.discriminated_union_members.len() == 1 {
                                borrow::Cow::Borrowed("dst")
                            } else if let StructureTableEntryResolvedBaseType::Structure(_) =
                                base_type
                            {
                                borrow::Cow::Owned(format!(
                                    "unsafe{{ptr::addr_of_mut!((*dst).{})}}",
                                    &member_name
                                ))
                            } else {
                                borrow::Cow::Owned(format!(
                                    "ptr::addr_of_mut!((*dst).{})",
                                    &member_name
                                ))
                            };
                            Some(dst_spec)
                        } else {
                            None
                        };
                        self.gen_structure_member_plain_type_unmarshal(
                            &mut iiiout,
                            "buf",
                            "buf",
                            dst_spec.as_ref().map(|s| s.as_ref()),
                            &member_name,
                            base_type,
                            plain_type.base_type_enable_conditional,
                            &|out| gen_drop_previous_members(out, j),
                            enable_allocator_api,
                        )?;
                    }
                    UnionTableEntryType::Array(array_type) => {
                        let element_type = array_type.resolved_element_type.as_ref().unwrap();
                        let dst_spec = if enable_in_place_unmarshal {
                            let dst_spec = if discriminant.discriminated_union_members.len() == 1 {
                                borrow::Cow::Borrowed("dst")
                            } else {
                                borrow::Cow::Owned(format!(
                                    "ptr::addr_of_mut!((*dst).{})",
                                    &member_name
                                ))
                            };
                            Some(dst_spec)
                        } else {
                            None
                        };
                        self.gen_structure_member_array_unmarshal(
                            &mut iiiout,
                            &union_table.name,
                            &selected.name,
                            "buf",
                            "buf",
                            dst_spec.as_ref().map(|s| s.as_ref()),
                            &member_name,
                            element_type,
                            array_type.element_type_enable_conditional,
                            &array_type.size,
                            None,
                            error_rc_size.unwrap(),
                            &|_, _| unreachable!(),
                            &|out| gen_drop_previous_members(out, j),
                            enable_allocator_api,
                        )?;
                    }
                };

                if !enable_in_place_unmarshal {
                    variant_members.push(member_name);
                }
            }
            writeln!(&mut iiiout)?;
            if enable_in_place_unmarshal {
                writeln!(&mut iiiout, "buf")?;
            } else if discriminant.discriminated_union_members.len() == 1 {
                assert_eq!(variant_members.len(), 1);
                let variant_member = "unmarshalled_".to_owned() + &variant_members[0];
                writeln!(
                    &mut iiiout,
                    "(buf, Self::{}({}))",
                    Self::camelize(&name),
                    variant_member
                )?;
            } else {
                let variant_members = variant_members
                    .iter()
                    .map(|m| format!("{}: unmarshalled_{}", m, m))
                    .collect::<Vec<String>>()
                    .join(", ");
                writeln!(
                    &mut iiiout,
                    "(buf, Self::{}{{{}}})",
                    Self::camelize(&name),
                    variant_members
                )?;
            }
            writeln!(&mut iiout, "}},")?;
        }
        let mut iiout = iout.make_indent();
        writeln!(&mut iiout, "_ => {{")?;
        self.format_error_return(&mut iiout.make_indent(), None, error_rc_value.unwrap())?;
        writeln!(&mut iiout, "}},")?;
        writeln!(&mut iout, "}};")?;

        if !is_structure_member_repr {
            self.gen_structure_size_spec_checks(
                &mut iout,
                table,
                table_deps,
                &unmarshal_deps,
                error_rc_size.unwrap(),
                &|out| {
                    if !enable_in_place_unmarshal
                        || !self.tagged_union_needs_drop(table, discriminant)
                    {
                        return Ok(());
                    }
                    writeln!(out, "let dst = dst as *mut Self;")?;
                    writeln!(out, "unsafe{{dst.drop_in_place()}};")?;
                    Ok(())
                },
            )?;
        }

        writeln!(&mut iout)?;
        if enable_in_place_unmarshal {
            writeln!(&mut iout, "Ok(buf)")?;
        } else {
            writeln!(&mut iout, "Ok((buf, r))")?;
        }
        writeln!(out, "}}")?;

        Ok(())
    }

    pub(in super::super) fn structure_is_cryptable(&self, table: &StructureTable) -> bool {
        if !table.is_command_response_params || table.entries.is_empty() {
            false
        } else {
            let first_member = &table.entries[0];
            match &first_member.entry_type {
                StructureTableEntryType::Plain(plain_type) => {
                    match plain_type.resolved_base_type.as_ref().unwrap() {
                        StructureTableEntryResolvedBaseType::Structure(index) => {
                            let table = self.tables.structures.get_structure(*index);
                            table.can_crypt()
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
    }

    pub(super) fn gen_structure_unmarshal<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        conditional: bool,
        enable_allocator_api: bool,
        enable_in_place_unmarshal: bool,
    ) -> Result<(), io::Error> {
        let table_closure_deps = if !conditional {
            &table.closure_deps
        } else {
            &table.closure_deps_conditional
        };
        let table_deps = table_closure_deps.collect_config_deps(ClosureDepsFlags::all());

        let mut unmarshal_deps =
            table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_UNMARSHAL);
        unmarshal_deps.factor_by_common_of(&table_deps);
        if !unmarshal_deps.is_implied_by(&table_deps) {
            writeln!(out, "#[cfg({})]", Self::format_deps(&unmarshal_deps))?;
        }

        let contains_array = self.structure_contains_array(table);
        let references_inbuf = contains_array && self.structure_references_inbuf(table);
        let gen_params_spec = if !contains_array && enable_allocator_api {
            "<'a, A: Clone + Allocator>"
        } else if !references_inbuf {
            "<'a>"
        } else {
            ""
        };
        let allocator_arg = if self.structure_contains_nonbyte_array(table) && enable_allocator_api
        {
            ", alloc"
        } else {
            ""
        };

        let need_limits = self.structure_unmarshal_needs_limits(table);
        let limits_arg = if need_limits {
            (", limits: &TpmLimits", ", limits")
        } else {
            ("", "")
        };

        let is_cryptable = self.structure_is_cryptable(table);
        let (
            decrypted_head_buf_arg_decl,
            decrypted_head_buf_arg,
            unencrypted_tail_buf_arg_decl,
            unenctryped_tail_buf,
        ) = if is_cryptable {
            (
                "decrypted_head_buf: Option<&'a [u8]>, ",
                "decrypted_head_buf, ",
                "unencrypted_tail_buf: &'a [u8]",
                "unencrypted_tail_buf",
            )
        } else {
            ("", "", "buf: &'a [u8]", "buf")
        };

        writeln!(
            out,
            "pub fn unmarshal{}({}{}{}{}) -> Result<(&'a [u8], Box<Self{}>), TpmErr> {{",
            gen_params_spec,
            decrypted_head_buf_arg_decl,
            unencrypted_tail_buf_arg_decl,
            limits_arg.0,
            enable_allocator_api.then_some(", alloc: &A").unwrap_or(""),
            enable_allocator_api.then_some(", A").unwrap_or("")
        )?;

        let mut iout = out.make_indent();
        let error_rc_memory = self
            .tables
            .structures
            .lookup_constant("TPM_RC_MEMORY")
            .unwrap();

        if enable_in_place_unmarshal {
            if enable_allocator_api {
                writeln!(
                    &mut iout,
                    "let mut unmarshalled_uninit = match Box::<Self, A>::try_new_uninit_in(alloc.clone()) {{",
                )?;
            } else {
                writeln!(
                    &mut iout,
                    "let mut unmarshalled_uninit = match box_try_new(mem::MaybeUninit::<Self>::uninit()) {{",
                )?;
            }
            let mut iiout = iout.make_indent();
            writeln!(
                &mut iiout,
                "Ok(unmarshalled_uninit) => unmarshalled_uninit,"
            )?;
            writeln!(&mut iiout, "Err(_) => {{")?;
            self.format_error_return(&mut iiout.make_indent(), None, error_rc_memory)?;
            writeln!(&mut iiout, "}},")?;
            writeln!(&mut iout, "}};")?;

            writeln!(&mut iout)?;
            writeln!(
                &mut iout,
                "let buf = Self::unmarshal_intern(unmarshalled_uninit.as_mut_ptr(), {}{}{}{})?;",
                decrypted_head_buf_arg, unenctryped_tail_buf, limits_arg.1, allocator_arg
            )?;
            writeln!(
                &mut iout,
                "let unmarshalled: Box<Self{}> = unsafe{{unmarshalled_uninit.assume_init()}};",
                enable_allocator_api.then_some(", A").unwrap_or("")
            )?;
        } else {
            writeln!(
                &mut iout,
                "let (buf, unmarshalled) = Self::unmarshal_intern({}{}{}{})?;",
                decrypted_head_buf_arg, unenctryped_tail_buf, limits_arg.1, allocator_arg
            )?;
            if enable_allocator_api {
                writeln!(
                    &mut iout,
                    "let unmarshalled: Box<Self, A> = match Box::<Self, A>::try_new_in(unmarshalled, alloc.clone()) {{"
                )?;
            } else {
                writeln!(
                    &mut iout,
                    "let unmarshalled: Box<Self> = match box_try_new(unmarshalled) {{"
                )?;
            }
            let mut iiout = iout.make_indent();
            writeln!(&mut iiout, "Ok(unmarshalled) => unmarshalled,")?;
            writeln!(&mut iiout, "Err(_) => {{")?;
            self.format_error_return(&mut iiout.make_indent(), None, error_rc_memory)?;
            writeln!(&mut iiout, "}},")?;
            writeln!(&mut iout, "}};")?;
        }

        writeln!(&mut iout)?;
        writeln!(&mut iout, "Ok((buf, unmarshalled))")?;
        writeln!(out, "}}")?;

        Ok(())
    }
}
