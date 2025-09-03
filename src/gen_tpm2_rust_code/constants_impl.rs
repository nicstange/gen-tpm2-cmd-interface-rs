// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use structures::constants_table::ConstantsTable;
use structures::expr::{Expr, ExprId, ExprOp, ExprResolvedId, ExprValue};
use structures::predefined::{PredefinedTypeRef, PredefinedTypes};
use structures::table_common::ClosureDepsFlags;
use structures::tables::{
    StructuresPartTablesConstantIndex, StructuresPartTablesConstantsIndex,
    StructuresPartTablesIndex,
};

use super::{Tpm2InterfaceRustCodeGenerator, code_writer};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn strip_constant_table_prefix(
        &self,
        index: StructuresPartTablesConstantIndex,
    ) -> usize {
        let entry = self.tables.structures.get_constant(index);
        let entry_name = &entry.name;
        let table_index = StructuresPartTablesConstantsIndex::from(index);
        let table = self.tables.structures.get_constants(table_index);

        let mut prefix_end = Self::strip_table_prefix(&table.name, entry_name);
        // Re-add prefix parts until the identifier is unique.
        let entry_name_parts = entry_name.split('_').collect::<Vec<&str>>();
        'others: while prefix_end > 0 {
            let entry_name_tail_parts = &entry_name_parts[prefix_end..];
            for k in 0..table.entries.len() {
                if k == index.1 {
                    continue;
                }
                let other_name = &table.entries[k].name;
                let other_prefix_end = Self::strip_table_prefix(&table.name, other_name);
                let other_name_parts = other_name.split('_').collect::<Vec<&str>>();

                // If the other name is guaranteed to have more components retained, there's no
                // chance of conflict.
                // If the other name is guaranteed to have less components retained, there's no
                // chance of conflict either.
                if other_name_parts.len() - other_prefix_end > entry_name_tail_parts.len()
                    || other_name_parts.len() < entry_name_tail_parts.len()
                {
                    continue;
                }

                // If the tail components are all equal, re-add the component immediately preceeding
                // them, until the result becomes unique again.
                let other_name_tail_parts =
                    &other_name_parts[other_name_parts.len() - entry_name_tail_parts.len()..];
                if *other_name_tail_parts == *entry_name_tail_parts {
                    prefix_end -= 1;
                    continue 'others;
                }
            }
            break;
        }

        prefix_end
    }

    pub(super) fn format_const_member_name(
        &self,
        index: StructuresPartTablesConstantIndex,
    ) -> String {
        let entry = self.tables.structures.get_constant(index);
        let entry_name = &entry.name;
        let prefix_end = self.strip_constant_table_prefix(index);
        let entry_name_parts = entry_name.split('_').collect::<Vec<&str>>();
        entry_name_parts[prefix_end..].join("_")
    }

    pub(super) fn constants_are_compiletime_const(table: &ConstantsTable) -> bool {
        for entry in &table.entries {
            match entry.value.value.as_ref().unwrap() {
                ExprValue::CompiletimeConstant(_) => (),
                _ => {
                    assert!(!table.enum_like);
                    return false;
                }
            };
        }
        true
    }

    fn use_enum_repr_for_constants(table: &ConstantsTable) -> bool {
        if table.enum_like {
            debug_assert!(Self::constants_are_compiletime_const(table));
        }

        table.enum_like
    }

    pub(super) fn format_constant_ref(
        &self,
        context: Option<StructuresPartTablesIndex>,
        index: StructuresPartTablesConstantIndex,
        target_type_hint: Option<PredefinedTypeRef>,
    ) -> Result<(String, PredefinedTypeRef, bool, bool), ()> {
        let context = context.and_then(|c| match c {
            StructuresPartTablesIndex::Constants(index) => Some(index),
            _ => None,
        });
        let mut name;
        let table_index = StructuresPartTablesConstantsIndex::from(index);
        let table = self.tables.structures.get_constants(table_index);
        match context {
            Some(context) => {
                if context == table_index {
                    name = "Self::".to_owned();
                } else {
                    name = Self::camelize(&table.name) + "::";
                }
            }
            None => {
                name = Self::camelize(&table.name) + "::";
            }
        };

        let c = self.tables.structures.get_constant(index);
        let (result_type, can_fail, primitive) = match &c.value.value.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(v) => {
                if Self::use_enum_repr_for_constants(&table) && !c.is_helper_duplicate {
                    let repr_bits = v.repr_bits();
                    let is_signed = v.is_signed();
                    let target_type_hint = target_type_hint.filter(|target_type_hint| {
                        !(target_type_hint.bits < repr_bits
                            || is_signed && !target_type_hint.signed
                            || (target_type_hint.bits == repr_bits
                                && target_type_hint.signed != is_signed))
                    });

                    let result_type = match target_type_hint {
                        Some(target_type_hint) => target_type_hint,
                        None => match table.resolved_base {
                            Some(base_type) => base_type,
                            None => self.determine_compiletime_const_expr_min_type(&c.value)?,
                        },
                    };

                    name += &Self::camelize(&self.format_const_member_name(index));
                    name += " as ";
                    name += Self::predefined_type_to_rust(result_type);
                    (result_type, false, false)
                } else {
                    name += &self.format_const_member_name(index).to_ascii_uppercase();
                    let result_type = match table.resolved_base {
                        Some(base_type) => base_type,
                        None => self.determine_compiletime_const_expr_min_type(&c.value)?,
                    };
                    (result_type, false, true)
                }
            }
            ExprValue::RuntimeConstant(_) => {
                name += &self.format_const_member_name(index).to_ascii_lowercase();
                name += "(limits)";
                let result_type = match table.resolved_base {
                    Some(base_type) => base_type,
                    None => self.determine_expr_min_type(&c.value, &mut |_, _| unreachable!())?,
                };
                (result_type, true, true)
            }
            _ => unreachable!(),
        };

        Ok((name, result_type, can_fail, primitive))
    }

    pub(super) fn format_error_return<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        context: Option<StructuresPartTablesIndex>,
        error_rc: StructuresPartTablesConstantIndex,
    ) -> Result<(), io::Error> {
        // The TCG's TPM_RC constants have a base type of uint32_t.
        let error_rc_type = PredefinedTypes::find_type_with_repr(32, false).unwrap();

        let c = self.tables.structures.get_constant(error_rc);
        let e = ExprResolvedId::Constant(error_rc);
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
        let e = self.format_expr_for_type(
            out,
            &e,
            error_rc_type,
            "limits",
            context,
            &|_, _| unreachable!(),
            &|out| writeln!(out, "return Err(TpmErr::InternalErr);"),
        )?;
        writeln!(out, "return Err(TpmErr::Rc({}));", e)?;
        Ok(())
    }

    pub(super) fn gen_constants<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        index: StructuresPartTablesConstantsIndex,
        enable_enum_transmute: bool,
    ) -> Result<(), io::Error> {
        let table = self.tables.structures.get_constants(index);

        let mut table_deps = table
            .closure_deps
            .collect_config_deps(ClosureDepsFlags::all());
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            let entry_deps = entry
                .closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
            table_deps.merge_from(&entry_deps);
        }

        if table_deps.is_empty() {
            return Ok(());
        }

        writeln!(out)?;
        if let Some(src_ref) = &table.info.src_ref {
            writeln!(out, "// {}, {} constants", src_ref, &table.name)?;
        } else {
            writeln!(out, "// {} constants", &table.name)?;
        }
        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }

        let mut need_impl = false;
        let table_is_public = table
            .closure_deps
            .any(ClosureDepsFlags::PUBLIC_DEFINITION | ClosureDepsFlags::EXTERN_MAX_SIZE);
        let use_enum_repr = Self::use_enum_repr_for_constants(&table);
        if !table
            .entries
            .iter()
            .any(|e| e.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION))
        {
            writeln!(out, "#[derive(Clone, Copy, Debug)]")?;
            if table_is_public {
                write!(out, "pub ")?
            }
            writeln!(out, "struct {} {{}}", Self::camelize(&table.name))?;
        } else if use_enum_repr {
            let base_type = table.resolved_base.unwrap();
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;

            // One cannot have a 'repr()' attribute on empty enums.  If the enum is not
            // unconditionally non-empty, wrap it in a cfg_attr().
            let mut any_deps = ConfigDepsDisjunction::empty();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let mut deps = entry
                    .closure_deps
                    .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
                deps.factor_by_common_of(&table_deps);
                any_deps.merge_from(&deps);
            }
            if any_deps.is_unconditional_true() {
                writeln!(out, "#[repr({})]", Self::predefined_type_to_rust(base_type))?;
            } else {
                writeln!(
                    out,
                    "#[cfg_attr({}, repr({}))]",
                    Self::format_deps(&any_deps),
                    Self::predefined_type_to_rust(base_type)
                )?;
            }

            if table_is_public {
                write!(out, "pub ")?;
            }
            writeln!(out, "enum {} {{", Self::camelize(&table.name))?;
            let mut iout = out.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let mut deps = entry
                    .closure_deps
                    .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
                deps.factor_by_common_of(&table_deps);
                if deps.is_empty() {
                    continue;
                }

                if entry.is_helper_duplicate {
                    need_impl = true;
                    continue;
                }

                match entry.value.value.as_ref().unwrap() {
                    ExprValue::CompiletimeConstant(_) => (),
                    _ => unreachable!(),
                };

                if !deps.is_implied_by(&table_deps) {
                    writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&deps))?;
                }

                let name =
                    self.format_const_member_name(StructuresPartTablesConstantIndex(index, j));
                let (e, _) = self
                    .format_compiletime_const_expr_for_type(
                        &entry.value,
                        base_type,
                        "limits",
                        Some(StructuresPartTablesIndex::Constants(index)),
                    )
                    .map_err(|_| {
                        eprintln!(
                            "error: {}: {}: integer overflow in expression",
                            &table.name, &entry.name
                        );
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?;

                if table_is_public && !entry.closure_deps.any(ClosureDepsFlags::PUBLIC_DEFINITION) {
                    write!(&mut iout, "pub(self) ")?;
                }
                writeln!(&mut iout, "{} = {},", Self::camelize(&name), e)?;
            }
            writeln!(out, "}}")?;
        } else {
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;
            if table_is_public {
                write!(out, "pub ")?;
            }
            writeln!(out, "struct {} {{", Self::camelize(&table.name))?;
            if table
                .closure_deps
                .any(ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL)
            {
                let base_type = table.resolved_base.unwrap();
                let mut iout = out.make_indent();
                writeln!(
                    &mut iout,
                    "pub value: {},",
                    Self::predefined_type_to_rust(base_type)
                )?;
            }
            writeln!(out, "}}")?;

            for entry in table.entries.iter() {
                if entry.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
                    need_impl = true;
                    break;
                }
            }
        }

        need_impl |= table.closure_deps.any(
            ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                | ClosureDepsFlags::ANY_SIZE
                | ClosureDepsFlags::ANY_MAX_SIZE,
        );

        if need_impl {
            writeln!(out)?;
            if !table_deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
            }
            writeln!(out, "impl {} {{", Self::camelize(&table.name))?;
        }
        let mut iout = out.make_indent();
        let mut last_was_fn = false;
        let mut first = true;
        for j in 0..table.entries.len() {
            let entry = &table.entries[j];
            let mut deps = entry
                .closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
            deps.factor_by_common_of(&table_deps);
            if deps.is_empty() {
                continue;
            }
            match entry.value.value.as_ref().unwrap() {
                ExprValue::RuntimeConstant(_) => {
                    let base_type = match table.resolved_base {
                        Some(base_type) => base_type,
                        None => self
                            .determine_expr_min_type(&entry.value, &mut |_, _| unreachable!())
                            .map_err(|_| {
                                eprintln!(
                                    "error: table {}: could not determine type for constant {}",
                                    &table.name, &entry.name
                                );
                                io::Error::from(io::ErrorKind::InvalidData)
                            })?,
                    };

                    if !first {
                        writeln!(iout)?;
                    }
                    last_was_fn = true;

                    if !deps.is_implied_by(&table_deps) {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&deps))?;
                    }

                    if entry.closure_deps.any(ClosureDepsFlags::PUBLIC_DEFINITION) {
                        write!(&mut iout, "pub ")?;
                    }

                    let name =
                        self.format_const_member_name(StructuresPartTablesConstantIndex(index, j));
                    writeln!(
                        &mut iout,
                        "fn {}(limits: &TpmLimits) -> Result<{}, ()> {{",
                        &name.to_ascii_lowercase(),
                        Self::predefined_type_to_rust(base_type)
                    )?;

                    let mut iiout = iout.make_indent();
                    match self.format_expr_for_type(
                        &mut iiout,
                        &entry.value,
                        base_type,
                        "limits",
                        Some(StructuresPartTablesIndex::Constants(index)),
                        &|_j, _type_hint| {
                            unreachable!();
                        },
                        &|out| writeln!(out, "return Err(());"),
                    ) {
                        Ok(s) => {
                            writeln!(&mut iiout, "Ok({})", s)?;
                        }
                        Err(_) => {
                            eprintln!(
                                "error: {}: {}: failed to format expression",
                                &table.name, &entry.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    };
                    writeln!(&mut iout, "}}")?;
                }
                ExprValue::CompiletimeConstant(_) => {
                    if use_enum_repr && !entry.is_helper_duplicate {
                        continue;
                    }

                    let base_type = match table.resolved_base {
                        Some(base_type) => base_type,
                        None => self
                            .determine_compiletime_const_expr_min_type(&entry.value)
                            .map_err(|_| {
                                eprintln!(
                                    "error: table {}: could not determine type for constant {}",
                                    &table.name, &entry.name
                                );
                                io::Error::from(io::ErrorKind::InvalidData)
                            })?,
                    };

                    if last_was_fn {
                        writeln!(iout)?;
                    }
                    last_was_fn = false;

                    if !deps.is_implied_by(&table_deps) {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&deps))?;
                    }

                    if entry.closure_deps.any(ClosureDepsFlags::PUBLIC_DEFINITION) {
                        write!(&mut iout, "pub ")?;
                    }
                    let name =
                        self.format_const_member_name(StructuresPartTablesConstantIndex(index, j));
                    let (e, _) = self
                        .format_compiletime_const_expr_for_type(
                            &entry.value,
                            base_type,
                            "limits",
                            Some(StructuresPartTablesIndex::Constants(index)),
                        )
                        .map_err(|_| {
                            eprintln!(
                                "error: {}: {}: integer overflow in expression",
                                &table.name, &entry.name
                            );
                            io::Error::from(io::ErrorKind::InvalidData)
                        })?;

                    writeln!(
                        &mut iout,
                        "const {}: {} = {};",
                        name,
                        Self::predefined_type_to_rust(base_type),
                        e
                    )?;
                }
                _ => unreachable!(),
            };
            first = false;
        }

        if table
            .closure_deps
            .any(ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE)
        {
            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

            let mut marshalled_size_deps = table
                .closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE);
            marshalled_size_deps.factor_by_common_of(&table_deps);
            let pub_spec = if table
                .closure_deps
                .any(ClosureDepsFlags::EXTERN_SIZE | ClosureDepsFlags::EXTERN_MAX_SIZE)
            {
                "pub "
            } else {
                ""
            };

            if !marshalled_size_deps.is_implied_by(&table_deps) {
                writeln!(
                    &mut iout,
                    "#[cfg({})]",
                    Self::format_deps(&marshalled_size_deps)
                )?;
            }

            let size_type = PredefinedTypes::find_type_with_repr(16, false).unwrap();
            writeln!(
                &mut iout,
                "{}const fn marshalled_size() -> {} {{",
                pub_spec,
                Self::predefined_type_to_rust(size_type)
            )?;
            let mut iiout = iout.make_indent();
            writeln!(
                &mut iiout,
                "mem::size_of::<{}>() as {}",
                Self::predefined_type_to_rust(table.resolved_base.unwrap()),
                Self::predefined_type_to_rust(size_type)
            )?;
            writeln!(&mut iout, "}}")?;
        }

        if table.closure_deps.any(ClosureDepsFlags::ANY_MARSHAL) {
            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

            let mut marshal_deps = table
                .closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_MARSHAL);
            marshal_deps.factor_by_common_of(&table_deps);
            if !marshal_deps.is_implied_by(&table_deps) {
                writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&marshal_deps))?;
            }

            let pub_spec = if table.closure_deps.any(ClosureDepsFlags::EXTERN_MARSHAL) {
                "pub "
            } else {
                ""
            };
            writeln!(
                &mut iout,
                "{}fn marshal<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], TpmErr> {{",
                pub_spec
            )?;
            let mut iiout = iout.make_indent();
            let base_type = table.resolved_base.unwrap();
            if use_enum_repr {
                writeln!(
                    &mut iiout,
                    "marshal_{}(buf, *self as {})",
                    Self::predefined_type_to_rust(base_type),
                    Self::predefined_type_to_rust(base_type)
                )?;
            } else {
                writeln!(
                    &mut iiout,
                    "marshal_{}(buf, self.value)",
                    Self::predefined_type_to_rust(base_type)
                )?;
            }
            writeln!(&mut iout, "}}")?;
        }

        if table.closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) {
            if !first {
                writeln!(&mut iout)?;
            }

            let mut unmarshal_deps = table
                .closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_UNMARSHAL);
            unmarshal_deps.factor_by_common_of(&table_deps);
            if !unmarshal_deps.is_implied_by(&table_deps) {
                writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&unmarshal_deps))?;
            }

            let pub_spec = if table.closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL) {
                "pub "
            } else {
                ""
            };
            let need_limits = !Self::constants_are_compiletime_const(&table);
            let limits_arg = if need_limits {
                ", limits: &TpmLimits"
            } else {
                ""
            };
            writeln!(
                &mut iout,
                "{}fn unmarshal<'a>(buf: &'a [u8]{}) -> Result<(&'a [u8], Self), TpmErr> {{",
                pub_spec, limits_arg
            )?;
            let mut iiout = iout.make_indent();
            let base_type = table.resolved_base.unwrap();
            writeln!(
                &mut iiout,
                "let (buf, value) = unmarshal_{}(buf)?;",
                Self::predefined_type_to_rust(base_type)
            )?;

            if use_enum_repr {
                writeln!(&mut iiout, "let result = Self::try_from(value)?;")?;
                writeln!(&mut iiout, "Ok((buf, result))")?;
            } else {
                let error_rc = table.resolved_error_rc.unwrap_or_else(|| {
                    self.tables
                        .structures
                        .lookup_constant("TPM_RC_VALUE")
                        .unwrap()
                });

                for j in 0..table.entries.len() {
                    writeln!(&mut iiout)?;
                    let entry = &table.entries[j];
                    if entry.is_helper_duplicate {
                        continue;
                    }

                    let mut deps = entry
                        .closure_deps
                        .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
                    deps.factor_by_common_of(&table_deps);
                    deps.factor_by_common_of(&unmarshal_deps);
                    assert!(!deps.is_empty());

                    let mut iiiout = if !deps.is_implied_by(&unmarshal_deps) {
                        writeln!(&mut iiout, "if cfg!({}) {{", Self::format_deps(&deps))?;
                        iiout.make_indent()
                    } else {
                        iiout.make_same_indent()
                    };

                    let e = ExprResolvedId::Constant(StructuresPartTablesConstantIndex(index, j));
                    let e = ExprId {
                        name: entry.name.clone(),
                        resolved: Some(e),
                    };
                    let e = ExprOp::Id(e);
                    let e = Expr {
                        op: e,
                        rdepth: 0,
                        value: Some(entry.value.value.as_ref().unwrap().clone()),
                    };
                    let base_type = &table.resolved_base;
                    let e = self
                        .format_expr_for_type(
                            &mut iiiout,
                            &e,
                            base_type.unwrap(),
                            "limits",
                            Some(StructuresPartTablesIndex::Constants(index)),
                            &|_, _| unreachable!(),
                            &|out| writeln!(out, "return Err(TpmErr::InternalErr);"),
                        )
                        .map_err(|e| match e.kind() {
                            io::ErrorKind::InvalidData => {
                                eprintln!("error: {}: integer overflow in expression", &table.name);
                                io::Error::from(io::ErrorKind::InvalidData)
                            }
                            k => io::Error::from(k),
                        })?;
                    writeln!(&mut iiiout, "if {} == value {{", e)?;
                    let mut iiiiout = iiiout.make_indent();
                    writeln!(&mut iiiiout, "return Ok((buf, Self{{value}}));")?;
                    writeln!(&mut iiiout, "}}")?;
                    if !deps.is_implied_by(&unmarshal_deps) {
                        writeln!(&mut iiout, "}}")?;
                    }
                }

                writeln!(&mut iiout)?;
                self.format_error_return(
                    &mut iiout,
                    Some(StructuresPartTablesIndex::Constants(index)),
                    error_rc,
                )?;
            }
            writeln!(&mut iout, "}}")?;
        }

        if need_impl {
            writeln!(out, "}}")?;
        }

        if use_enum_repr && table.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
            writeln!(out)?;
            let definition_deps = table
                .closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
            if !definition_deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&definition_deps))?;
            }
            let base_type = table.resolved_base.unwrap();
            writeln!(
                out,
                "impl convert::TryFrom<{}> for {} {{",
                Self::predefined_type_to_rust(base_type),
                Self::camelize(&table.name)
            )?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "type Error = TpmErr;")?;
            writeln!(&mut iout)?;
            writeln!(
                &mut iout,
                "fn try_from(value: {}) -> Result<Self, TpmErr> {{",
                Self::predefined_type_to_rust(base_type)
            )?;
            let mut iiout = iout.make_indent();

            let error_rc = &table.resolved_error_rc.unwrap_or_else(|| {
                self.tables
                    .structures
                    .lookup_constant("TPM_RC_VALUE")
                    .unwrap()
            });

            if enable_enum_transmute {
                writeln!(&mut iiout, "match value {{")?;
            } else {
                writeln!(&mut iiout, "let result = match value {{")?;
            }
            let mut iiiout = iiout.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                if entry.is_helper_duplicate {
                    continue;
                }

                let mut deps = entry
                    .closure_deps
                    .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
                deps.factor_by_common_of(&definition_deps);
                assert!(!deps.is_empty());

                match entry.value.value.as_ref().unwrap() {
                    ExprValue::CompiletimeConstant(_) => (),
                    _ => unreachable!(),
                };
                if !deps.is_implied_by(&definition_deps) {
                    writeln!(&mut iiiout, "#[cfg({})]", Self::format_deps(&deps))?;
                }

                let name =
                    self.format_const_member_name(StructuresPartTablesConstantIndex(index, j));
                let name = Self::camelize(&name);
                if enable_enum_transmute {
                    writeln!(
                        &mut iiiout,
                        "value if value == Self::{} as {} => (),",
                        &name,
                        Self::predefined_type_to_rust(base_type)
                    )?;
                } else {
                    writeln!(
                        &mut iiiout,
                        "value if value == Self::{} as {} => Self::{},",
                        &name,
                        Self::predefined_type_to_rust(base_type),
                        &name
                    )?;
                }
            }

            writeln!(&mut iiiout, "_ => {{")?;
            self.format_error_return(
                &mut iiiout.make_indent(),
                Some(StructuresPartTablesIndex::Constants(index)),
                *error_rc,
            )?;
            writeln!(&mut iiiout, "}},")?;

            writeln!(&mut iiout, "}};")?;
            writeln!(&mut iiout)?;
            if enable_enum_transmute {
                writeln!(
                    &mut iiout,
                    "let result = unsafe{{mem::transmute::<{}, Self>(value)}};",
                    Self::predefined_type_to_rust(base_type)
                )?;
            }
            writeln!(&mut iiout, "Ok(result)")?;
            writeln!(&mut iout, "}}")?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }
}
