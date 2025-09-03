// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;
use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use structures::deps::ConfigDepsDisjunction;
use structures::expr::{Expr, ExprValue};
use structures::predefined::PredefinedTypes;
use structures::table_common::ClosureDepsFlags;
use structures::tables::StructuresPartTablesTypeIndex;
use structures::type_table::TypeTable;
use structures::value_range::ValueRange;

use super::{Tpm2InterfaceRustCodeGenerator, code_writer};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn format_enum_type_member_name(&self, table: &TypeTable, j: usize) -> String {
        assert!(table.enum_like);
        let constant_index = table.get_enum_type_member_constant(j);
        let constant_name = &self.tables.structures.get_constant(constant_index).name;

        let mut prefix_end = self.strip_constant_table_prefix(constant_index);
        // Re-add prefix parts until the identifier is unique.
        let entry_name_parts = constant_name.split('_').collect::<Vec<&str>>();
        'others: while prefix_end > 0 {
            let entry_name_tail_parts = &entry_name_parts[prefix_end..];
            for k in 0..table.entries.len() {
                if k == j {
                    continue;
                }

                let other_constant_index = table.get_enum_type_member_constant(k);
                let other_constant_name = &self
                    .tables
                    .structures
                    .get_constant(other_constant_index)
                    .name;
                let other_prefix_end = self.strip_constant_table_prefix(other_constant_index);
                let other_name_parts = other_constant_name.split('_').collect::<Vec<&str>>();

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

        entry_name_parts[prefix_end..].join("_")
    }

    pub(super) fn type_values_are_compiletime_const(table: &TypeTable) -> bool {
        for entry in &table.entries {
            match &entry.values {
                ValueRange::Discrete(values) => {
                    for v in values.iter() {
                        match v.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(_) => (),
                            _ => {
                                assert!(!table.enum_like);
                                return false;
                            }
                        };
                    }
                }
                ValueRange::Range {
                    min_value,
                    max_value,
                } => {
                    if let Some(min_value) = min_value {
                        match min_value.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(_) => (),
                            _ => {
                                assert!(!table.enum_like);
                                return false;
                            }
                        };
                    }
                    if let Some(max_value) = max_value {
                        match max_value.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(_) => (),
                            _ => {
                                assert!(!table.enum_like);
                                return false;
                            }
                        };
                    }
                }
            };
        }
        true
    }

    fn use_enum_repr_for_type(table: &TypeTable) -> bool {
        if table.enum_like {
            debug_assert!(Self::type_values_are_compiletime_const(table));
        }

        table.enum_like
    }

    fn format_type_range_bound_cmp_op<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &TypeTable,
        bound: &Expr,
        op: &'static str,
    ) -> Result<String, io::Error> {
        let base_type = table.underlying_type.unwrap();
        let (mut e, t, p) = self
            .format_expr(
                out,
                bound,
                Some(base_type),
                "limits",
                None,
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
        let common_type = PredefinedTypes::find_common_type(base_type, t).ok_or_else(|| {
            eprintln!("error: {}: integer overflow in expression", &table.name);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        if common_type != t {
            if !p {
                e = "(".to_owned() + &e + ")";
            }
            e = e + " as " + Self::predefined_type_to_rust(common_type);
        }

        let value = if common_type != base_type {
            let value = "value".to_owned() + " as " + Self::predefined_type_to_rust(common_type);
            borrow::Cow::Owned(value)
        } else {
            borrow::Cow::Borrowed("value")
        };

        Ok(format!("{} {} {}", value, op, e))
    }

    fn _gen_type<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &TypeTable,
        conditional: bool,
        enable_enum_transmute: bool,
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
            write!(out, "// {}, {} type", src_ref, &table.name)?;
        } else {
            write!(out, "// {} type", &table.name)?;
        }
        let table_name = if !table.conditional {
            writeln!(out)?;
            borrow::Cow::Borrowed(&table.name)
        } else if !conditional {
            writeln!(out, " (without conditional values)")?;
            borrow::Cow::Borrowed(&table.name)
        } else {
            writeln!(out, " (with conditional values)")?;
            borrow::Cow::Owned(table.name.to_owned() + "_W_C_V")
        };

        let base_type = table.underlying_type.unwrap();
        let use_enum_repr = Self::use_enum_repr_for_type(table);

        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }

        let table_is_public = table_closure_deps
            .any(ClosureDepsFlags::PUBLIC_DEFINITION | ClosureDepsFlags::EXTERN_MAX_SIZE);
        if !table_closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
            writeln!(out, "#[derive(Clone, Copy, Debug)]")?;
            if table_is_public {
                write!(out, "pub ")?
            }
            writeln!(out, "struct {} {{}}", Self::camelize(&table_name))?;
        } else if use_enum_repr {
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;

            // One cannot have a 'repr()' attribute on empty enums.  If the enum is not
            // unconditionally non-empty, wrap it in a cfg_attr().
            let mut any_deps = ConfigDepsDisjunction::empty();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                if !conditional && entry.conditional {
                    continue;
                }
                let deps = entry.deps.factor_by_common_of(&table_deps);
                any_deps.insert(deps);
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
                write!(out, "pub ")?
            }
            writeln!(out, "enum {} {{", Self::camelize(&table_name))?;

            let mut iout = out.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];

                if entry.conditional && !conditional {
                    continue;
                }

                let deps = entry.deps.factor_by_common_of(&table_deps);
                if !deps.is_unconditional_true() {
                    writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                }
                let name = Self::camelize(&self.format_enum_type_member_name(table, j));
                let value = match &entry.values {
                    ValueRange::Discrete(values) => {
                        assert_eq!(values.len(), 1);
                        &values[0]
                    }
                    _ => unreachable!(),
                };
                let (e, _) = self
                    .format_compiletime_const_expr_for_type(value, base_type, "limits", None)
                    .map_err(|_| {
                        eprintln!("error: {}: integer overflow in expression", &table.name);
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?;
                writeln!(&mut iout, "{} = {},", name, e)?;
            }

            writeln!(out, "}}")?
        } else {
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;
            if table_is_public {
                write!(out, "pub ")?
            }
            writeln!(out, "struct {} {{", Self::camelize(&table_name))?;
            let mut iout = out.make_indent();
            writeln!(
                &mut iout,
                "pub value: {},",
                Self::predefined_type_to_rust(base_type)
            )?;
            writeln!(out, "}}")?;
        }

        let need_impl = table_closure_deps.any(
            ClosureDepsFlags::ANY_UNMARSHAL_OR_MARSHAL
                | ClosureDepsFlags::ANY_SIZE
                | ClosureDepsFlags::ANY_MAX_SIZE,
        );

        if need_impl {
            writeln!(out)?;
            if !table_deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
            }
            writeln!(out, "impl {} {{", Self::camelize(&table_name))?;
        }
        let mut first = true;
        let mut iout = out.make_indent();
        if table_closure_deps.any(ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE) {
            first = false;

            let mut marshalled_size_deps = table_closure_deps
                .collect_config_deps(ClosureDepsFlags::ANY_SIZE | ClosureDepsFlags::ANY_MAX_SIZE);
            marshalled_size_deps.factor_by_common_of(&table_deps);
            let pub_spec = if table_closure_deps
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
                Self::predefined_type_to_rust(base_type),
                Self::predefined_type_to_rust(size_type)
            )?;
            writeln!(&mut iout, "}}")?;
        }

        if table_closure_deps.any(ClosureDepsFlags::ANY_MARSHAL) {
            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

            let mut marshal_deps =
                table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_MARSHAL);
            marshal_deps.factor_by_common_of(&table_deps);
            if !marshal_deps.is_implied_by(&table_deps) {
                writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&marshal_deps))?;
            }

            let pub_spec = if table_closure_deps.any(ClosureDepsFlags::EXTERN_MARSHAL) {
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

        if table_closure_deps.any(ClosureDepsFlags::ANY_UNMARSHAL) {
            if !first {
                writeln!(&mut iout)?;
            }

            let mut unmarshal_deps =
                table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_UNMARSHAL);
            unmarshal_deps.factor_by_common_of(&table_deps);
            if !unmarshal_deps.is_implied_by(&table_deps) {
                writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&unmarshal_deps))?;
            }

            let need_limits = !Self::type_values_are_compiletime_const(table);
            let limits_arg = if need_limits {
                ", limits: &TpmLimits"
            } else {
                ""
            };
            let pub_spec = if table_closure_deps.any(ClosureDepsFlags::EXTERN_UNMARSHAL) {
                "pub "
            } else {
                ""
            };
            writeln!(
                &mut iout,
                "{}fn unmarshal<'a>(buf: &'a [u8]{}) -> Result<(&'a [u8], Self), TpmErr> {{",
                pub_spec, limits_arg
            )?;
            let mut iiout = iout.make_indent();
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

                for entry in table.entries.iter() {
                    if entry.conditional && !conditional {
                        continue;
                    }

                    let deps = &entry.deps;
                    let deps = deps.factor_by_common_of(&table_deps);
                    let deps = deps.factor_by_common_of(&unmarshal_deps);

                    let mut iiiout = if !deps.is_unconditional_true() {
                        writeln!(
                            &mut iiout,
                            "if cfg!({}) {{",
                            Self::format_dep_conjunction(&deps)
                        )?;
                        iiout.make_indent()
                    } else {
                        iiout.make_same_indent()
                    };

                    match &entry.values {
                        ValueRange::Discrete(values) => {
                            for v in values.iter() {
                                writeln!(&mut iiiout)?;
                                let cond = self.format_type_range_bound_cmp_op(
                                    &mut iiiout,
                                    table,
                                    v,
                                    "==",
                                )?;
                                writeln!(&mut iiiout, "if {} {{", cond)?;
                                writeln!(
                                    &mut iiiout.make_indent(),
                                    "return Ok((buf, Self{{value}}))"
                                )?;
                                writeln!(&mut iiiout, "}}")?;
                            }
                        }
                        ValueRange::Range {
                            min_value,
                            max_value,
                        } => {
                            writeln!(&mut iiiout)?;
                            match min_value {
                                Some(min_value) => {
                                    let cond = self.format_type_range_bound_cmp_op(
                                        &mut iiiout,
                                        table,
                                        min_value,
                                        ">=",
                                    )?;
                                    writeln!(&mut iiiout, "if {} {{", cond)?;
                                    match max_value {
                                        Some(max_value) => {
                                            let mut iiiiout = iiiout.make_indent();
                                            let cond = self.format_type_range_bound_cmp_op(
                                                &mut iiiiout,
                                                table,
                                                max_value,
                                                "<=",
                                            )?;
                                            writeln!(&mut iiiiout, "if {} {{", cond)?;
                                            writeln!(
                                                &mut iiiiout.make_indent(),
                                                "return Ok((buf, Self{{value}}))"
                                            )?;
                                            writeln!(&mut iiiiout, "}}")?;
                                        }
                                        None => {
                                            writeln!(
                                                &mut iiiout.make_indent(),
                                                "return Ok((buf, Self{{value}}))"
                                            )?;
                                        }
                                    };
                                    writeln!(&mut iiiout, "}}")?;
                                }
                                None => {
                                    match max_value {
                                        Some(max_value) => {
                                            let cond = self.format_type_range_bound_cmp_op(
                                                &mut iiiout,
                                                table,
                                                max_value,
                                                "<=",
                                            )?;
                                            writeln!(&mut iiiout, "if {} {{", cond)?;
                                            writeln!(
                                                &mut iiiout.make_indent(),
                                                "return Ok((buf, Self{{value}}))"
                                            )?;
                                            writeln!(&mut iiiout, "}}")?;
                                        }
                                        None => {
                                            // Unspecified lower + upper bounds means everything is to be
                                            // accepted.
                                            writeln!(
                                                &mut iiiout,
                                                "return Ok((buf, Self{{value}}))"
                                            )?;
                                        }
                                    };
                                }
                            };
                        }
                    };

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iiout, "}}")?;
                    }
                }

                writeln!(&mut iiout)?;
                self.format_error_return(&mut iiout, None, error_rc)?;
            }
            writeln!(&mut iout, "}}")?;
        }

        if need_impl {
            writeln!(out, "}}")?;
        }
        if use_enum_repr && table_closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
            writeln!(out)?;
            let definition_deps =
                table_closure_deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
            if !definition_deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&definition_deps))?;
            }

            writeln!(
                out,
                "impl convert::TryFrom<{}> for {} {{",
                Self::predefined_type_to_rust(base_type),
                Self::camelize(&table_name)
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

            let error_rc = table.resolved_error_rc.unwrap_or_else(|| {
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

                if entry.conditional && !conditional {
                    continue;
                }

                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&definition_deps);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let name = self.format_enum_type_member_name(table, j);
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
            self.format_error_return(&mut iiiout.make_indent(), None, error_rc)?;
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

    fn _gen_type_non_cond_cond_conversions<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &TypeTable,
        enable_enum_transmute: bool,
    ) -> Result<(), io::Error> {
        if !table.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION)
            || !table
                .closure_deps_conditional
                .any(ClosureDepsFlags::ANY_DEFINITION)
        {
            return Ok(());
        }

        let table_name_noncond = Self::camelize(&table.name);
        let table_name_cond = Self::camelize(&(table.name.clone() + "_W_C_V"));

        writeln!(out)?;
        let config_deps_noncond = table
            .closure_deps
            .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
        let mut config_deps_cond = table
            .closure_deps_conditional
            .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
        if config_deps_cond.is_implied_by(&config_deps_noncond) {
            if !config_deps_noncond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_noncond))?;
            }
        } else if config_deps_noncond.is_implied_by(&config_deps_cond) {
            if !config_deps_cond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_cond))?;
            }
        } else {
            config_deps_cond.factor_by_common_of(&config_deps_noncond);
            writeln!(
                out,
                "#[cfg(and({}, {}))]",
                Self::format_deps(&config_deps_noncond),
                Self::format_deps(&config_deps_cond)
            )?;
        }

        writeln!(
            out,
            "impl convert::From<{}> for {} {{",
            &table_name_noncond, &table_name_cond
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn from(value: {}) -> Self {{",
            table_name_noncond
        )?;
        let mut iiout = iout.make_indent();
        if enable_enum_transmute {
            writeln!(
                &mut iiout,
                "unsafe {{ mem::transmute::<{}, Self>(value) }}",
                table_name_noncond
            )?;
        } else {
            writeln!(&mut iiout, "match value {{")?;
            let mut iiiout = iiout.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                if entry.conditional {
                    continue;
                }

                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&config_deps_noncond);
                let deps = deps.factor_by_common_of(&config_deps_cond);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let name = self.format_enum_type_member_name(table, j);
                let name = Self::camelize(&name);
                writeln!(
                    &mut iiiout,
                    "{}::{} => Self::{},",
                    table_name_noncond, &name, &name
                )?;
            }
            writeln!(&mut iiout, "}}")?;
        }
        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        writeln!(out)?;
        if config_deps_cond.is_implied_by(&config_deps_noncond) {
            if !config_deps_noncond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_noncond))?;
            }
        } else if config_deps_noncond.is_implied_by(&config_deps_cond) {
            if !config_deps_cond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_cond))?;
            }
        } else {
            writeln!(
                out,
                "#[cfg(and({}, {}))]",
                Self::format_deps(&config_deps_noncond),
                Self::format_deps(&config_deps_cond)
            )?;
        }

        writeln!(
            out,
            "impl convert::TryFrom<{}> for {} {{",
            &table_name_cond, &table_name_noncond
        )?;
        let mut iout = out.make_indent();
        writeln!(&mut iout, "type Error = TpmErr;")?;
        writeln!(&mut iout)?;
        writeln!(
            &mut iout,
            "fn try_from(value: {}) -> Result<Self, TpmErr> {{",
            table_name_cond
        )?;
        let mut iiout = iout.make_indent();
        let error_rc = table.resolved_error_rc.unwrap_or_else(|| {
            self.tables
                .structures
                .lookup_constant("TPM_RC_VALUE")
                .unwrap()
        });
        if enable_enum_transmute {
            writeln!(&mut iiout, "match value {{")?;
            let mut iiiout = iiout.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                if !entry.conditional {
                    continue;
                }
                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&config_deps_noncond);
                let deps = deps.factor_by_common_of(&config_deps_cond);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let name = self.format_enum_type_member_name(table, j);
                let name = Self::camelize(&name);
                if entry.conditional {
                    writeln!(&mut iiiout, "{}::{} => {{", table_name_cond, &name)?;
                    self.format_error_return(&mut iiiout.make_indent(), None, error_rc)?;
                    writeln!(&mut iiiout, "}},")?;
                }
            }
            writeln!(&mut iiiout, "_ => (),")?;
            writeln!(&mut iiout, "}};")?;
            writeln!(&mut iiout)?;
            writeln!(
                &mut iiout,
                "let result = unsafe {{ mem::transmute::<{}, Self>(value) }};",
                table_name_cond
            )?;
            writeln!(&mut iiout, "Ok(result)")?;
        } else {
            writeln!(&mut iiout, "let result = match value {{")?;
            let mut iiiout = iiout.make_indent();
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let deps = &entry.deps;
                let deps = deps.factor_by_common_of(&config_deps_noncond);
                let deps = deps.factor_by_common_of(&config_deps_cond);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let name = self.format_enum_type_member_name(table, j);
                let name = Self::camelize(&name);
                if entry.conditional {
                    writeln!(&mut iiiout, "{}::{} => {{", table_name_cond, &name)?;
                    self.format_error_return(&mut iiiout.make_indent(), None, error_rc)?;
                    writeln!(&mut iiiout, "}},")?;
                } else {
                    writeln!(
                        &mut iiiout,
                        "{}::{} => Self::{},",
                        table_name_cond, &name, &name
                    )?;
                }
            }
            writeln!(&mut iiout, "}};")?;
            writeln!(&mut iiout, "Ok(result)")?;
        }

        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        // Not strictly a conversion, but provide PartialEq implementations
        // for the cond <-> non-cond comparison as well.
        writeln!(out)?;
        if config_deps_cond.is_implied_by(&config_deps_noncond) {
            if !config_deps_noncond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_noncond))?;
            }
        } else if config_deps_noncond.is_implied_by(&config_deps_cond) {
            if !config_deps_cond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_cond))?;
            }
        } else {
            writeln!(
                out,
                "#[cfg(and({}, {}))]",
                Self::format_deps(&config_deps_noncond),
                Self::format_deps(&config_deps_cond)
            )?;
        }
        writeln!(
            out,
            "impl cmp::PartialEq<{}> for {} {{",
            &table_name_noncond, &table_name_cond
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn eq(&self, other: &{}) -> bool {{",
            &table_name_noncond
        )?;
        let mut iiout = iout.make_indent();
        let base_type = table.underlying_type.unwrap();
        writeln!(
            &mut iiout,
            "*self as {} == *other as {}",
            Self::predefined_type_to_rust(base_type),
            Self::predefined_type_to_rust(base_type)
        )?;
        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        writeln!(out)?;
        if config_deps_cond.is_implied_by(&config_deps_noncond) {
            if !config_deps_noncond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_noncond))?;
            }
        } else if config_deps_noncond.is_implied_by(&config_deps_cond) {
            if !config_deps_cond.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_deps(&config_deps_cond))?;
            }
        } else {
            writeln!(
                out,
                "#[cfg(and({}, {}))]",
                Self::format_deps(&config_deps_noncond),
                Self::format_deps(&config_deps_cond)
            )?;
        }
        writeln!(
            out,
            "impl cmp::PartialEq<{}> for {} {{",
            &table_name_cond, &table_name_noncond
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn eq(&self, other: &{}) -> bool {{",
            &table_name_cond
        )?;
        writeln!(&mut iout.make_indent(), "other.eq(self)")?;
        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        Ok(())
    }

    pub(super) fn gen_type<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        index: StructuresPartTablesTypeIndex,
        enable_enum_transmute: bool,
    ) -> Result<(), io::Error> {
        let table = self.tables.structures.get_type(index);
        self._gen_type(out, &table, false, enable_enum_transmute)?;
        if table.conditional {
            self._gen_type(out, &table, true, enable_enum_transmute)?;
            if Self::use_enum_repr_for_type(&table) {
                self._gen_type_non_cond_cond_conversions(out, &table, enable_enum_transmute)?;
            }
        }
        Ok(())
    }
}
