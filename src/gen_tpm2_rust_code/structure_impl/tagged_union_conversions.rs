// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use structures::structure_table::{StructureTable, StructureTableEntryResolvedDiscriminantType};
use structures::table_common::{ClosureDeps, ClosureDepsFlags};
use structures::tables::UnionSelectorIterator;

use super::super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn gen_tagged_union_to_discriminant<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        closure_deps: &ClosureDeps,
        tagged_union_name: &str,
        discriminant_member: usize,
        conditional: bool,
        enable_allocator_api: bool,
        enable_enum_transmute: bool,
    ) -> Result<(), io::Error> {
        let discriminant_entry = &table.entries[discriminant_member];
        assert!(discriminant_entry.deps.is_unconditional_true());
        let discriminant =
            Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);

        let tagged_union_name = Self::camelize(tagged_union_name);
        let mut tagged_union_config_deps =
            closure_deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);

        let discriminant_enable_conditional = if discriminant.discriminant_type_enable_conditional {
            true
        } else if discriminant.discriminant_type_conditional {
            conditional
        } else {
            false
        };
        let (discriminant_type_name, mut discriminant_config_deps) =
            match discriminant.resolved_discriminant_type.as_ref().unwrap() {
                StructureTableEntryResolvedDiscriminantType::Constants(i) => {
                    let constants_table = self.tables.structures.get_constants(*i);
                    let discriminant_type_name = Self::camelize(&constants_table.name);
                    (
                        discriminant_type_name,
                        constants_table
                            .closure_deps
                            .collect_config_deps(ClosureDepsFlags::ANY_DEFINITION),
                    )
                }
                StructureTableEntryResolvedDiscriminantType::Type(i) => {
                    let type_table = self.tables.structures.get_type(*i);
                    if discriminant_enable_conditional {
                        let discriminant_type_name = type_table.name.clone() + "_W_C_V";
                        let discriminant_type_name = Self::camelize(&discriminant_type_name);
                        let closure_deps = &type_table.closure_deps_conditional;
                        (
                            discriminant_type_name,
                            closure_deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION),
                        )
                    } else {
                        let discriminant_type_name = Self::camelize(&type_table.name);
                        let closure_deps = &type_table.closure_deps;
                        (
                            discriminant_type_name,
                            closure_deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION),
                        )
                    }
                }
            };

        let contains_array = self.tagged_union_contains_array(table, discriminant);
        let references_inbuf =
            contains_array && self.tagged_union_references_inbuf(table, discriminant);
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

        if tagged_union_config_deps.is_implied_by(&discriminant_config_deps) {
            if !discriminant_config_deps.is_unconditional_true() {
                writeln!(
                    out,
                    "#[cfg({})]",
                    Self::format_deps(&discriminant_config_deps)
                )?;
            }
        } else if discriminant_config_deps.is_implied_by(&tagged_union_config_deps) {
            if !tagged_union_config_deps.is_unconditional_true() {
                writeln!(
                    out,
                    "#[cfg({})]",
                    Self::format_deps(&tagged_union_config_deps)
                )?;
            }
        } else {
            tagged_union_config_deps.factor_by_common_of(&discriminant_config_deps);
            writeln!(
                out,
                "#[cfg(and({}, {}))]",
                Self::format_deps(&discriminant_config_deps),
                Self::format_deps(&tagged_union_config_deps)
            )?;
        }

        writeln!(
            out,
            "impl{} convert::From<&{}{}> for {} {{",
            gen_params_spec.0, tagged_union_name, gen_params_spec.1, discriminant_type_name
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn from(value: &{}{}) -> Self {{",
            tagged_union_name, gen_params_spec.1
        )?;
        let mut iiout = iout.make_indent();
        if enable_enum_transmute {
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
            writeln!(
                &mut iiout,
                "unsafe {{ mem::transmute::<{}, {}>(*(value as * const {}{} as * const {})) }}",
                Self::predefined_type_to_rust(discriminant_base),
                discriminant_type_name,
                &tagged_union_name,
                gen_params_spec.1,
                Self::predefined_type_to_rust(discriminant_base)
            )?;
        } else {
            writeln!(&mut iiout, "match value {{")?;
            let mut iiiout = iiout.make_indent();
            for selector in UnionSelectorIterator::new(
                &self.tables.structures,
                *discriminant.resolved_discriminant_type.as_ref().unwrap(),
                discriminant_enable_conditional,
            ) {
                let deps = selector.config_deps();
                let deps = deps.factor_by_common_of(&tagged_union_config_deps);
                let deps = deps.factor_by_common_of(&discriminant_config_deps);
                if !deps.is_unconditional_true() {
                    writeln!(
                        &mut iiiout,
                        "#[cfg({})]",
                        Self::format_dep_conjunction(&deps)
                    )?;
                }

                let selected_union_members =
                    self.get_structure_selected_union_members(table, discriminant, &selector);
                let enum_member_name = self.format_tagged_union_member_name(&selector);
                let enum_member_name = Self::camelize(&enum_member_name);
                if selected_union_members.is_empty() {
                    writeln!(
                        &mut iiiout,
                        "{}::{} => Self::{},",
                        &tagged_union_name, &enum_member_name, &enum_member_name
                    )?;
                    continue;
                };

                let selected_union_members_match_spec = selected_union_members
                    .iter()
                    .map(|(u, _union_table_index, _selected_member_index)| {
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
                if discriminant.discriminated_union_members.len() == 1 {
                    writeln!(
                        &mut iiiout,
                        "{}::{}({}) => Self::{},",
                        &tagged_union_name,
                        &enum_member_name,
                        selected_union_members_match_spec,
                        &enum_member_name
                    )?;
                } else {
                    writeln!(
                        &mut iiiout,
                        "{}::{}{{{}}} => Self::{},",
                        &tagged_union_name,
                        &enum_member_name,
                        selected_union_members_match_spec,
                        &enum_member_name
                    )?;
                }
            }
            writeln!(&mut iiout, "}}")?;
        }

        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        Ok(())
    }

    pub(super) fn gen_tagged_union_non_cond_cond_conversions<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        table: &StructureTable,
        discriminant_member: usize,
        is_structure_member_repr: bool,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error> {
        let discriminant_entry = &table.entries[discriminant_member];
        assert!(discriminant_entry.deps.is_unconditional_true());
        let discriminant =
            Self::to_structure_discriminant_entry_type(&discriminant_entry.entry_type);

        let (tagged_union_name_noncond, tagged_union_name_cond) = if !is_structure_member_repr {
            (
                Self::camelize(&Self::format_structure_name(table, false)),
                Self::camelize(&Self::format_structure_name(table, true)),
            )
        } else {
            (
                Self::camelize(&Self::format_structure_discriminant_member_enum_name(
                    table,
                    false,
                    discriminant_entry,
                )),
                Self::camelize(&Self::format_structure_discriminant_member_enum_name(
                    table,
                    true,
                    discriminant_entry,
                )),
            )
        };

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

        let contains_array = self.tagged_union_contains_array(table, discriminant);
        let references_inbuf =
            contains_array && self.tagged_union_references_inbuf(table, discriminant);
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
            "impl{} convert::From<{}{}> for {}{} {{",
            gen_params_spec.0,
            &tagged_union_name_noncond,
            gen_params_spec.1,
            tagged_union_name_cond,
            gen_params_spec.1
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn from(value: {}{}) -> Self {{",
            &tagged_union_name_noncond, gen_params_spec.1
        )?;
        let mut iiout = iout.make_indent();
        writeln!(&mut iiout, "match value {{")?;
        let mut iiiout = iiout.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            false,
        ) {
            let deps = &selector.config_deps();
            let deps = deps.factor_by_common_of(&config_deps_noncond);
            let deps = deps.factor_by_common_of(&config_deps_cond);
            if !deps.is_unconditional_true() {
                writeln!(
                    &mut iiiout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&deps)
                )?;
            }

            let selected_union_members =
                self.get_structure_selected_union_members(table, discriminant, &selector);
            let enum_member_name = self.format_tagged_union_member_name(&selector);
            let enum_member_name = Self::camelize(&enum_member_name);
            if selected_union_members.is_empty() {
                writeln!(
                    &mut iiiout,
                    "{}::{} => Self::{},",
                    &tagged_union_name_noncond, &enum_member_name, enum_member_name
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
                    &mut iiiout,
                    "{}::{}({}) => Self::{}({}),",
                    &tagged_union_name_noncond,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                )?;
            } else {
                writeln!(
                    &mut iiiout,
                    "{}::{}{{{}}} => Self::{}{{{}}},",
                    &tagged_union_name_noncond,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                )?;
            }
        }
        writeln!(&mut iiout, "}}")?;
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
            "impl{} convert::TryFrom<{}{}> for {}{} {{",
            gen_params_spec.0,
            &tagged_union_name_cond,
            gen_params_spec.1,
            tagged_union_name_noncond,
            gen_params_spec.1
        )?;
        let mut iout = out.make_indent();
        writeln!(&mut iout, "type Error = TpmErr;")?;
        writeln!(&mut iout)?;
        writeln!(
            &mut iout,
            "fn try_from(value: {}{}) -> Result<Self, TpmErr> {{",
            &tagged_union_name_cond, gen_params_spec.1
        )?;
        let mut iiout = iout.make_indent();
        writeln!(&mut iiout, "let result = match value {{")?;
        let mut iiiout = iiout.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            false,
        ) {
            let deps = &selector.config_deps();
            let deps = deps.factor_by_common_of(&config_deps_noncond);
            let deps = deps.factor_by_common_of(&config_deps_cond);
            if !deps.is_unconditional_true() {
                writeln!(
                    &mut iiiout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&deps)
                )?;
            }

            let selected_union_members =
                self.get_structure_selected_union_members(table, discriminant, &selector);
            let enum_member_name = self.format_tagged_union_member_name(&selector);
            let enum_member_name = Self::camelize(&enum_member_name);
            if selected_union_members.is_empty() {
                writeln!(
                    &mut iiiout,
                    "{}::{} => Self::{},",
                    &tagged_union_name_cond, &enum_member_name, enum_member_name
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
                    &mut iiiout,
                    "{}::{}({}) => Self::{}({}),",
                    &tagged_union_name_cond,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                )?;
            } else {
                writeln!(
                    &mut iiiout,
                    "{}::{}{{{}}} => Self::{}{{{}}},",
                    &tagged_union_name_cond,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                    &enum_member_name,
                    &selected_union_members_match_spec,
                )?;
            }
        }

        let error_rc_value = match discriminant.resolved_discriminant_type.as_ref().unwrap() {
            StructureTableEntryResolvedDiscriminantType::Constants(i) => {
                let constants_table = self.tables.structures.get_constants(*i);
                constants_table.resolved_error_rc
            }
            StructureTableEntryResolvedDiscriminantType::Type(i) => {
                let type_table = self.tables.structures.get_type(*i);
                type_table.resolved_error_rc
            }
        }
        .unwrap_or_else(|| {
            self.tables
                .structures
                .lookup_constant("TPM_RC_VALUE")
                .unwrap()
        });
        writeln!(&mut iiiout, "_ => {{")?;
        self.format_error_return(&mut iiiout.make_indent(), None, error_rc_value)?;
        writeln!(&mut iiiout, "}},")?;

        writeln!(&mut iiout, "}};")?;
        writeln!(&mut iiout)?;
        writeln!(&mut iiout, "Ok(result)")?;
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
            "impl{} cmp::PartialEq<{}{}> for {}{} {{",
            gen_params_spec.0,
            &tagged_union_name_noncond,
            gen_params_spec.1,
            tagged_union_name_cond,
            gen_params_spec.1
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn eq(&self, other: &{}{}) -> bool {{",
            &tagged_union_name_noncond, gen_params_spec.1
        )?;
        let mut iiout = iout.make_indent();
        writeln!(&mut iiout, "match self {{")?;
        let mut iiiout = iiout.make_indent();
        for selector in UnionSelectorIterator::new(
            &self.tables.structures,
            *discriminant.resolved_discriminant_type.as_ref().unwrap(),
            false,
        ) {
            let deps = &selector.config_deps();
            let deps = deps.factor_by_common_of(&config_deps_noncond);
            let deps = deps.factor_by_common_of(&config_deps_cond);
            if !deps.is_unconditional_true() {
                writeln!(
                    &mut iiiout,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&deps)
                )?;
            }

            let selected_union_members =
                self.get_structure_selected_union_members(table, discriminant, &selector);
            let enum_member_name = self.format_tagged_union_member_name(&selector);
            let enum_member_name = Self::camelize(&enum_member_name);
            if selected_union_members.is_empty() {
                writeln!(
                    &mut iiiout,
                    "Self::{} => matches!(other, {}::{}),",
                    &enum_member_name, &tagged_union_name_noncond, enum_member_name
                )?;
                continue;
            };

            let selected_union_members_lhs_match_spec = selected_union_members
                .iter()
                .map(|(u, _, _)| {
                    let name = &Self::format_structure_member_name(&table.entries[*u].name);
                    if discriminant.discriminated_union_members.len() == 1 {
                        "self_".to_owned() + name
                    } else {
                        name.clone().into_owned() + ": self_" + name
                    }
                })
                .collect::<Vec<String>>()
                .join(", ");
            let selected_union_members_rhs_match_spec = selected_union_members
                .iter()
                .map(|(u, _, _)| {
                    let name = &Self::format_structure_member_name(&table.entries[*u].name);
                    if discriminant.discriminated_union_members.len() == 1 {
                        "other_".to_owned() + name
                    } else {
                        name.clone().into_owned() + ": other_" + name
                    }
                })
                .collect::<Vec<String>>()
                .join(", ");
            let match_delims = if discriminant.discriminated_union_members.len() == 1 {
                ("(", ")")
            } else {
                ("{", "}")
            };
            writeln!(
                &mut iiiout,
                "Self::{}{}{}{} => {{",
                &enum_member_name,
                match_delims.0,
                &selected_union_members_lhs_match_spec,
                match_delims.1
            )?;
            let mut iiiiout = iiiout.make_indent();
            writeln!(
                &mut iiiiout,
                "if let {}::{}{}{}{} = other {{",
                &tagged_union_name_noncond,
                &enum_member_name,
                match_delims.0,
                &selected_union_members_rhs_match_spec,
                match_delims.1
            )?;
            let mut iiiiiout = iiiiout.make_indent();
            let mut first = true;
            for selected in selected_union_members.iter() {
                let name = Self::format_structure_member_name(&table.entries[selected.0].name);
                if !first {
                    writeln!(&mut iiiiiout, "&& self_{} == other_{}", &name, &name)?;
                } else {
                    writeln!(&mut iiiiiout, "self_{} == other_{}", &name, &name)?;
                }
                first = false;
            }
            writeln!(&mut iiiiout, "}} else {{")?;
            writeln!(&mut iiiiout.make_indent(), "false")?;
            writeln!(&mut iiiiout, "}}")?;
            writeln!(&mut iiiout, "}},")?;
        }

        writeln!(&mut iiiout, "_ => false,")?;

        writeln!(&mut iiout, "}}")?;
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
            "impl{} cmp::PartialEq<{}{}> for {}{} {{",
            gen_params_spec.0,
            &tagged_union_name_cond,
            gen_params_spec.1,
            tagged_union_name_noncond,
            gen_params_spec.1
        )?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "fn eq(&self, other: &{}{}) -> bool {{",
            &tagged_union_name_cond, gen_params_spec.1
        )?;
        writeln!(&mut iout.make_indent(), "other.eq(self)")?;
        writeln!(&mut iout, "}}")?;
        writeln!(out, "}}")?;

        Ok(())
    }
}
