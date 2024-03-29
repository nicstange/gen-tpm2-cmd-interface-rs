// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use structures::predefined::PredefinedTypes;
use structures::table_common::ClosureDepsFlags;
use structures::tables::StructuresPartTablesBitsIndex;

use super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    fn format_bits_member_name(&self, index: StructuresPartTablesBitsIndex, j: usize) -> String {
        let table = self.tables.structures.get_bits(index);
        let entry = &table.entries[j];
        let entry_name = Self::uncamelize(&entry.name).to_ascii_uppercase();

        let mut prefix_end = Self::strip_table_prefix(&table.name, &entry_name);
        // Re-add prefix parts until the identifier is unique.
        let entry_name_parts = entry_name.split('_').collect::<Vec<&str>>();
        'others: while prefix_end > 0 {
            let entry_name_tail_parts = &entry_name_parts[prefix_end..];
            for k in 0..table.entries.len() {
                if k == j {
                    continue;
                }
                let other_name = Self::uncamelize(&table.entries[k].name).to_ascii_uppercase();
                let other_prefix_end = Self::strip_table_prefix(&table.name, &other_name);
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

        entry_name_parts[prefix_end..].join("_")
    }

    pub(super) fn gen_bits<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        index: StructuresPartTablesBitsIndex,
    ) -> Result<(), io::Error> {
        let table = self.tables.structures.get_bits(index);

        let table_deps = table
            .closure_deps
            .collect_config_deps(ClosureDepsFlags::all());
        if table_deps.is_empty() {
            return Ok(());
        }

        writeln!(out)?;
        if let Some(src_ref) = &table.info.src_ref {
            writeln!(out, "// {}, {} bits", src_ref, &table.name)?;
        } else {
            writeln!(out, "// {} bits", &table.name)?;
        }
        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }

        writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]")?;
        let table_is_public = table
            .closure_deps
            .any(ClosureDepsFlags::PUBLIC_DEFINITION | ClosureDepsFlags::EXTERN_MAX_SIZE);
        if table_is_public {
            write!(out, "pub ")?
        }
        writeln!(out, "struct {} {{", Self::camelize(&table.name))?;
        let base_type = *table.get_underlying_type();
        if table.closure_deps.any(ClosureDepsFlags::ANY_DEFINITION) {
            let mut iout = out.make_indent();
            writeln!(
                &mut iout,
                "value: {},",
                Self::predefined_type_to_rust(base_type)
            )?;
        }
        writeln!(out, "}}")?;

        writeln!(out)?;
        if !table_deps.is_unconditional_true() {
            writeln!(out, "#[cfg({})]", Self::format_deps(&table_deps))?;
        }
        writeln!(out, "impl {} {{", Self::camelize(&table.name))?;

        let mut first = true;
        let mut iout = out.make_indent();
        let distance_type = PredefinedTypes::find_type_with_repr(32, false).unwrap();
        let all_set_mask = "0x".to_owned()
            + &"f".repeat(base_type.bits as usize / 4)
            + Self::predefined_type_to_rust(base_type);
        if table.closure_deps.any(ClosureDepsFlags::PUBLIC_DEFINITION) {
            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

            writeln!(&mut iout, "pub fn new() -> Self {{")?;
            let mut iiout = iout.make_indent();
            writeln!(
                &mut iiout,
                "Self {{ value: 0{} }}",
                Self::predefined_type_to_rust(base_type)
            )?;
            writeln!(&mut iout, "}}")?;

            for j in 0..table.entries.len() {
                writeln!(&mut iout)?;
                let entry = &table.entries[j];
                let name = self.format_bits_member_name(index, j);
                let deps = entry.deps.factor_by_common_of(&table_deps);

                let (mut min_bit_index, p) = self
                    .format_compiletime_const_expr_for_type(
                        &entry.bits.min_bit_index,
                        distance_type,
                        "limits",
                        None,
                    )
                    .map_err(|_| {
                        eprintln!(
                            "error: {}: {}: integer overflow in bit range bound",
                            &table.name, &entry.name
                        );
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?;
                if !p {
                    min_bit_index = "(".to_owned() + &min_bit_index + ")";
                }

                if let Some(max_bit_index) = &entry.bits.max_bit_index {
                    let (mut max_bit_index, p) = self
                        .format_compiletime_const_expr_for_type(
                            max_bit_index,
                            distance_type,
                            "limits",
                            None,
                        )
                        .map_err(|_| {
                            eprintln!(
                                "error: {}: {}: integer overflow in bit range bound",
                                &table.name, &entry.name
                            );
                            io::Error::from(io::ErrorKind::InvalidData)
                        })?;
                    if !p {
                        max_bit_index = "(".to_owned() + &max_bit_index + ")";
                    }

                    let (mut min_bit_index, p) = self
                        .format_compiletime_const_expr_for_type(
                            &entry.bits.min_bit_index,
                            distance_type,
                            "limits",
                            None,
                        )
                        .map_err(|_| {
                            eprintln!(
                                "error: {}: {}: integer overflow in bit range bound",
                                &table.name, &entry.name
                            );
                            io::Error::from(io::ErrorKind::InvalidData)
                        })?;
                    if !p {
                        min_bit_index = "(".to_owned() + &min_bit_index + ")";
                    }

                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                    }
                    writeln!(
                        &mut iout,
                        "const {}_MASK: {} = {} >> ({}u32 - 1u32 - {} + {}) << {};",
                        &name,
                        Self::predefined_type_to_rust(base_type),
                        &all_set_mask,
                        base_type.bits,
                        &max_bit_index,
                        &min_bit_index,
                        &min_bit_index
                    )?;
                } else {
                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                    }
                    writeln!(
                        &mut iout,
                        "const {}_MASK: {} = 1{} << {};",
                        &name,
                        Self::predefined_type_to_rust(base_type),
                        Self::predefined_type_to_rust(base_type),
                        &min_bit_index
                    )?;
                }

                if entry.bits.max_bit_index.is_some() {
                    if !deps.is_unconditional_true() {
                        writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                    }
                    writeln!(
                        &mut iout,
                        "const {}_SHIFT: u32 = {};",
                        &name, &min_bit_index
                    )?;
                }

                writeln!(&mut iout)?;
                if !deps.is_unconditional_true() {
                    writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                }
                if entry.bits.max_bit_index.is_some() {
                    writeln!(
                        &mut iout,
                        "pub fn get_{}(&self) -> {} {{",
                        name.to_ascii_lowercase(),
                        Self::predefined_type_to_rust(base_type)
                    )?;
                    let mut iiout = iout.make_indent();
                    writeln!(
                        &mut iiout,
                        "(self.value & Self::{}_MASK) >> Self::{}_SHIFT",
                        &name, &name
                    )?;
                    writeln!(&mut iout, "}}")?;
                } else {
                    writeln!(
                        &mut iout,
                        "pub fn get_{}(&self) -> bool {{",
                        name.to_ascii_lowercase()
                    )?;
                    let mut iiout = iout.make_indent();
                    writeln!(&mut iiout, "self.value & Self::{}_MASK != 0", &name)?;
                    writeln!(&mut iout, "}}")?;
                }

                writeln!(&mut iout)?;
                if !deps.is_unconditional_true() {
                    writeln!(&mut iout, "#[cfg({})]", Self::format_dep_conjunction(&deps))?;
                }
                if entry.bits.max_bit_index.is_some() {
                    writeln!(
                        &mut iout,
                        "pub fn set_{}(&mut self, value: {}) {{",
                        name.to_ascii_lowercase(),
                        Self::predefined_type_to_rust(base_type)
                    )?;
                    let mut iiout = iout.make_indent();
                    writeln!(&mut iiout, "let value = value << Self::{}_SHIFT;", &name)?;
                    writeln!(
                        &mut iiout,
                        "debug_assert!(value & !Self::{}_MASK == 0, \"invalid bitfield value\");",
                        &name
                    )?;
                    writeln!(&mut iiout, "self.value &= !Self::{}_MASK;", &name)?;
                    writeln!(&mut iiout, "self.value |= value;")?;
                    writeln!(&mut iout, "}}")?;
                } else {
                    writeln!(
                        &mut iout,
                        "pub fn set_{}(&mut self, value: bool) {{",
                        name.to_ascii_lowercase()
                    )?;
                    let mut iiout = iout.make_indent();
                    writeln!(&mut iiout, "if value {{")?;
                    let mut iiiout = iiout.make_indent();
                    writeln!(&mut iiiout, "self.value |= Self::{}_MASK;", &name)?;
                    writeln!(&mut iiout, "}} else {{")?;
                    let mut iiiout = iiout.make_indent();
                    writeln!(&mut iiiout, "self.value &= !Self::{}_MASK;", &name)?;
                    writeln!(&mut iiout, "}}")?;
                    writeln!(&mut iout, "}}")?;
                }
            }

            if !table.reserved.is_empty() {
                if !first {
                    writeln!(&mut iout)?;
                }
                first = false;

                for j in 0..table.reserved.len() {
                    let reserved = &table.reserved[j];
                    let (mut min_bit_index, p) = self
                        .format_compiletime_const_expr_for_type(
                            &reserved.min_bit_index,
                            distance_type,
                            "limits",
                            None,
                        )
                        .map_err(|_| {
                            eprintln!(
                                "error: {}: integer overflow in reserved bit range bound",
                                &table.name
                            );
                            io::Error::from(io::ErrorKind::InvalidData)
                        })?;
                    if !p {
                        min_bit_index = "(".to_owned() + &min_bit_index + ")";
                    }

                    if let Some(max_bit_index) = &reserved.max_bit_index {
                        let (mut max_bit_index, p) = self
                            .format_compiletime_const_expr_for_type(
                                max_bit_index,
                                distance_type,
                                "limits",
                                None,
                            )
                            .map_err(|_| {
                                eprintln!(
                                    "error: {}: integer overflow in reserved bit range bound",
                                    &table.name
                                );
                                io::Error::from(io::ErrorKind::InvalidData)
                            })?;
                        if !p {
                            max_bit_index = "(".to_owned() + &max_bit_index + ")";
                        }

                        if table.reserved.len() > 1 {
                            writeln!(
                                &mut iout,
                                "const RESERVED_MASK{}: {} = {} >> ({}u32 - 1u32 - {} + {}) << {};",
                                j,
                                Self::predefined_type_to_rust(base_type),
                                &all_set_mask,
                                base_type.bits,
                                &max_bit_index,
                                &min_bit_index,
                                &min_bit_index
                            )?;
                        } else {
                            writeln!(
                                &mut iout,
                                "const RESERVED_MASK: {} = {} >> ({}u32 - 1u32 - {} + {}) << {};",
                                Self::predefined_type_to_rust(base_type),
                                &all_set_mask,
                                base_type.bits,
                                &max_bit_index,
                                &min_bit_index,
                                &min_bit_index
                            )?;
                        }
                    } else if table.reserved.len() > 1 {
                        writeln!(
                            &mut iout,
                            "const RESERVED_MASK{}: {} = 1{} << {};",
                            j,
                            Self::predefined_type_to_rust(base_type),
                            Self::predefined_type_to_rust(base_type),
                            &min_bit_index
                        )?;
                    } else {
                        writeln!(
                            &mut iout,
                            "const RESERVED_MASK: {} = 1{} << {};",
                            Self::predefined_type_to_rust(base_type),
                            Self::predefined_type_to_rust(base_type),
                            &min_bit_index
                        )?;
                    }
                }

                if table.reserved.len() > 1 {
                    writeln!(
                        &mut iout,
                        "const RESERVED_MASK: {} = {};",
                        Self::predefined_type_to_rust(base_type),
                        (0..table.reserved.len())
                            .map(|j| "Self::RESERVED_MASK".to_string() + &j.to_string())
                            .collect::<Vec<String>>()
                            .join(" | ")
                    )?;
                }
            }
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
            let pub_spec = if table.closure_deps.any(ClosureDepsFlags::EXTERN_MAX_SIZE) {
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

        let mut marshal_deps = table
            .closure_deps
            .collect_config_deps(ClosureDepsFlags::ANY_MARSHAL);
        marshal_deps.factor_by_common_of(&table_deps);
        if table.closure_deps.any(ClosureDepsFlags::ANY_MARSHAL) {
            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

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
            writeln!(
                &mut iiout,
                "marshal_{}(buf, self.value)",
                Self::predefined_type_to_rust(base_type)
            )?;
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
            writeln!(&mut iout,
                     "{}fn unmarshal(buf: &[u8]) -> Result<(&[u8], Self), TpmErr> {{",
                     pub_spec)?;
            let mut iiout = iout.make_indent();
            writeln!(
                &mut iiout,
                "let (buf, value) = unmarshal_{}(buf)?;",
                Self::predefined_type_to_rust(base_type)
            )?;

            if table.reserved.is_empty() {
                writeln!(&mut iiout, "let result = Self::from(value);")?;
            } else {
                writeln!(&mut iiout, "let result = Self::try_from(value)?;")?;
            }

            writeln!(&mut iiout, "Ok((buf, result))")?;
            writeln!(&mut iout, "}}")?;
        }

        writeln!(out, "}}")?;

        writeln!(out)?;
        if table.reserved.is_empty() {
            writeln!(out, "impl convert::From<{}> for {} {{",
                     Self::predefined_type_to_rust(base_type), Self::camelize(&table.name))?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "fn from(value: {}) -> Self {{",
                     Self::predefined_type_to_rust(base_type))?;
            writeln!(&mut iout.make_indent(), "Self {{ value }}")?;
            writeln!(&mut iout, "}}")?;
            writeln!(out, "}}")?;
        } else {
            writeln!(out, "impl convert::TryFrom<{}> for {} {{",
                     Self::predefined_type_to_rust(base_type), Self::camelize(&table.name))?;
            let mut iout = out.make_indent();
            writeln!(&mut iout, "type Error = TpmErr;")?;
            writeln!(&mut iout)?;
            writeln!(&mut iout, "fn try_from(value: {}) -> Result<Self, TpmErr> {{",
                     Self::predefined_type_to_rust(base_type))?;
            let mut iiout = iout.make_indent();
            let error_rc = self
                .tables
                .structures
                .lookup_constant("TPM_RC_RESERVED_BITS")
                .unwrap();
            writeln!(&mut iiout)?;
            writeln!(&mut iiout, "if value & Self::RESERVED_MASK != 0 {{")?;
            self.format_error_return(&mut iiout.make_indent(), None, error_rc)?;
            writeln!(&mut iiout, "}}")?;
            writeln!(&mut iiout)?;

            writeln!(&mut iiout, "Ok(Self {{ value }})")?;
            writeln!(&mut iout, "}}")?;
            writeln!(out, "}}")?;
        }

        Ok(())
    }
}
