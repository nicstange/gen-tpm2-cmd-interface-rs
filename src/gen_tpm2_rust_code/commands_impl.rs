// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use super::{code_writer, Tpm2InterfaceRustCodeGenerator};
use crate::tcg_tpm2::commands::command_table::{
    CommandTableCCFlushModfier, CommandTableHandleAuthRole, CommandTablePlatformAuthPPModfier,
};
use crate::tcg_tpm2::commands::tables::CommandsPartTablesEntry;
use crate::tcg_tpm2::structures::structure_table::{StructureTable, StructureTableEntryType};
use crate::tcg_tpm2::structures::tables::StructuresPartTablesConstantsIndex;

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn gen_commands_macro<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error> {
        writeln!(out)?;
        writeln!(out, "macro_rules! with_tpm_commands {{")?;
        let mut iout = out.make_indent();
        writeln!(
            &mut iout,
            "( $m:ident, $cp_lifetime:lifetime, $rp_lifetime:lifetime ) => {{"
        )?;
        let mut iiout = iout.make_indent();
        writeln!(&mut iiout, "$m![")?;
        let mut iiiout = iiout.make_indent();
        for i in 0..self.tables.commands.len() {
            let c = &self.tables.commands[i];
            writeln!(&mut iiiout, "{{")?;
            self.gen_commands_macro_entry(&mut iiiout.make_indent(), c, enable_allocator_api)?;
            let sep = if i != self.tables.commands.len() - 1 {
                ","
            } else {
                ""
            };
            writeln!(&mut iiiout, "}}{}", sep)?;
        }
        writeln!(&mut iiout, "]")?;
        writeln!(&mut iout, "}};")?;
        writeln!(out, "}}")?;

        Ok(())
    }

    fn gen_commands_macro_entry<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        command: &CommandsPartTablesEntry,
        enable_allocator_api: bool,
    ) -> Result<(), io::Error> {
        let command_code_index = command.command_code;
        let command_code_table_index = StructuresPartTablesConstantsIndex::from(command_code_index);
        let command_code_table = self
            .tables
            .structures
            .get_constants(command_code_table_index);
        let command_code = format!(
            "{}::{}",
            Self::camelize(&command_code_table.name),
            Self::camelize(&self.format_const_member_name(command_code_index))
        );
        writeln!(out, "command_code: {},", command_code)?;

        writeln!(
            out,
            "name_in_camelcase: {},",
            Self::camelize(&command.command.name)
        )?;
        writeln!(
            out,
            "name_in_snakecase: {},",
            Self::uncamelize(&command.command.name)
        )?;

        if !command.deps.is_unconditional_true() {
            writeln!(out, "cfg: {},", Self::format_dep_conjunction(&command.deps))?;
        }

        if command.command.cc_modifiers.nv {
            writeln!(out, "nv: true,")?;
        }

        match command.command.cc_modifiers.flushing {
            CommandTableCCFlushModfier::None => (),
            CommandTableCCFlushModfier::Used => {
                writeln!(out, "flushing: Used,")?;
            }
            CommandTableCCFlushModfier::Extensive => {
                writeln!(out, "flushing: Extensive,")?;
            }
        };

        match command.command.platform_auth_pp_modifier {
            CommandTablePlatformAuthPPModfier::None => (),
            CommandTablePlatformAuthPPModfier::IsRequired => {
                writeln!(out, "platform_auth_pp: IsRequired,")?;
            }
            CommandTablePlatformAuthPPModfier::MayBeRequired => {
                writeln!(out, "platform_auth_pp: MayBeRequired,")?;
            }
        };

        if let Some(handles_structure_index) = &command.command.handles_structure {
            let handles_structure = self
                .tables
                .structures
                .get_structure(*handles_structure_index);
            writeln!(out, "command_handles: {{")?;
            let mut iout = out.make_indent();
            self.gen_commands_macro_entry_params_spec(&mut iout, &handles_structure, false)?;
            writeln!(&mut iout, "handles: {{")?;
            let mut iiout = iout.make_indent();
            for i in 0..command.command.handles.len() {
                let structure_entry = &handles_structure.entries[i];
                let handle_spec = &command.command.handles[i];
                let name = Self::uncamelize(&structure_entry.name);
                let t = match &structure_entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => self
                        .format_structure_member_plain_type(
                            plain_type.resolved_base_type.as_ref().unwrap(),
                            plain_type.base_type_enable_conditional,
                            false,
                            enable_allocator_api,
                        ),
                    _ => unreachable!(),
                };

                let sep = if i != command.command.handles.len() - 1 {
                    ","
                } else {
                    ""
                };

                if let Some(auth) = handle_spec.auth.as_ref() {
                    writeln!(&mut iiout, "{{")?;
                    let mut iiiout = iiout.make_indent();
                    writeln!(&mut iiiout, "name: {}, type: {},", name, t)?;
                    let role = match &auth.role {
                        CommandTableHandleAuthRole::User => "User",
                        CommandTableHandleAuthRole::Admin => "Admin",
                        CommandTableHandleAuthRole::Dup => "Dup",
                    };
                    writeln!(
                        &mut iiiout,
                        "auth: {{ index: {}, role: {}, }},",
                        auth.index, role
                    )?;
                    writeln!(&mut iiout, "}}{}", sep)?;
                } else {
                    writeln!(&mut iiout, "{{ name: {}, type: {}, }}{}", name, t, sep)?;
                }
            }
            writeln!(&mut iout, "}},")?;
            writeln!(out, "}},")?;
        };

        if let Some(params_structure_index) = command.command.params_structure {
            let params_structure = self.tables.structures.get_structure(params_structure_index);
            writeln!(out, "command_params: {{")?;
            self.gen_commands_macro_entry_params_spec(
                &mut out.make_indent(),
                &params_structure,
                true,
            )?;
            writeln!(out, "}},")?;
        }

        if let Some(handles_structure_index) = &command.response.handles_structure {
            let handles_structure = self
                .tables
                .structures
                .get_structure(*handles_structure_index);
            writeln!(out, "response_handles: {{")?;
            let mut iout = out.make_indent();
            self.gen_commands_macro_entry_params_spec(&mut iout, &handles_structure, false)?;
            writeln!(&mut iout, "handles: {{")?;
            let mut iiout = iout.make_indent();
            for i in 0..command.response.handles.len() {
                let structure_entry = &handles_structure.entries[i];
                let name = Self::uncamelize(&structure_entry.name);
                let t = match &structure_entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => self
                        .format_structure_member_plain_type(
                            plain_type.resolved_base_type.as_ref().unwrap(),
                            plain_type.base_type_enable_conditional,
                            false,
                            enable_allocator_api,
                        ),
                    _ => unreachable!(),
                };

                let sep = if i != command.response.handles.len() - 1 {
                    ","
                } else {
                    ""
                };

                writeln!(&mut iiout, "{{ name: {}, type: {}, }}{}", name, t, sep)?;
            }
            writeln!(&mut iout, "}},")?;
            writeln!(out, "}},")?;
        };

        if let Some(params_structure_index) = command.response.params_structure {
            let params_structure = self.tables.structures.get_structure(params_structure_index);
            writeln!(out, "response_params: {{")?;
            self.gen_commands_macro_entry_params_spec(
                &mut out.make_indent(),
                &params_structure,
                true,
            )?;
            writeln!(out, "}},")?;
        }

        Ok(())
    }

    fn gen_commands_macro_entry_params_spec<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        params: &StructureTable,
        is_params: bool,
    ) -> Result<(), io::Error> {
        writeln!(out, "type: {},", Self::camelize(&params.name))?;
        if self.structure_references_inbuf(params) {
            writeln!(out, "lifetime: $cp_lifetime,")?;
        }
        if is_params {
            let can_crypt = self.structure_is_cryptable(params);
            writeln!(out, "can_crypt: {},", can_crypt)?;

            let contains_arrays = self.structure_contains_array(params);
            writeln!(out, "trivial_clone: {},", !contains_arrays)?;
        }
        writeln!(
            out,
            "unmarshal_needs_limits: {},",
            self.structure_unmarshal_needs_limits(params)
        )?;
        writeln!(
            out,
            "marshalled_size_needs_limits: {},",
            Self::structure_marshalled_size_needs_limits(params)
        )?;
        writeln!(
            out,
            "marshal_needs_limits: {},",
            Self::structure_marshal_needs_limits(params)
        )?;
        Ok(())
    }
}
