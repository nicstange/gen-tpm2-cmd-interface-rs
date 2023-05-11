// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A TCG TPM2 Part 3 "Commands" "Command" table

use crate::tcg_tpm2::structures::tables::StructuresPartTablesStructureIndex;
use std::io;

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;

// See TCG Tpm2 spec, part 3 "Commands", Table 1 "Command Modifiers and
// Decoration"
#[derive(Clone, Copy, Debug)]
pub enum CommandTableCCFlushModfier {
    None,
    Used,
    Extensive,
}

// See TCG Tpm2 spec, part 3 "Commands", Table 1 "Command Modifiers and
// Decoration"
#[derive(Clone, Copy, Debug)]
pub struct CommandTableCCModifiers {
    pub nv: bool,
    pub flushing: CommandTableCCFlushModfier,
}

impl CommandTableCCModifiers {
    fn new() -> Self {
        Self {
            nv: false,
            flushing: CommandTableCCFlushModfier::None,
        }
    }

    fn new_from_csv(s: &str, filename: &str, lineno: u32) -> Result<Self, io::Error> {
        let mut cc_modifiers = Self::new();

        for m in s.split(char::is_whitespace) {
            if m == "NV" {
                cc_modifiers.nv = true;
            } else if m == "F" {
                if let CommandTableCCFlushModfier::Extensive = cc_modifiers.flushing {
                    eprintln!(
                        "error: {}:{}: conflicting command code modifiers",
                        filename, lineno
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                cc_modifiers.flushing = CommandTableCCFlushModfier::Used;
            } else if m == "E" {
                if let CommandTableCCFlushModfier::Used = cc_modifiers.flushing {
                    eprintln!(
                        "error: {}:{}: conflicting command code modifiers",
                        filename, lineno
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                cc_modifiers.flushing = CommandTableCCFlushModfier::Extensive;
            } else {
                eprintln!(
                    "error: {}:{}: unrecoginzed command code modifier",
                    filename, lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        }
        Ok(cc_modifiers)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommandTablePlatformAuthPPModfier {
    None,
    IsRequired,
    MayBeRequired,
}

impl CommandTablePlatformAuthPPModfier {
    fn new_from_csv(
        handle_descr_col: &str,
        filename: &str,
        lineno: u32,
        regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let mut platform_auth_pp_modifier = Self::None;
        for captures in regexps_cache
            .re_command_handle_description_platform_auth_pp
            .captures_iter(handle_descr_col)
        {
            let pp_modifier = captures.name("PPMOD").unwrap().as_str();
            let pp_modifier = match pp_modifier {
                "PP" => Self::IsRequired,
                "{PP}" => Self::MayBeRequired,
                _ => {
                    eprintln!(
                        "error: {}:{}: unrecognized platform auth PP modifier",
                        filename, lineno
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };

            if platform_auth_pp_modifier != Self::None && platform_auth_pp_modifier != pp_modifier {
                eprintln!(
                    "error: {}:{}: multiple conflicting platform auth PP modifiers",
                    filename, lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            platform_auth_pp_modifier = pp_modifier;
        }
        Ok(platform_auth_pp_modifier)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum CommandTableHandleAuthRole {
    User,
    Admin,
    Dup,
}

#[derive(Debug)]
pub struct CommandTableHandleAuth {
    pub index: u32,
    pub role: CommandTableHandleAuthRole,
}

#[derive(Debug)]
pub struct CommandTableHandle {
    pub name: String,
    pub handle_type: String,
    pub handle_type_enable_conditional: bool,
    pub auth: Option<CommandTableHandleAuth>,
}

impl CommandTableHandle {
    fn new_from_csv(
        cols: &[&str],
        filename: &str,
        lineno: u32,
        regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let name = cols[1];
        if name.is_empty() {
            eprintln!("error: {}:{}: empty handle name", filename, lineno);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let handle_type = cols[0];
        let mut handle_type_enable_conditional = false;
        let handle_type = match handle_type.strip_suffix('+') {
            Some(handle_type) => {
                handle_type_enable_conditional = true;
                handle_type.trim_end()
            }
            None => handle_type,
        };
        if handle_type.is_empty() {
            eprintln!("error: {}:{}: empty handle type", filename, lineno);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        if !name.starts_with('@') {
            for captures in regexps_cache
                .re_command_handle_description_auth_index
                .captures_iter(cols[2])
            {
                let auth_index = captures.name("AUTHINDEX").unwrap().as_str();
                if auth_index != "None" && auth_index != "none" {
                    eprintln!(
                        "error: {}:{}: unexpected auth index for handle with no authorization",
                        filename, lineno
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }
            if regexps_cache
                .re_command_handle_description_auth_role
                .captures_iter(cols[2])
                .next()
                .is_some()
            {
                eprintln!(
                    "error: {}:{}: unexpected auth role for handle with no authorization",
                    filename, lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            return Ok(CommandTableHandle {
                name: name.to_owned(),
                handle_type: handle_type.to_owned(),
                handle_type_enable_conditional,
                auth: None,
            });
        }
        let name = name.strip_prefix('@').unwrap();
        let mut index: Option<u32> = None;
        for captures in regexps_cache
            .re_command_handle_description_auth_index
            .captures_iter(cols[2])
        {
            let auth_index = captures.name("AUTHINDEX").unwrap().as_str();
            if auth_index == "None" || auth_index == "none" {
                eprintln!(
                    "error: {}:{}: unexpected auth index for handle with authorization",
                    filename, lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let auth_index: u32 = auth_index.parse().map_err(|_| {
                eprintln!("error: {}:{}: failed to parse auth index", filename, lineno);
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

            if let Some(index) = index {
                if index != auth_index {
                    eprintln!(
                        "error: {}:{}: multiple inconsistent auth indices",
                        filename, lineno
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }

            index = Some(auth_index);
        }
        let index = match index {
            Some(index) => index,
            None => {
                eprintln!(
                    "error: {}:{}: no auth index for handle with authorization",
                    filename, lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        };

        let mut role: Option<CommandTableHandleAuthRole> = None;
        for captures in regexps_cache
            .re_command_handle_description_auth_role
            .captures_iter(cols[2])
        {
            let auth_role = captures.name("AUTHROLE").unwrap().as_str();
            let auth_role = match auth_role {
                "USER" | "User" => CommandTableHandleAuthRole::User,
                "ADMIN" => CommandTableHandleAuthRole::Admin,
                "DUP" => CommandTableHandleAuthRole::Dup,
                _ => {
                    eprintln!("error: {}:{}: unrecognized auth role", filename, lineno);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };

            if let Some(role) = role {
                if role != auth_role {
                    eprintln!(
                        "error: {}:{}: multiple inconsistent auth roles",
                        filename, lineno
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }

            role = Some(auth_role);
        }
        let role = match role {
            Some(role) => role,
            None => {
                eprintln!(
                    "error: {}:{}: no auth role for handle with authorization",
                    filename, lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        };

        let auth = CommandTableHandleAuth { index, role };
        Ok(CommandTableHandle {
            name: name.to_owned(),
            handle_type: handle_type.to_owned(),
            handle_type_enable_conditional,
            auth: Some(auth),
        })
    }
}

#[derive(Debug)]
pub struct CommandTableParam {
    pub name: String,
    pub param_type: String,
    pub param_type_enable_conditional: bool,
}

#[derive(Debug)]
pub struct CommandTable {
    pub info: CommonTableInfo,
    pub name: String,
    pub command_code: String,
    pub cc_modifiers: CommandTableCCModifiers,
    pub platform_auth_pp_modifier: CommandTablePlatformAuthPPModfier,

    pub handles: Vec<CommandTableHandle>,
    pub params: Vec<CommandTableParam>,

    pub handles_structure: Option<StructuresPartTablesStructureIndex>,
    pub params_structure: Option<StructuresPartTablesStructureIndex>,
}

impl CommandTable {
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        name: &str,
        filename: &str,
        table_lines: &[(u32, String)],
        regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let header_row = &table_lines[0];
        let rows = &table_lines[1..];
        let col_headers: Vec<&str> = header_row.1.split(';').map(|e| e.trim()).collect();
        if col_headers.len() < 3 {
            eprintln!(
                "error: {}:{}: too few columns in table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if !col_headers[0].contains("Type") {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[1] != "Name" {
            eprintln!(
                "error: {}:{}: unexpected column name header in second column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[2] != "Description" {
            eprintln!(
                "error: {}:{}: unexpected column name header in third column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        if rows.len() < 3 {
            eprintln!(
                "error: {}:{}: too few rows in command table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let tag_row: Vec<&str> = rows[0].1.split(';').map(|e| e.trim()).collect();
        if tag_row.len() != col_headers.len() {
            eprintln!(
                "error: {}:{}: unexpected number of columns in table row",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if tag_row[0] != "TPMI_ST_COMMAND_TAG"
            || (tag_row[1] != "tag" && tag_row[1] != "Tag")
        {
            eprintln!(
                "error: {}:{}: expected \"tag\" for first entry in command table",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let command_size_row: Vec<&str> = rows[1].1.split(';').map(|e| e.trim()).collect();
        if command_size_row.len() != col_headers.len() {
            eprintln!(
                "error: {}:{}: unexpected number of columns in table row",
                filename, rows[1].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if command_size_row[0] != "UINT32" || command_size_row[1] != "commandSize" {
            eprintln!(
                "error: {}:{}: expected \"commandSize\" for second entry in command table",
                filename, rows[1].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let command_code_row: Vec<&str> = rows[2].1.split(';').map(|e| e.trim()).collect();
        if command_code_row.len() != col_headers.len() {
            eprintln!(
                "error: {}:{}: unexpected number of columns in table row",
                filename, rows[2].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if command_code_row[0] != "TPM_CC" || command_code_row[1] != "commandCode" {
            eprintln!(
                "error: {}:{}: expected \"commandCode\" for third entry in command table",
                filename, rows[2].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let (command_code, cc_modifiers) = match regexps_cache
            .re_command_code_description
            .captures(command_code_row[2])
        {
            Some(caps) => {
                let command_code = caps.name("CC").unwrap().as_str();
                let cc_modifiers = match caps.name("CCMOD") {
                    Some(m) => {
                        CommandTableCCModifiers::new_from_csv(m.as_str(), filename, rows[2].0)?
                    }
                    None => CommandTableCCModifiers::new(),
                };
                (command_code, cc_modifiers)
            }
            None => {
                eprintln!(
                    "error: {}:{}: unrecognized \"commandCode\" description",
                    filename, rows[2].0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        };

        let mut platform_auth_pp_modifier = CommandTablePlatformAuthPPModfier::None;
        let mut handles: Vec<CommandTableHandle> = Vec::new();
        let mut params: Vec<CommandTableParam> = Vec::new();
        let mut in_handle_area = false;
        let mut in_param_area = false;
        for row in rows.iter().skip(3) {
            let trimmed_row = row.1.trim();
            if trimmed_row == "HANDLE_AREA" {
                in_param_area = false;
                in_handle_area = true;
                continue;
            } else if trimmed_row == "PARAM_AREA" {
                in_param_area = true;
                in_handle_area = false;
                continue;
            }

            if !in_handle_area && !in_param_area {
                eprintln!(
                    "error: {}:{}: unexpected row outside handle and parameter areas",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let cols: Vec<&str> = row.1.split(';').map(|e| e.trim()).collect();
            if cols.len() != col_headers.len() {
                eprintln!(
                    "error: {}:{}: unexpected number of columns in table row",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            if in_handle_area {
                let pp_modifier = CommandTablePlatformAuthPPModfier::new_from_csv(
                    cols[2],
                    filename,
                    row.0,
                    regexps_cache,
                )?;
                if pp_modifier != CommandTablePlatformAuthPPModfier::None
                    && platform_auth_pp_modifier != CommandTablePlatformAuthPPModfier::None
                    && platform_auth_pp_modifier != pp_modifier
                {
                    eprintln!(
                        "error: {}:{}: multiple conflicting platform auth PP modifiers",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                platform_auth_pp_modifier = pp_modifier;

                handles.push(CommandTableHandle::new_from_csv(
                    &cols,
                    filename,
                    row.0,
                    regexps_cache,
                )?);
                continue;
            }

            assert!(in_param_area);
            if !cols[2].is_empty() {
                eprintln!(
                    "error: {}:{}: unexpected non-empty command parameter description",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let name = cols[1];
            if name.is_empty() {
                eprintln!("error: {}:{}: empty parameter name", filename, row.0);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            } else if name.starts_with('@') {
                eprintln!(
                    "error: {}:{}: parameter name looks like a handle",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let param_type = cols[0];
            let mut param_type_enable_conditional = false;
            let param_type = match param_type.strip_suffix('+') {
                Some(param_type) => {
                    param_type_enable_conditional = true;
                    param_type.trim_end()
                }
                None => param_type,
            };
            if param_type.is_empty() {
                eprintln!("error: {}:{}: empty parameter type", filename, row.0);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            params.push(CommandTableParam {
                name: name.to_owned(),
                param_type: param_type.to_owned(),
                param_type_enable_conditional,
            })
        }

        // Finally verify that the auth indices start at 1 and are consecutive.
        let mut auth_indices: Vec<u32> = handles
            .iter()
            .filter(|h| h.auth.is_some())
            .map(|h| h.auth.as_ref().unwrap().index)
            .collect();
        auth_indices.sort_unstable();
        let mut prev_i = 0;
        for i in auth_indices {
            if i != prev_i + 1 {
                eprintln!(
                    "error: {}:{}: auth indices not covering consecutive range at offset 1",
                    filename, header_row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            prev_i = i;
        }

        Ok(Self {
            info,
            name: name.to_owned(),
            command_code: command_code.to_owned(),
            cc_modifiers,
            platform_auth_pp_modifier,
            handles,
            params,
            handles_structure: None,
            params_structure: None,
        })
    }
}
