// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A TCG TPM2 Part 3 "Commands" "Response" table

use super::super::structures::tables::StructuresPartTablesStructureIndex;
use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::command_table::CommandTableParam;
use std::io;

#[derive(Debug)]
pub struct ResponseTableHandle {
    pub name: String,
    pub handle_type: String,
    pub handle_type_enable_conditional: bool,
}

type ResponseTableParam = CommandTableParam;

#[derive(Debug)]
pub struct ResponseTable {
    pub info: CommonTableInfo,
    pub name: String,
    pub handles: Vec<ResponseTableHandle>,
    pub params: Vec<ResponseTableParam>,

    pub handles_structure: Option<StructuresPartTablesStructureIndex>,
    pub params_structure: Option<StructuresPartTablesStructureIndex>,
}

impl ResponseTable {
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        name: &str,
        filename: &str,
        table_lines: &[(u32, String)],
        _regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        let header_row = &table_lines[0];
        let rows = &table_lines[1..];
        let col_headers: Vec<&str> = header_row.1.split(';').map(|e| e.trim()).collect();
        if col_headers.len() < 2 {
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
        }

        if rows.len() < 3 {
            eprintln!(
                "error: {}:{}: too few rows in response table",
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
        } else if tag_row[0] != "TPM_ST" || (tag_row[1] != "tag" && tag_row[1] != "Tag") {
            eprintln!(
                "error: {}:{}: expected \"tag\" for first entry in response table",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let response_size_row: Vec<&str> = rows[1].1.split(';').map(|e| e.trim()).collect();
        if response_size_row.len() != col_headers.len() {
            eprintln!(
                "error: {}:{}: unexpected number of columns in table row",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if response_size_row[0] != "UINT32" || response_size_row[1] != "responseSize" {
            eprintln!(
                "error: {}:{}: expected \"responseSize\" for second entry in response table",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let response_code_row: Vec<&str> = rows[2].1.split(';').map(|e| e.trim()).collect();
        if response_code_row.len() != col_headers.len() {
            eprintln!(
                "error: {}:{}: unexpected number of columns in table row",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if response_code_row[0] != "TPM_RC" || response_code_row[1] != "responseCode" {
            eprintln!(
                "error: {}:{}: expected \"responseCode\" for third entry in response table",
                filename, rows[0].0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut handles: Vec<ResponseTableHandle> = Vec::new();
        let mut params: Vec<ResponseTableParam> = Vec::new();
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
                let name = cols[1];
                if name.is_empty() {
                    eprintln!("error: {}:{}: empty handle name", filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                } else if name.starts_with('@') {
                    eprintln!(
                        "error: {}:{}: handle with authorization in response",
                        filename, row.0
                    );
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
                    eprintln!("error: {}:{}: empty handle type", filename, row.0);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                handles.push(ResponseTableHandle {
                    name: name.to_owned(),
                    handle_type: handle_type.to_owned(),
                    handle_type_enable_conditional,
                });
                continue;
            }

            assert!(in_param_area);
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

            params.push(ResponseTableParam {
                name: name.to_owned(),
                param_type: param_type.to_owned(),
                param_type_enable_conditional,
            });
        }

        Ok(Self {
            info,
            name: name.to_owned(),
            handles,
            params,
            handles_structure: None,
            params_structure: None,
        })
    }
}
