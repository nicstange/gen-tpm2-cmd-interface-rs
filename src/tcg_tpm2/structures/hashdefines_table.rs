// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::AlgMacroInvocationFinder;
use std::io;

#[derive(Clone, Debug)]
pub struct HashDefinesTable {
    pub info: CommonTableInfo,
    pub name: String,

    pub digest_size: u16,
    pub block_size: u16,
    pub der: Option<Vec<u8>>,
}

impl HashDefinesTable {
    fn read_der_byte_string(
        filename: &str,
        lineno: u32,
        member: &str,
        der_byte_string: &str,
    ) -> Result<Vec<u8>, io::Error> {
        // Format is octet0, octet1, ..., octetn
        let mut result = Vec::new();
        for b in der_byte_string.split(',') {
            let b = match b.trim().strip_prefix("0x") {
                Some(b) => u8::from_str_radix(b, 16),
                None => b.parse(),
            }
            .map_err(|_| {
                eprintln!(
                    "error: {}:{}: invalid DER byte string entry for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
            result.push(b);
        }

        Ok(result)
    }

    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        name: String,
        filename: &str,
        header_alg_macro_finder: &AlgMacroInvocationFinder,
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
        } else if col_headers[0] != "Name" {
            eprintln!(
                "error: {}:{}: unexpected column name header in first column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if col_headers[1] != "Value" {
            eprintln!(
                "error: {}:{}: unexpected column name header in second column",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut digest_size: Option<u16> = None;
        let mut block_size: Option<u16> = None;
        let mut der_size: Option<usize> = None;
        let mut der: Option<Vec<u8>> = None;
        let member_prefix = name.to_owned() + "_";
        for row in rows {
            let cols: Vec<&str> = row.1.split(';').map(|e| e.trim()).collect();
            if cols.len() < col_headers.len() {
                dbg!(cols);
                eprintln!(
                    "error: {}:{}: unexpected number of columns in table row",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            // Skip all-empty rows.
            if !cols.iter().any(|col| !col.is_empty()) {
                continue;
            }

            let name = cols[0];
            let value = cols[1];
            if name.is_empty() {
                eprintln!("error: {}:{}: no name in hash define", filename, row.0);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            } else if value.is_empty() {
                eprintln!(
                    "error: {}:{}: no replacement in hash define",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let mut alg_macro_finder = header_alg_macro_finder.clone_and_reset();
            let report_alg_finder_error =
                |e| AlgMacroInvocationFinder::report_err(filename, row.0, e);
            alg_macro_finder
                .search(name)
                .map_err(report_alg_finder_error)?;
            alg_macro_finder
                .search(value)
                .map_err(report_alg_finder_error)?;
            if alg_macro_finder.found_any() {
                eprintln!(
                    "error: {}:{}: !ALG macro invocations not supported in hash defines",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let name = name.strip_prefix(&member_prefix).unwrap_or(name);
            match name.to_ascii_lowercase().as_str() {
                "digest_size" => {
                    if digest_size.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"DIGEST_SIZE\" field in hash defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    digest_size = Some(value.parse().map_err(|_| {
                        eprintln!("error: {}:{}: invalid DIGEST_SIZE value", filename, row.0);
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?);
                }
                "block_size" => {
                    if block_size.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"BLOCK_SIZE\" field in hash defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    block_size = Some(value.parse().map_err(|_| {
                        eprintln!("error: {}:{}: invalid BLOCK_SIZE value", filename, row.0);
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?);
                }
                "der_size" => {
                    if der_size.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"DER_SIZE\" field in hash defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    der_size = Some(value.parse().map_err(|_| {
                        eprintln!("error: {}:{}: invalid DER_SIZE value", filename, row.0);
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?);
                }
                "der" => {
                    if der.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"DER\" field in hash defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    der = Some(Self::read_der_byte_string(filename, row.0, "DER", value)?);
                }
                _ => {
                    eprintln!(
                        "error: {}:{}: unrecognized field in hash defines table",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };
        }

        let digest_size = digest_size.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"DIGEST_SIZE\" field in hash defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let block_size = block_size.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"BLOCK_SIZE\" field in hash defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

        if let Some(der) = der.as_ref() {
            if let Some(der_size) = der_size {
                if der_size != der.len() {
                    eprintln!(
                        "error: {}:{}: inconsistent \"DER_SIZE\" field in hash defines table",
                        filename, header_row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            } else {
                eprintln!(
                    "error: {}:{}: \"DER\" without \"DER_SIZE\" field in hash defines table",
                    filename, header_row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        } else if der_size.is_some() {
                eprintln!(
                    "error: {}:{}: \"DER_SIZE\" without \"DER\" field in hash defines table",
                    filename, header_row.0
                );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        Ok(Self {
            info,
            name,
            digest_size,
            block_size,
            der,
        })
    }
}
