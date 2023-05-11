// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::AlgMacroInvocationFinder;
use std::io;

#[derive(Clone, Debug)]
pub struct SymcipherDefinesTable {
    pub info: CommonTableInfo,
    pub name: String,

    pub key_sizes_bits: Vec<u16>,
    pub block_sizes_bits: Vec<u16>,
    pub rounds: Vec<u8>,
}

impl SymcipherDefinesTable {
    fn read_bit_sizes_array(
        filename: &str,
        lineno: u32,
        member: &str,
        bit_sizes_array: &str,
    ) -> Result<Vec<u16>, io::Error> {
        // Format is {bit_size0, bit_size1, ...,}
        let bit_sizes_array = bit_sizes_array
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or_else(|| {
                eprintln!(
                    "error: {}:{}: invalid bit sizes array format for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        let mut result = Vec::new();
        for b in bit_sizes_array.split(',') {
            let b = b.trim().parse().map_err(|_| {
                eprintln!(
                    "error: {}:{}: invalid bit size entry for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
            result.push(b);
        }

        Ok(result)
    }

    fn read_rounds_array(
        filename: &str,
        lineno: u32,
        member: &str,
        rounds_array: &str,
    ) -> Result<Vec<u8>, io::Error> {
        // Format is {round0, round1, ...,}
        let rounds_array = rounds_array
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or_else(|| {
                eprintln!(
                    "error: {}:{}: invalid rounds array format for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        let mut result = Vec::new();
        for b in rounds_array.split(',') {
            let b = b.trim().parse().map_err(|_| {
                eprintln!(
                    "error: {}:{}: invalid rounds entry for \"{}\"",
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

        let mut key_sizes_bits: Option<Vec<u16>> = None;
        let mut block_sizes_bits: Option<Vec<u16>> = None;
        let mut rounds: Option<Vec<u8>> = None;
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
                eprintln!(
                    "error: {}:{}: no name in symmetric cipher define",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            } else if value.is_empty() {
                eprintln!(
                    "error: {}:{}: no replacement in symmetric cipher define",
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
                eprintln!("error: {}:{}: !ALG macro invocations not supported in symmetric cipher defines",
                          filename, row.0);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let name = name.strip_prefix(&member_prefix).unwrap_or(name);
            match name.to_ascii_lowercase().as_str() {
                "key_sizes_bits" => {
                    if key_sizes_bits.is_some() {
                        eprintln!("error: {}:{}: duplicate \"KEY_SIZES_BITS\" field in symetric ciphers defines table",
                                  filename, row.0);
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    key_sizes_bits = Some(Self::read_bit_sizes_array(
                        filename,
                        row.0,
                        "KEY_SIZES_BITS",
                        value,
                    )?);
                }
                "block_sizes_bits" => {
                    if block_sizes_bits.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"BLOCK_SIZES_BITS\" field in symetric ciphers defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    block_sizes_bits = Some(Self::read_bit_sizes_array(
                        filename,
                        row.0,
                        "BLOCK_SIZES_BITS",
                        value,
                    )?);
                }
                "rounds" => {
                    if rounds.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"ROUNDS\" field in symetric ciphers defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    rounds = Some(Self::read_rounds_array(filename, row.0, "ROUNDS", value)?);
                }
                _ => {
                    eprintln!(
                        "error: {}:{}: unrecognized field in symmetric cipher defines table",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };
        }

        let key_sizes_bits = key_sizes_bits.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"KEY_SIZES_BITS\" field in symmetric cipher defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let block_sizes_bits = block_sizes_bits.ok_or_else(|| {
            eprintln!("error: {}:{}: missing \"BLOCK_SIZES_BITS\" field in symmetric cipher defines table",
                      filename, header_row.0);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let rounds = rounds.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"ROUNDS\" field in symmetric cipher defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

        if key_sizes_bits.len() != block_sizes_bits.len() {
            eprintln!(
                "error: {}:{}: inconsistent KEY- and BLOCK_SIZES_BITS array lengths in symmetric cipher defines table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if key_sizes_bits.len() != rounds.len() {
            eprintln!(
                "error: {}:{}: inconsistent KEY_SIZES_BITS and ROUNDS array lengths in symmetric cipher defines table",
                filename, header_row.0
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        Ok(Self {
            info,
            name,
            key_sizes_bits,
            block_sizes_bits,
            rounds,
        })
    }
}
