// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::AlgMacroInvocationFinder;
use std::io;

#[derive(Clone, Debug)]
pub struct CppDefinesTableEntry {
    pub name: String,
    pub replacement: String,
}

impl CppDefinesTableEntry {
    fn new(name: String, replacement: String) -> Self {
        Self { name, replacement }
    }
}

#[derive(Clone, Debug)]
pub struct CppDefinesTable {
    #[allow(unused)]
    info: CommonTableInfo,
    pub name: String,
    pub entries: Vec<CppDefinesTableEntry>,
}

impl CppDefinesTable {
    pub(in super::super) fn new_from_csv(
        info: CommonTableInfo,
        name: String,
        filename: &str,
        header_alg_macro_finder: &AlgMacroInvocationFinder,
        table_lines: &[(u32, String)],
        _regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<Self, io::Error> {
        if header_alg_macro_finder.found_any() {}
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

        let mut entries = Vec::new();
        for row in rows {
            let cols: Vec<&str> = row.1.split(';').map(|e| e.trim()).collect();
            if cols.len() != col_headers.len() {
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
            let replacement = cols[1];
            if name.is_empty() {
                eprintln!("error: {}:{}: no name in CPP-style define", filename, row.0);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            } else if replacement.is_empty() {
                eprintln!(
                    "error: {}:{}: no replacement in CPP-style define",
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
                .search(replacement)
                .map_err(report_alg_finder_error)?;
            if alg_macro_finder.found_any() {
                eprintln!(
                    "error: {}:{}: !ALG macro invocations not supported in CPP-style defines",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            entries.push(CppDefinesTableEntry::new(
                name.to_owned(),
                replacement.to_owned(),
            ));
        }

        Ok(Self {
            info,
            name,
            entries,
        })
    }
}
