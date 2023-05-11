// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::super::table_common::CommonTableInfo;
use super::super::tables::read_csv_impl::CSVInputRegexpsCache;
use super::algs::AlgMacroInvocationFinder;
use std::io;

#[derive(Clone, Debug)]
pub struct EccDefinesTable {
    pub info: CommonTableInfo,
    pub name: String,

    pub curve_id: String,
    pub key_size: u16,
    pub kdf: (String, String),
    pub sign: (String, String),

    pub p: Vec<u8>,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub g_x: Vec<u8>,
    pub g_y: Vec<u8>,
    pub n: Vec<u8>,
    pub h: Vec<u8>,
}

impl EccDefinesTable {
    fn read_byte_string(
        filename: &str,
        lineno: u32,
        member: &str,
        byte_string: &str,
    ) -> Result<Vec<u8>, io::Error> {
        // Format is {n, {octet0, octet1, ..., octetn}}
        let (len, bytes) = byte_string
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|s| s.split_once(','))
            .map(|(len, bytes)| (len.trim(), bytes.trim()))
            .ok_or_else(|| {
                eprintln!(
                    "error: {}:{}: invalid byte string format for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        let len = len.parse::<usize>().map_err(|_| {
            eprintln!(
                "error: {}:{}: invalid length specifier in byte string for \"{}\"",
                filename, lineno, member
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

        let bytes = bytes
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or_else(|| {
                eprintln!(
                    "error: {}:{}: invalid byte string format for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        let mut result = Vec::new();
        for b in bytes.split(',') {
            let b = match b.trim().strip_prefix("0x") {
                Some(b) => u8::from_str_radix(b, 16),
                None => b.parse(),
            }
            .map_err(|_| {
                eprintln!(
                    "error: {}:{}: invalid byte string entry for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
            result.push(b);
        }

        if len != result.len() {
            eprintln!(
                "error: {}:{}: inconsistent byte string length specifier for \"{}\"",
                filename, lineno, member
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        Ok(result)
    }

    fn read_alg_id_pair(
        filename: &str,
        lineno: u32,
        member: &str,
        pair: &str,
    ) -> Result<(String, String), io::Error> {
        // Format is {TPM_ALG_*, TPM_ALG_*}
        pair.trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|s| s.split_once(','))
            .map(|(alg0, alg1)| (alg0.trim().to_owned(), alg1.trim().to_owned()))
            .ok_or_else(|| {
                eprintln!(
                    "error: {}:{}: invalid algorithm specification for \"{}\"",
                    filename, lineno, member
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })
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
        } else if col_headers[0] != "Parameter" {
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

        let mut curve_id: Option<String> = None;
        let mut key_size: Option<u16> = None;
        let mut kdf: Option<(String, String)> = None;
        let mut sign: Option<(String, String)> = None;
        let mut p: Option<Vec<u8>> = None;
        let mut a: Option<Vec<u8>> = None;
        let mut b: Option<Vec<u8>> = None;
        let mut g_x: Option<Vec<u8>> = None;
        let mut g_y: Option<Vec<u8>> = None;
        let mut n: Option<Vec<u8>> = None;
        let mut h: Option<Vec<u8>> = None;
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
                eprintln!("error: {}:{}: no name in ECC curve define", filename, row.0);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            } else if value.is_empty() {
                eprintln!(
                    "error: {}:{}: no replacement in ECC curve define",
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
                    "error: {}:{}: !ALG macro invocations not supported in ECC curve defines",
                    filename, row.0
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            match name.to_ascii_lowercase().as_str() {
                "curveid" => {
                    if curve_id.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"curveID\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    curve_id = Some(value.to_owned());
                }
                "keysize" => {
                    if key_size.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"keySize\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    key_size = Some(value.parse().map_err(|_| {
                        eprintln!("error: {}:{}: invalid keySize value", filename, row.0);
                        io::Error::from(io::ErrorKind::InvalidData)
                    })?);
                }
                "kdf" => {
                    if kdf.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"kdf\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    kdf = Some(Self::read_alg_id_pair(filename, row.0, "kdf", value)?);
                }
                "sign" => {
                    if sign.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"sign\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    sign = Some(Self::read_alg_id_pair(filename, row.0, "sign", value)?);
                }
                "p" => {
                    if p.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"p\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    p = Some(Self::read_byte_string(filename, row.0, "p", value)?);
                }
                "a" => {
                    if a.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"a\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    a = Some(Self::read_byte_string(filename, row.0, "a", value)?);
                }
                "b" => {
                    if b.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"b\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    b = Some(Self::read_byte_string(filename, row.0, "b", value)?);
                }
                "gx" => {
                    if g_x.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"gX\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    g_x = Some(Self::read_byte_string(filename, row.0, "gX", value)?);
                }
                "gy" => {
                    if g_y.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"gY\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    g_y = Some(Self::read_byte_string(filename, row.0, "gY", value)?);
                }
                "n" => {
                    if n.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"n\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    n = Some(Self::read_byte_string(filename, row.0, "n", value)?);
                }
                "h" => {
                    if h.is_some() {
                        eprintln!(
                            "error: {}:{}: duplicate \"h\" field in ECC defines table",
                            filename, row.0
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    h = Some(Self::read_byte_string(filename, row.0, "h", value)?);
                }
                _ => {
                    eprintln!(
                        "error: {}:{}: unrecognized field in ECC defines table",
                        filename, row.0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };
        }

        let curve_id = curve_id.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"curveID\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let key_size = key_size.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"keySize\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let kdf = kdf.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"kdf\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let sign = sign.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"sign\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let p = p.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"p\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let a = a.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"a\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let b = b.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"b\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let g_x = g_x.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"gX\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let g_y = g_y.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"gY\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let n = n.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"n\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let h = h.ok_or_else(|| {
            eprintln!(
                "error: {}:{}: missing \"h\" field in ECC defines table",
                filename, header_row.0
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

        Ok(Self {
            info,
            name,
            curve_id,
            key_size,
            kdf,
            sign,
            p,
            a,
            b,
            g_x,
            g_y,
            n,
            h,
        })
    }
}
