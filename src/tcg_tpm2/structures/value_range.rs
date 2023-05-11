// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// A value range or set of values commonly found within the
// TCG TPM2 Part 2 "Structures" tables.

use super::expr::{Expr, ExprParser, ExprResolvedId, ExprResolvedType};
use super::string_transformer::StringTransformer;
use std::io;

#[derive(Clone, Debug)]
pub enum ValueRange {
    Range {
        min_value: Option<Expr>,
        max_value: Option<Expr>,
    },
    Discrete(Vec<Expr>),
}

impl ValueRange {
    pub(super) fn new_from_csv<'a>(
        filename: &str,
        lineno: u32,
        range_spec: &'a str,
    ) -> Result<Option<(Self, &'a str)>, io::Error> {
        if range_spec.trim_start().strip_prefix('{').is_none() {
            return Ok(None);
        }

        return Self::parse(range_spec)
            .map_err(|err| {
                eprintln!("error: {}:{}: {}", filename, lineno, err);
                io::Error::from(io::ErrorKind::InvalidData)
            })
            .map(Some);
    }

    pub fn parse(range_spec: &str) -> Result<(Self, &str), &'static str> {
        let range_spec = match range_spec.trim_start().strip_prefix('{') {
            Some(range_spec) => range_spec,
            None => return Err("range specifier format unrecognized"),
        };

        let (range_spec, remainder) = match range_spec.split_once('}') {
            Some((range_spec, remainder)) => (range_spec, remainder),
            None => {
                return Err("unterminated range specifier");
            }
        };

        if let Some((min_spec, max_spec)) = range_spec.split_once(':') {
            if max_spec.find(':').is_some() {
                return Err("unrecognized range specfier format");
            }

            let min_spec = min_spec.trim_start();
            let mut min_value = None;
            if !min_spec.is_empty() {
                min_value = match ExprParser::parse(min_spec) {
                    Ok(expr) => Some(expr),
                    Err(_) => {
                        return Err("failed to parse lower range bound expression");
                    }
                };
            }

            let max_spec = max_spec.trim_start();
            let mut max_value = None;
            if !max_spec.is_empty() {
                max_value = match ExprParser::parse(max_spec) {
                    Ok(expr) => Some(expr),
                    Err(_) => {
                        return Err("failed to parse upper range bound expression");
                    }
                };
            }

            Ok((
                Self::Range {
                    min_value,
                    max_value,
                },
                remainder,
            ))
        } else {
            let mut values = Vec::new();
            for value in range_spec.split(',') {
                let value = match ExprParser::parse(value) {
                    Ok(expr) => expr,
                    Err(_) => {
                        return Err("failed to parse value list element expression");
                    }
                };
                values.push(value);
            }

            if values.is_empty() {
                return Err("empty value list");
            }

            Ok((Self::Discrete(values), remainder))
        }
    }

    pub(super) fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        match self {
            Self::Range {
                min_value,
                max_value,
            } => {
                let min_value = min_value.as_ref().map(|e| e.transform_strings(repl));
                let max_value = max_value.as_ref().map(|e| e.transform_strings(repl));
                Self::Range {
                    min_value,
                    max_value,
                }
            }
            Self::Discrete(values) => Self::Discrete(Vec::from_iter(
                values.iter().map(|e| e.transform_strings(repl)),
            )),
        }
    }

    pub(super) fn resolve_ids<I, T, U>(
        &mut self,
        resolve_expr_id: &mut I,
        resolve_sizeof_type: &mut T,
    ) -> Result<(), U>
    where
        U: Copy,
        I: FnMut(&str) -> Result<ExprResolvedId, U>,
        T: FnMut(&str) -> Result<ExprResolvedType, U>,
    {
        match self {
            Self::Range {
                min_value,
                max_value,
            } => {
                match min_value {
                    Some(value) => {
                        value.resolve_ids(resolve_expr_id, resolve_sizeof_type)?;
                    }
                    None => (),
                };
                match max_value {
                    Some(value) => {
                        value.resolve_ids(resolve_expr_id, resolve_sizeof_type)?;
                    }
                    None => (),
                };
                Ok(())
            }
            Self::Discrete(values) => {
                for value in values.iter_mut() {
                    value.resolve_ids(resolve_expr_id, resolve_sizeof_type)?;
                }
                Ok(())
            }
        }
    }
}
