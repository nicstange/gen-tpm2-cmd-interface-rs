// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use regex::Regex;
use std::borrow;
use std::fs;
use std::io::{self, BufRead};
use std::iter::Iterator;
use std::path;

use crate::tcg_tpm2::commands::tables::{CommandsPartTables, CommandsPartTablesEntry};

use super::super::commands::CommandTable;
use super::super::commands::ResponseTable;
use super::super::structures::algs::{
    AlgMacroInvocationFinder, AlgMacroInvocationNormalizer, AlgorithmRegistry,
};
use super::super::structures::aliases_table::AliasesTable;
use super::super::structures::bits_table::BitsTable;
use super::super::structures::constants_table::ConstantsTable;
use super::super::structures::cppdefines_table::CppDefinesTable;
use super::super::structures::deps::ConfigDeps;
use super::super::structures::eccdefines_table::EccDefinesTable;
use super::super::structures::hashdefines_table::HashDefinesTable;
use super::super::structures::structure_table::StructureTable;
use super::super::structures::symcipherdefines_table::SymcipherDefinesTable;
use super::super::structures::table_common::CommonStructuresTableInfo;
use super::super::structures::type_table::TypeTable;
use super::super::structures::union_table::UnionTable;
use super::super::structures::StructuresPartTables;
use super::super::table_common::CommonTableInfo;
use super::Tables;

pub(in super::super) struct CSVInputRegexpsCache {
    pub re_alg_macro_invocation: Regex,
    pub re_common_header: Regex,
    pub re_structures_header: Regex,
    pub re_commands_header: Regex,
    pub re_struct_member_name: Regex,
    pub re_union_member_name: Regex,
    pub re_command_code_description: Regex,
    pub re_command_handle_description_platform_auth_pp: Regex,
    pub re_command_handle_description_auth_index: Regex,
    pub re_command_handle_description_auth_role: Regex,
}

impl CSVInputRegexpsCache {
    fn new() -> Self {
        let re_alg_macro_invocation = Regex::new(
            r"(?x)
            (?P<NLWB>\w)? # No word boundary at the left, the negative form is needed
                          # because the algorithm macro invocation's starting exclamation
                          # mark would unconditionally match a '\b'.
            !(?:ALG|alg)(?:\.(?P<MASK>[A-Za-z]+(\.[A-Za-z]+)*))?
            (?P<RWB>\b)?  # Word boundary on the right.
            ",
        )
        .unwrap();

        let re_common_header =
            Regex::new(r#"^(?:"(?P<SRCREF>[^"]+)"\s)\s*(?P<SUBJECT>.+)"#).unwrap();

        // Match table header subjects from TCG TPM2, part 2 "Structures"
        let re_structures_header = Regex::new(r"(?x)
            ^(?:
                (?P<DEFINITION>Definition\s+of\s+
                   (?:\{\s*(?P<DEP0>[\w!.]+)\s*\}\s*)? # optional {DEP} specifier, first possible position
                      (?:(?P<TYPE>
                         (?:\(\s*(?P<BASE>\w+)\s*\)\s*)? # optional (BASE) type specifier
                         (?:\{\s*(?P<DEP1>[\w!.]+)\s*\}\s*)? # optional {DEP} specifier, second possible position
                         (?P<NAME>[\w!.]+)\s+ # the name of what's getting defined
                         (?P<CLASS>Constants|Bits|Type|Structure|Union)\s*
                         (?:\([^)]*\)\s*)? # optional comment in parenthesises
                         (?:<[^>]*>\s*)? # optional <IN/OUT, S> specifier
                       )|
                       (?P<ALIAS>
                         (?:Base\s+Types|Types\s+for)\s*
                         (?:\{\s*(?P<DEP2>[\w!.]+)\s*\}\s*)? # optional {DEP} specifier, second possible position
                         \b.*
                       )
                   )
                )|
                (?P<DEFINES>Defines\s+for\s+
                      # An ECC curve specification table from the TCG Algorithm Registry.
                   (?:(?P<ECCDEFINES>[A-Z_0-9]+)\s+ECC|
                      # A hash algorithm description from from the TCG Algorithm Registry.
                      (?P<HASHDEFINES>.*)\s+Hash|
                      # A symmetric cipher algorithm description from from the TCG Algorithm Registry.
                      (?P<SYMCIPHERDEFINES>.*)\s+Symmetric\s+Cipher\s+Algorithm|
                      # A bunch of CPP-style defines of unknown category.
                      (?P<CPPDEFINES>.*)
                   )\s+(?:Values|Constants)
                )
            )$").unwrap();

        // Match table header subjects from TCG TPM2, part 3 "Commands"
        let re_commands_header =
            Regex::new(r"^(?P<NAME>\w+)\s+(?P<CLASS>Command|Response)\s*$").unwrap();

        // Match structure member name specifier from TCG TPM2, part2 "Structures"
        let re_struct_member_name = Regex::new(
            r"(?x)
            ^
            (?:\[\s*(?P<DISCR>\w+)\s*\]\s*)?
            (?P<NAME>\w+)\s*
            (?:(?:(?P<IS_SIZESPEC>=)|
                  (?:\[(?P<ARRAYSIZE>[^\]]+)\]))\s*)?
            (?:(?P<RANGE>\{[^\}]+\})\s*)?
            $",
        )
        .unwrap();

        // Match union member name specifier from TCG TPM2, part 2 "Structures"
        let re_union_member_name = Regex::new(
            r"(?x)
            ^
            (?P<NAME>[\w!.]+)\s*
            (?:\[(?P<ARRAYSIZE>[^\]]+)\]\s*)?
            $",
        )
        .unwrap();

        // Match the commandCode description from TCG TPM2, part 3 "Commands"
        let re_command_code_description = Regex::new(
            r"(?x)
            ^
            (?P<CC>[A-Za-z0-9_]+)\s*
            (?:\{\s*(?P<CCMOD>[^\}]+)\}\s*)?
            $",
        )
        .unwrap();

        // Match the handle description from TCG TPM2, part 3 "Commands" for
        // those TPM_RH_PLATFORM+PP/+{PP} modifiers.
        let re_command_handle_description_platform_auth_pp = Regex::new(
            r"(?x)
            \b
            TPM_RH_PLATFORM\s*\+\s*
            (?P<PPMOD>\{\s*\w+\s*\}|\w+)
            ",
        )
        .unwrap();

        // Match the handle description from TCG TPM2, part 3 "Commands" for
        // the associated Auth Index.
        let re_command_handle_description_auth_index = Regex::new(
            r"(?x)
            \b
            Auth\s+(?:Index|Handle)\s*:\s*(?P<AUTHINDEX>(?:\w+|None|none))
            \b",
        )
        .unwrap();

        // Match the handle description from TCG TPM2, part 3 "Commands" for
        // the associated Auth Role.
        let re_command_handle_description_auth_role = Regex::new(
            r"(?x)
            \b
            Auth\s+Role\s*:\s*(?P<AUTHROLE>\w+)
            \b",
        )
        .unwrap();

        CSVInputRegexpsCache {
            re_alg_macro_invocation,
            re_common_header,
            re_structures_header,
            re_commands_header,
            re_struct_member_name,
            re_union_member_name,
            re_command_code_description,
            re_command_handle_description_platform_auth_pp,
            re_command_handle_description_auth_index,
            re_command_handle_description_auth_role,
        }
    }
}

impl Tables {
    fn read_table(
        structures: &mut StructuresPartTables,
        commands: &mut Vec<CommandTable>,
        responses: &mut Vec<ResponseTable>,
        filename: &str,
        table_lines: &[(u32, String)],
        regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<(), io::Error> {
        let table_header_lineno = table_lines[0].0;
        let captures = match regexps_cache.re_common_header.captures(&table_lines[0].1) {
            None => {
                eprintln!(
                    "error: {}:{}: unrecognized table header format",
                    filename, table_header_lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            Some(captures) => captures,
        };

        let src_ref = captures.name("SRCREF").map(|s| s.as_str());
        let info = CommonTableInfo::new(src_ref);
        let table_lines = &table_lines[1..];
        let subject = captures.name("SUBJECT").unwrap().as_str().to_owned();
        if let Some(captures) = regexps_cache.re_structures_header.captures(&subject) {
            if table_lines.is_empty() {
                eprintln!(
                    "error: {}:{}: unexpected empty table",
                    filename, table_header_lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            if captures.name("DEFINITION").is_some() {
                let mut dep = None;
                for cap in ["DEP0", "DEP1", "DEP2"] {
                    dep = match captures.name(cap) {
                        Some(curdep) => {
                            if dep.is_some() {
                                eprintln!(
                                    "error: {}:{}: mutiple dependency specifiers in table header",
                                    filename, table_header_lineno
                                );
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                            Some(curdep)
                        }
                        None => dep,
                    };
                }
                let dep = dep.map(|dep_match| dep_match.as_str());
                let report_alg_finder_error =
                    |e| AlgMacroInvocationFinder::report_err(filename, table_header_lineno, e);
                let mut alg_macro_finder =
                    AlgMacroInvocationFinder::new(&regexps_cache.re_alg_macro_invocation);
                if let Some(dep) = dep {
                    alg_macro_finder
                        .search(dep)
                        .map_err(report_alg_finder_error)?;
                }

                if captures.name("TYPE").is_some() {
                    let name = captures.name("NAME").unwrap().as_str();
                    let alg_macro_in_name = alg_macro_finder
                        .search(name)
                        .map_err(report_alg_finder_error)?;
                    let base = captures.name("BASE").map(|base_match| base_match.as_str());

                    if let Some(base) = base {
                        alg_macro_finder
                            .search(base)
                            .map_err(report_alg_finder_error)?;
                    }
                    if alg_macro_finder.found_any() && !alg_macro_in_name {
                        eprintln!(
                            "error: {}:{}: no algorithm macro invocation in expanded table's name",
                            filename, table_header_lineno
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    } else if alg_macro_finder.found_any()
                        && alg_macro_finder.found_mask().is_none()
                    {
                        eprintln!(
                            "error: {}:{}: all algorithm macro invocations without mask specifiers",
                            filename, table_header_lineno
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    let mut alg_macro_normalizer =
                        AlgMacroInvocationNormalizer::new(&alg_macro_finder, false);
                    let name = alg_macro_normalizer.normalize(name).into_owned();
                    let base = base.map(|base| alg_macro_normalizer.normalize(base).into_owned());
                    let dep = dep.map(|dep| alg_macro_normalizer.normalize(dep));

                    let mut structures_info = CommonStructuresTableInfo::new();
                    if let Some(dep) = dep {
                        structures_info.deps.add(dep);
                    }
                    match captures.name("CLASS").unwrap().as_str() {
                        "Constants" => {
                            // If it's the TPM_ALG_ID table, create the algorithm registry from it
                            // alongside the usual ConstantsTable.
                            let mut is_alg_id = false;
                            if name == "TPM_ALG_ID" {
                                is_alg_id = true;
                                let alg_registry =
                                    AlgorithmRegistry::new_from_csv(filename, table_lines)?;
                                structures.set_alg_registry(alg_registry)?;
                            }
                            let is_ecc_curves = name == "TPM_ECC_CURVE";
                            let mut table = ConstantsTable::new_from_csv(
                                info,
                                structures_info,
                                name,
                                base,
                                filename,
                                &alg_macro_finder,
                                table_lines,
                                regexps_cache,
                            )?;
                            if is_alg_id {
                                // If the TPM_ALG_ID table, amend the entries by
                                // their resp. dependencies.
                                for entry in table.entries.iter_mut() {
                                    if let Some(alg) = entry.name.strip_prefix("TPM_ALG_") {
                                        if let Some(alg) =
                                            structures.alg_registry.as_ref().unwrap().lookup(alg)
                                        {
                                            entry.deps.merge_from(&alg.deps());
                                        }
                                    }
                                }
                            } else if is_ecc_curves {
                                // Likewise, if the TPM_ALG_ID table, amend the entries by
                                // corresponding dependencies.
                                for entry in table.entries.iter_mut() {
                                    if entry.name == "TPM_ECC_NONE" {
                                        continue;
                                    }
                                    let dep_name =
                                        entry.name.strip_prefix("TPM_").unwrap_or(&entry.name);
                                    let dep_name = dep_name.to_ascii_lowercase();
                                    let mut deps = ConfigDeps::new();
                                    deps.add(borrow::Cow::Owned(dep_name));
                                    entry.deps.merge_from(&deps);
                                }

                                // Also, construct a ECC discrete value range CPP define from the table.
                                structures.register_cppdefine(
                                    "ECC_CURVES".to_owned(),
                                    "{".to_owned()
                                        + table
                                            .entries
                                            .iter()
                                            .map(|e| e.name.as_str())
                                            .filter(|name| *name != "TPM_ECC_NONE")
                                            .collect::<Vec<&str>>()
                                            .join(", ")
                                            .as_str()
                                        + "}",
                                )?;
                            }
                            structures.push_constants_table(table)?;
                        }
                        "Bits" => {
                            let base = match base {
                                Some(base) => base,
                                None => {
                                    eprintln!("error: {}:{}: missing base type specifier for \"Bits\" table",
                                              filename, table_header_lineno);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            };
                            let table = BitsTable::new_from_csv(
                                info,
                                structures_info,
                                name,
                                base,
                                filename,
                                &alg_macro_finder,
                                table_lines,
                                regexps_cache,
                            )?;
                            structures.push_bits_table(table)?;
                        }
                        "Type" => {
                            let base = match base {
                                Some(base) => base,
                                None => {
                                    eprintln!("error: {}:{}: missing base type specifier for \"Type\" table",
                                              filename, table_header_lineno);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            };
                            let table = TypeTable::new_from_csv(
                                info,
                                structures_info,
                                name,
                                base,
                                filename,
                                &alg_macro_finder,
                                table_lines,
                                regexps_cache,
                            )?;
                            structures.push_type_table(table)?;
                        }
                        "Structure" => {
                            let table = StructureTable::new_from_csv(
                                info,
                                structures_info,
                                name,
                                filename,
                                &alg_macro_finder,
                                table_lines,
                                regexps_cache,
                            )?;
                            structures.push_structure_table(table)?;
                        }
                        "Union" => {
                            let table = UnionTable::new_from_csv(
                                info,
                                structures_info,
                                name,
                                filename,
                                &alg_macro_finder,
                                table_lines,
                                regexps_cache,
                            )?;
                            structures.push_union_table(table)?;
                        }
                        _ => unreachable!(),
                    };
                } else {
                    assert!(captures.name("ALIAS").is_some());
                    let mut alg_macro_normalizer =
                        AlgMacroInvocationNormalizer::new(&alg_macro_finder, false);
                    let dep = dep.map(|dep| alg_macro_normalizer.normalize(dep));
                    let mut structures_info = CommonStructuresTableInfo::new();
                    if let Some(dep) = dep {
                        structures_info.deps.add(dep);
                    }
                    let table = AliasesTable::new_from_csv(
                        info,
                        structures_info,
                        filename,
                        &alg_macro_finder,
                        table_lines,
                        regexps_cache,
                    )?;
                    structures.push_aliases_table(table)?;
                }
            } else {
                assert!(captures.name("DEFINES").is_some());
                if let Some(name) = captures.name("ECCDEFINES") {
                    let name = name.as_str();
                    let report_alg_finder_error =
                        |e| AlgMacroInvocationFinder::report_err(filename, table_header_lineno, e);
                    let mut alg_macro_finder =
                        AlgMacroInvocationFinder::new(&regexps_cache.re_alg_macro_invocation);
                    alg_macro_finder
                        .search(name)
                        .map_err(report_alg_finder_error)?;
                    if alg_macro_finder.found_any() {
                        eprintln!("error: {}:{}: !ALG macro invocations not supported in ECC curve defines",
                                  filename, table_header_lineno);
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }

                    let table = EccDefinesTable::new_from_csv(
                        info,
                        name.to_owned(),
                        filename,
                        &alg_macro_finder,
                        table_lines,
                        regexps_cache,
                    )?;
                    structures.push_ecc_defines_table(table)?;
                } else if let Some(name) = captures.name("HASHDEFINES") {
                    let name = name.as_str();
                    let report_alg_finder_error =
                        |e| AlgMacroInvocationFinder::report_err(filename, table_header_lineno, e);
                    let mut alg_macro_finder =
                        AlgMacroInvocationFinder::new(&regexps_cache.re_alg_macro_invocation);
                    alg_macro_finder
                        .search(name)
                        .map_err(report_alg_finder_error)?;
                    if alg_macro_finder.found_any() {
                        eprintln!(
                            "error: {}:{}: !ALG macro invocations not supported in hash defines",
                            filename, table_header_lineno
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }

                    let table = HashDefinesTable::new_from_csv(
                        info,
                        name.to_owned(),
                        filename,
                        &alg_macro_finder,
                        table_lines,
                        regexps_cache,
                    )?;

                    structures.register_cppdefine(
                        table.name.clone() + "_DIGEST_SIZE",
                        table.digest_size.to_string(),
                    )?;
                    structures.register_cppdefine(
                        table.name.clone() + "_BLOCK_SIZE",
                        table.block_size.to_string(),
                    )?;
                    structures.push_hash_defines_table(table)?;
                } else if let Some(name) = captures.name("SYMCIPHERDEFINES") {
                    let name = name.as_str();
                    let report_alg_finder_error =
                        |e| AlgMacroInvocationFinder::report_err(filename, table_header_lineno, e);
                    let mut alg_macro_finder =
                        AlgMacroInvocationFinder::new(&regexps_cache.re_alg_macro_invocation);
                    alg_macro_finder
                        .search(name)
                        .map_err(report_alg_finder_error)?;
                    if alg_macro_finder.found_any() {
                        eprintln!("error: {}:{}: !ALG macro invocations not supported in symmetric cipher defines",
                                  filename, table_header_lineno);
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    let table = SymcipherDefinesTable::new_from_csv(
                        info,
                        name.to_owned(),
                        filename,
                        &alg_macro_finder,
                        table_lines,
                        regexps_cache,
                    )?;
                    structures.register_cppdefine(
                        table.name.clone() + "_KEY_SIZES_BITS",
                        "{".to_owned()
                            + table
                                .key_sizes_bits
                                .iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<String>>()
                                .join(", ")
                                .as_str()
                            + "}",
                    )?;
                    structures.register_cppdefine(
                        table.name.clone() + "_BLOCK_SIZES_BITS",
                        "{".to_owned()
                            + table
                                .block_sizes_bits
                                .iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<String>>()
                                .join(", ")
                                .as_str()
                            + "}",
                    )?;
                    structures.push_symcipher_defines_table(table)?;
                } else {
                    let name = captures.name("CPPDEFINES").unwrap();
                    let name = name.as_str();
                    let report_alg_finder_error =
                        |e| AlgMacroInvocationFinder::report_err(filename, table_header_lineno, e);
                    let mut alg_macro_finder =
                        AlgMacroInvocationFinder::new(&regexps_cache.re_alg_macro_invocation);
                    alg_macro_finder
                        .search(name)
                        .map_err(report_alg_finder_error)?;
                    if alg_macro_finder.found_any() {
                        eprintln!("error: {}:{}: !ALG macro invocations not supported in CPP-style defines", filename,
                                  table_header_lineno);
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }

                    let table = CppDefinesTable::new_from_csv(
                        info,
                        name.to_owned(),
                        filename,
                        &alg_macro_finder,
                        table_lines,
                        regexps_cache,
                    )?;
                    for j in 0..table.entries.len() {
                        let entry = &table.entries[j];
                        structures
                            .register_cppdefine(entry.name.clone(), entry.replacement.clone())?;
                    }
                }
            }
        } else if let Some(captures) = regexps_cache.re_commands_header.captures(&subject) {
            if table_lines.is_empty() {
                eprintln!(
                    "error: {}:{}: unexpected empty table",
                    filename, table_header_lineno
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            let name = captures.name("NAME").unwrap().as_str();
            match captures.name("CLASS").unwrap().as_str() {
                "Command" => {
                    let table = CommandTable::new_from_csv(
                        info,
                        name,
                        filename,
                        table_lines,
                        regexps_cache,
                    )?;
                    commands.push(table);
                }
                "Response" => {
                    let table = ResponseTable::new_from_csv(
                        info,
                        name,
                        filename,
                        table_lines,
                        regexps_cache,
                    )?;
                    responses.push(table);
                }
                _ => unreachable!(),
            };
        } else {
            eprintln!("info: skipping unrecognized input table \"{}\"", subject);
        }

        Ok(())
    }

    fn read_file(
        structures: &mut StructuresPartTables,
        commands: &mut Vec<CommandTable>,
        responses: &mut Vec<ResponseTable>,
        filename: &path::Path,
        regexps_cache: &CSVInputRegexpsCache,
    ) -> Result<(), io::Error> {
        let f = match fs::File::open(filename) {
            Err(e) => {
                eprintln!("error: failed to open \"{}\"", filename.to_string_lossy());
                return Err(e);
            }
            Ok(f) => f,
        };
        let mut f = io::BufReader::new(f);

        let filename = filename.to_string_lossy();
        let mut table_lines: Vec<(u32, String)> = Vec::new();
        let mut lineno = 1;
        loop {
            let mut line = String::new();
            match f.read_line(&mut line) {
                Err(e) => {
                    eprintln!("error: failed to read from \"{}\"", filename);
                    return Err(e);
                }
                Ok(len) => {
                    if len == 0 {
                        if !table_lines.is_empty() {
                            eprintln!(
                                "error: {}:{}: unterminated table definition",
                                filename, table_lines[0].0
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        break;
                    }
                }
            }

            let line = line.trim();
            if line.starts_with("BEGINTABLE") {
                if !table_lines.is_empty() {
                    eprintln!(
                        "error: {}:{}: unterminated table definition",
                        filename, table_lines[0].0
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                let line = line.get(10..).unwrap().trim_start().to_owned();
                table_lines.push((lineno, line));
            } else if line.starts_with("ENDTABLE") {
                Self::read_table(
                    structures,
                    commands,
                    responses,
                    &filename,
                    &table_lines,
                    regexps_cache,
                )?;
                table_lines = Vec::new();
            } else if !line.is_empty() {
                table_lines.push((lineno, line.to_owned()));
            }

            lineno += 1;
        }

        Ok(())
    }

    fn pair_commands_responses(
        mut commands: Vec<CommandTable>,
        mut responses: Vec<ResponseTable>,
    ) -> Result<Vec<(CommandTable, ResponseTable)>, io::Error> {
        // Expected input order is that commands and corresponding responses appear
        // as pairs in the input sequence each. Avoid excessive element moves by
        // always working from the back and reversing the result at the end.
        let mut pairs = Vec::new();
        pairs.reserve_exact(commands.len());
        while let Some(command) = commands.pop() {
            let i = match responses.iter().rposition(|r| r.name == command.name) {
                Some(i) => i,
                None => {
                    eprintln!(
                        "error: command {} without response definition",
                        command.name
                    );
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };

            let response = responses.remove(i);
            pairs.push((command, response));
        }
        if !responses.is_empty() {
            eprintln!(
                "error: command {} response without command definition",
                responses[0].name
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        pairs.reverse();
        Ok(pairs)
    }

    pub fn read_from_csv_files<I>(files: I) -> Result<Self, io::Error>
    where
        I: Iterator,
        I::Item: AsRef<path::Path>,
    {
        let regexps_cache = CSVInputRegexpsCache::new();
        let mut structures = StructuresPartTables::new(&regexps_cache.re_alg_macro_invocation);
        let mut command_tables = Vec::new();
        let mut response_tables = Vec::new();

        for filename in files {
            Self::read_file(
                &mut structures,
                &mut command_tables,
                &mut response_tables,
                AsRef::<path::Path>::as_ref(&filename),
                &regexps_cache,
            )?;
        }

        if structures.alg_registry.is_none() {
            eprintln!("error: mandatory \"TPM_ALG_ID\" table not found");
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        let mut command_response_tables =
            Self::pair_commands_responses(command_tables, response_tables)?;
        let mut command_structures = Vec::new();
        let mut response_structures = Vec::new();
        for c in command_response_tables.iter() {
            command_structures.push(structures.push_command_structures(&c.0));
            response_structures.push(structures.push_response_structures(&c.1));
        }
        structures.resolve_all()?;
        structures.eval_all()?;

        // Propagate the config dependencies from the command code constants, if any,
        // to the corresponding top-level command/response PARAMS + HANDLE structures.
        let mut commands = CommandsPartTables::new();
        for (i, command_response_tables) in command_response_tables.drain(..).enumerate() {
            let command_structures = &command_structures[i];
            let response_structures = &response_structures[i];

            let (mut command_table, mut response_table) = command_response_tables;
            let resolved_command_code = structures
                .lookup_constant(&command_table.command_code)
                .ok_or_else(|| {
                    eprintln!(
                        "error: command {}: associated command code \"{}\" not found",
                        &command_table.name, &command_table.command_code
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            let command_code = structures.get_constant(resolved_command_code);
            let config_deps = &command_code.deps;

            for j in command_structures.iter().flatten() {
                let mut table = structures.get_structure_mut(*j);
                table.structures_info.deps.merge_from(config_deps);
            }
            command_table.handles_structure = command_structures[0];
            command_table.params_structure = command_structures[1];

            for j in response_structures.iter().flatten() {
                let mut table = structures.get_structure_mut(*j);
                table.structures_info.deps.merge_from(config_deps);
            }
            response_table.handles_structure = response_structures[0];
            response_table.params_structure = response_structures[1];

            commands.push(CommandsPartTablesEntry {
                command_code: resolved_command_code,
                deps: config_deps.clone(),
                command: command_table,
                response: response_table,
            });
        }

        Ok(Self {
            structures,
            commands,
        })
    }
}
