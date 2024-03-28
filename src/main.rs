// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io;
use std::path;

use clap::Parser;

mod tcg_tpm2;
use tcg_tpm2::structures::table_common::ClosureDepsFlags;

mod gen_tpm2_rust_code;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(name = "tables-file", short, long, action = clap::ArgAction::Append, required = true)]
    input_files: Vec<path::PathBuf>,

    #[arg(name = "enable-unsafe-unaligned-accesses", long)]
    enable_unaligned_accesses: bool,

    #[arg(name = "enable-unsafe-enum-transmute", long)]
    enable_enum_transmute: bool,

    #[arg(name = "enable-unsafe-inplace-unmarshal", long)]
    enable_in_place_unmarshal: bool,

    #[arg(name = "enable-unsafe-inplace-into-buffers-owner", long)]
    enable_in_place_into_bufs_owner: bool,

    #[arg(name = "gen-definition", short = 'd' , long, action = clap::ArgAction::Append)]
    definition_patterns_noncond: Vec<regex::Regex>,

    #[arg(name = "gen-definition-cond", short = 'D' , long, action = clap::ArgAction::Append)]
    definition_patterns_cond: Vec<regex::Regex>,

    #[arg(name = "gen-try-clone", short = 'l' , long, action = clap::ArgAction::Append)]
    try_clone_patterns_noncond: Vec<regex::Regex>,

    #[arg(name = "gen-try-clone-cond", short = 'L' , long, action = clap::ArgAction::Append)]
    try_clone_patterns_cond: Vec<regex::Regex>,

    #[arg(name = "gen-marshal", short = 'm', long, action = clap::ArgAction::Append)]
    marshal_patterns_noncond: Vec<regex::Regex>,

    #[arg(name = "gen-marshal-cond", short = 'M', long, action = clap::ArgAction::Append)]
    marshal_patterns_cond: Vec<regex::Regex>,

    #[arg(name = "gen-unmarshal", short = 'u', long, action = clap::ArgAction::Append)]
    unmarshal_patterns_noncond: Vec<regex::Regex>,

    #[arg(name = "gen-unmarshal-cond", short = 'U', long, action = clap::ArgAction::Append)]
    unmarshal_patterns_cond: Vec<regex::Regex>,

    #[arg(name = "gen-into-buffers-owner", short = 'o' , long, action = clap::ArgAction::Append)]
    into_bufs_owner_patterns_noncond: Vec<regex::Regex>,

    #[arg(name = "gen-into-buffers-owner-cond", short = 'O' , long, action = clap::ArgAction::Append)]
    into_bufs_owner_patterns_cond: Vec<regex::Regex>,

    #[arg(name = "gen-commands-macro", short = 'c', long)]
    gen_commands_macro: bool,
}

fn main() -> Result<(), io::Error> {
    let cli = Cli::parse();

    let mut tables = tcg_tpm2::tables::Tables::read_from_csv_files(cli.input_files.iter())?;

    for p in cli.definition_patterns_noncond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::PUBLIC_DEFINITION, p, false)?;
    }
    for p in cli.definition_patterns_cond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::PUBLIC_DEFINITION, p, true)?;
    }
    for p in cli.unmarshal_patterns_noncond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_UNMARSHAL, p, false)?;
    }
    for p in cli.unmarshal_patterns_cond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_UNMARSHAL, p, true)?;
    }
    for p in cli.marshal_patterns_noncond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_MARSHAL, p, false)?;
    }
    for p in cli.marshal_patterns_cond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_MARSHAL, p, true)?;
    }
    for p in cli.try_clone_patterns_noncond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_TRY_CLONE, p, false)?;
    }
    for p in cli.try_clone_patterns_cond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_TRY_CLONE, p, true)?;
    }
    for p in cli.into_bufs_owner_patterns_noncond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER, p, false)?;
    }
    for p in cli.into_bufs_owner_patterns_cond.iter() {
        tables
            .structures
            .set_closure_deps_for(ClosureDepsFlags::EXTERN_INTO_BUFS_OWNER, p, true)?
    }
    tables.structures.propagate_closure_deps()?;

    let codegen = gen_tpm2_rust_code::Tpm2InterfaceRustCodeGenerator::new(&tables);
    codegen.generate(
        &mut io::stdout(),
        cli.enable_unaligned_accesses,
        cli.enable_enum_transmute,
        cli.enable_in_place_unmarshal,
        cli.enable_in_place_into_bufs_owner,
        cli.gen_commands_macro,
    )?;

    Ok(())
}
