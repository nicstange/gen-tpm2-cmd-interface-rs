// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use crate::tcg_tpm2::structures::deps::ConfigDeps;
use crate::tcg_tpm2::structures::tables::StructuresPartTablesConstantIndex;

use super::command_table::CommandTable;
use super::response_table::ResponseTable;

pub struct CommandsPartTablesEntry {
    pub command_code: StructuresPartTablesConstantIndex,
    pub deps: ConfigDeps,
    pub command: CommandTable,
    pub response: ResponseTable,
}

pub type CommandsPartTables = Vec<CommandsPartTablesEntry>;
