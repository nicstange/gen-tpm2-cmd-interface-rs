// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

pub(super) mod read_csv_impl;
use super::commands::tables::CommandsPartTables;
use super::structures::tables::StructuresPartTables;

pub struct Tables {
    pub structures: StructuresPartTables,
    pub commands: CommandsPartTables,
}
