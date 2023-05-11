// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

pub mod command_table;
pub use command_table::CommandTable;

mod response_table;
pub use response_table::ResponseTable;

pub mod tables;
