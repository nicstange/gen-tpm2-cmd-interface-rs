// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// TCG TPM2 Part 2 "Structures" tables.

pub mod algs;
pub mod deps;
pub mod expr;
mod string_transformer;
pub mod value_range;

pub(super) mod aliases_table;
pub mod bits_table;
pub mod constants_table;
pub(super) mod cppdefines_table;
pub mod eccdefines_table;
pub mod hashdefines_table;
pub mod predefined;
pub mod structure_table;
pub mod symcipherdefines_table;
pub mod table_common;
pub mod tables;
pub mod type_table;
pub mod union_table;

pub use aliases_table::AliasesTable;
pub use bits_table::BitsTable;
pub use constants_table::ConstantsTable;
pub use cppdefines_table::CppDefinesTable;
pub use structure_table::StructureTable;
pub use tables::StructuresPartTables;
pub use type_table::TypeTable;
pub use union_table::UnionTable;
