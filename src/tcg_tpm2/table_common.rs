// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#[derive(Clone, Debug)]
pub struct CommonTableInfo {
    pub src_ref: Option<String>,
}

impl CommonTableInfo {
    pub fn new(src_ref: Option<&str>) -> Self {
        Self {
            src_ref: src_ref.map(|s| s.to_owned()),
        }
    }

    pub fn add_alg_macro_indicator(&mut self, alg: &str) {
        // Amend the table number by an indication that it's been expanded.
        self.src_ref = match &self.src_ref {
            Some(src_ref) => {
                let mut src_ref = src_ref.clone();
                src_ref += ", expanded for ";
                src_ref += &alg.to_ascii_lowercase();
                Some(src_ref)
            }
            None => {
                let mut src_ref = "Expanded for ".to_owned();
                src_ref += &alg.to_ascii_lowercase();
                Some(src_ref)
            }
        };
    }
}
