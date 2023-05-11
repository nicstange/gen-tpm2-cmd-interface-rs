// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use crate::tcg_tpm2::structures::deps::{ConfigDeps, ConfigDepsDisjunction};

use super::Tpm2InterfaceRustCodeGenerator;

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    fn format_dep(dep: &str) -> String {
        if let Some(dep) = dep.strip_prefix('!') {
            format!("not(feature = \"{}\")", dep)
        } else {
            format!("feature = \"{}\"", dep)
        }
    }

    pub fn format_dep_conjunction(dep: &ConfigDeps) -> String {
        if dep.len() == 1 {
            Self::format_dep(&dep.deps[0])
        } else {
            let mut s = "all(".to_owned();
            s += &dep
                .deps
                .iter()
                .map(|d| Self::format_dep(d))
                .collect::<Vec<String>>()
                .join(", ");
            s += ")";
            s
        }
    }
    pub(super) fn format_deps(deps: &ConfigDepsDisjunction) -> String {
        assert!(!deps.is_unconditional_true());
        assert!(!deps.is_empty());
        if deps.deps.len() == 1 {
            return Self::format_dep_conjunction(&deps.deps[0]);
        }

        let (common, factored) = deps.factor();
        let mut s = if !common.is_unconditional_true() {
            let mut s = "all(".to_owned() + &Self::format_dep_conjunction(&common);
            s += ", ";
            s
        } else {
            "".to_owned()
        };
        s += "any(";
        s += &factored
            .deps
            .iter()
            .map(Self::format_dep_conjunction)
            .collect::<Vec<String>>()
            .join(", ");
        if !common.is_unconditional_true() {
            s += "))";
        } else {
            s += ")";
        }
        s
    }
}
