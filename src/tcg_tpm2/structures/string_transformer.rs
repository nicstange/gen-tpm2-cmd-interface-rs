// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::borrow;

pub(super) trait StringTransformer {
    fn transform<'a>(&self, _: &'a str) -> borrow::Cow<'a, str>;

    fn transform_in_place(&self, s: &mut String) {
        let t = self.transform(s);
        if let borrow::Cow::Owned(_) = t {
            // The string has chaged.
            *s = t.into_owned();
        }
    }
}
