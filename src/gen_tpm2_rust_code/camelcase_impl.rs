// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::Tpm2InterfaceRustCodeGenerator;

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn camelize(s: &str) -> String {
        let mut result = String::new();
        let mut last_was_digit = false;
        for p in s.split('_') {
            if p.is_empty() {
                continue;
            }
            let first = p.chars().next().unwrap();
            if first.is_ascii_digit() && last_was_digit {
                result.push('_');
            }
            let tail = p.split_at(first.len_utf8()).1;
            result.push(first.to_ascii_uppercase());
            if tail
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                result += &tail.to_ascii_lowercase();
            } else {
                result += tail;
            }
            if let Some(c) = tail.chars().last() {
                last_was_digit = c.is_ascii_digit();
            }
        }
        result
    }

    pub(super) fn uncamelize(s: &str) -> String {
        let mut result = String::new();
        enum Last {
            First,
            Uppercase,
            Lowercase,
            Digit,
        }
        let mut last = Last::First;
        let mut n_uppercase = 0;
        for c in s.chars() {
            if c.is_ascii_uppercase() {
                if let Last::Lowercase = last {
                    result.push('_');
                } else if let Last::Digit = last {
                    result.push('_');
                }
                last = Last::Uppercase;
                n_uppercase += 1;
                result.push(c.to_ascii_lowercase());
            } else if c.is_ascii_lowercase() {
                if let Last::Uppercase = last {
                    if n_uppercase >= 2 {
                        result.push('_');
                    }
                } else if let Last::Digit = last {
                    result.push('_');
                }
                last = Last::Lowercase;
                n_uppercase = 0;
                result.push(c);
            } else if c.is_ascii_digit() {
                last = Last::Digit;
                n_uppercase = 0;
                result.push(c);
            } else {
                last = Last::First;
                result.push(c);
                n_uppercase = 0;
            }
        }
        result
    }

    pub(super) fn strip_table_prefix(table_name: &str, entry_name: &str) -> usize {
        let entry_name_parts = entry_name.split('_').collect::<Vec<&str>>();
        let mut prefix_end = 0;
        for table_name_part in table_name.split('_') {
            if prefix_end == entry_name_parts.len() {
                break;
            } else if table_name_part == entry_name_parts[prefix_end] {
                prefix_end += 1;
            } else if prefix_end > 0 {
                break;
            }
        }
        // Re-add prefix parts until the identifier is valid.
        while prefix_end > 0 {
            let entry_name_tail_parts = &entry_name_parts[prefix_end..];
            if entry_name_tail_parts.is_empty()
                || (entry_name_tail_parts.len() == 1 && entry_name_tail_parts[0].len() <= 1)
                || entry_name_tail_parts[0]
                    .chars()
                    .next()
                    .unwrap()
                    .is_ascii_digit()
            {
                prefix_end -= 1;
            } else {
                break;
            }
        }
        prefix_end
    }
}
