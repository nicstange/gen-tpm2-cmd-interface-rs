// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io;
use std::mem;

pub struct CodeWriter<W: io::Write> {
    out: W,
}

impl<W: io::Write> CodeWriter<W> {
    pub fn new(out: W) -> Self {
        CodeWriter { out }
    }

    pub fn make_writer(&mut self) -> IndentedCodeWriter<'_, W> {
        IndentedCodeWriter::new(IndentedCodeWriterParent::Root(self), 0)
    }
}

enum IndentedCodeWriterParent<'a, W: io::Write> {
    Root(&'a mut CodeWriter<W>),
    Indented(&'a mut IndentedCodeWriter<'a, W>),
}

pub struct IndentedCodeWriter<'a, W: io::Write> {
    parent: IndentedCodeWriterParent<'a, W>,
    indentation: u8,
    line_buffer: Vec<u8>,
}

impl<'a, W: io::Write> IndentedCodeWriter<'a, W> {
    fn new(parent: IndentedCodeWriterParent<'a, W>, indentation: u8) -> Self {
        Self {
            parent,
            indentation,
            line_buffer: Vec::new(),
        }
    }

    pub fn make_indent<'b>(&'b mut self) -> IndentedCodeWriter<'b, W>
    where
        'a: 'b,
    {
        assert!(self.line_buffer.is_empty());
        let indentation = self.indentation + 1;
        // Self is invariant over 'a, due to the invariant mut reference in
        // parent. Shorten the lifetime to 'b.
        let s = unsafe { mem::transmute::<&'b mut Self, &'b mut IndentedCodeWriter<'b, W>>(self) };
        IndentedCodeWriter::<'b, W>::new(IndentedCodeWriterParent::Indented(s), indentation)
    }

    pub fn make_same_indent<'b>(&'b mut self) -> IndentedCodeWriter<'b, W>
    where
        'a: 'b,
    {
        assert!(self.line_buffer.is_empty());
        let indentation = self.indentation;
        // Self is invariant over 'a, due to the invariant mut reference in
        // parent. Shorten the lifetime to 'b.
        let s = unsafe { mem::transmute::<&'b mut Self, &'b mut IndentedCodeWriter<'b, W>>(self) };
        IndentedCodeWriter::<'b, W>::new(IndentedCodeWriterParent::Indented(s), indentation)
    }

    fn get_wrapped_writer(&mut self) -> &mut W {
        let mut parent = &mut self.parent;
        {
            loop {
                match parent {
                    IndentedCodeWriterParent::Indented(indented) => parent = &mut indented.parent,
                    IndentedCodeWriterParent::Root(writer) => break &mut writer.out,
                }
            }
        }
    }
}

impl<'a, W: io::Write> io::Write for IndentedCodeWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let buf_len = buf.len();
        let mut line_buffer = std::mem::take(&mut self.line_buffer);
        let indentation = self.indentation;
        let writer = self.get_wrapped_writer();
        let mut buf = buf;
        while let Some(line_end) = buf.iter().position(|c| *c == b'\n') {
            if !line_buffer.is_empty() || line_end != 0 {
                for _ in 0..indentation {
                    writer.write_all(b"    ")?;
                }
            }
            writer.write_all(&line_buffer)?;
            line_buffer.clear();
            writer.write_all(&buf[..line_end + 1])?;
            buf = &buf[line_end + 1..];
        }

        line_buffer.extend_from_slice(buf);
        self.line_buffer = line_buffer;
        Ok(buf_len)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.get_wrapped_writer().flush()
    }
}
