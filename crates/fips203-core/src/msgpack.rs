//! MessagePack helpers — pure Rust, wire-compatible with [TheMapleseed/203] `fips203_msgpack.c` + MSGPACK-C.

use crate::error::{Error, Result};
use crate::frame::MAX_MSG;

const DECODE_MAX_DEPTH: usize = 64;
const DECODE_MAX_ALLOC: usize = 8 * 1024 * 1024;
const QUIT_MAX_DEPTH: usize = 8;
const QUIT_MAX_ALLOC: usize = 65536;
const FMT_MAX_DEPTH: usize = 48;

/// Every byte must be `<= 0x7F` (7-bit ASCII).
pub fn ascii_valid(s: &[u8]) -> bool {
    s.iter().all(|&b| b <= 0x7f)
}

fn pack_str(ascii: &[u8], out: &mut [u8]) -> Result<usize> {
    let len = ascii.len();
    let hdr = if len <= 31 {
        out[0] = 0xa0 | len as u8;
        1
    } else if len <= 255 {
        out[0] = 0xd9;
        out[1] = len as u8;
        2
    } else if len <= 0xffff {
        out[0] = 0xda;
        out[1] = (len >> 8) as u8;
        out[2] = len as u8;
        3
    } else if len <= 0xffff_ffff {
        out[0] = 0xdb;
        out[1] = (len >> 24) as u8;
        out[2] = (len >> 16) as u8;
        out[3] = (len >> 8) as u8;
        out[4] = len as u8;
        5
    } else {
        return Err(Error::Length);
    };
    if hdr + len > out.len() {
        return Err(Error::BufferTooSmall);
    }
    out[hdr..hdr + len].copy_from_slice(ascii);
    Ok(hdr + len)
}

/// Pack ASCII as one MessagePack string (`msgpack_pack_str` via MSGPACK-C).
pub fn pack_line(ascii: &[u8], out: &mut [u8]) -> Result<usize> {
    if ascii.len() > MAX_MSG {
        return Err(Error::Length);
    }
    if !ascii_valid(ascii) {
        return Err(Error::NotAscii);
    }
    pack_str(ascii, out)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    max_depth: usize,
    max_alloc: usize,
    cur_alloc: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], max_depth: usize, max_alloc: usize) -> Self {
        Self {
            data,
            pos: 0,
            max_depth,
            max_alloc,
            cur_alloc: 0,
        }
    }

    fn require(&self, need: usize) -> Result<()> {
        if need > self.data.len() || self.pos > self.data.len() - need {
            Err(Error::MsgPack)
        } else {
            Ok(())
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.require(len)?;
        let s = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    fn alloc_check(&mut self, size: usize) -> Result<()> {
        if self.max_alloc != 0 {
            if size > self.max_alloc || self.cur_alloc > self.max_alloc - size {
                return Err(Error::MsgPack);
            }
        }
        self.cur_alloc += size;
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_be_u16(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_be_u32(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_be_u64(&mut self) -> Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn read_be_i16(&mut self) -> Result<i16> {
        Ok(self.read_be_u16()? as i16)
    }

    fn read_be_i32(&mut self) -> Result<i32> {
        Ok(self.read_be_u32()? as i32)
    }

    fn read_be_i64(&mut self) -> Result<i64> {
        Ok(self.read_be_u64()? as i64)
    }

    fn read_f32(&mut self) -> Result<f32> {
        let b = self.read_bytes(4)?;
        Ok(f32::from_bits(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }

    fn read_f64(&mut self) -> Result<f64> {
        let b = self.read_bytes(8)?;
        Ok(f64::from_bits(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ])))
    }

    fn read_object(&mut self, depth: usize) -> Result<Value<'a>> {
        if self.max_depth != 0 && depth > self.max_depth {
            return Err(Error::MsgPack);
        }
        if self.pos >= self.data.len() {
            return Err(Error::MsgPack);
        }
        let b = self.read_u8()?;
        if b == 0xc0 {
            return Ok(Value::Nil);
        }
        if b == 0xc2 {
            return Ok(Value::Bool(false));
        }
        if b == 0xc3 {
            return Ok(Value::Bool(true));
        }
        if b <= 0x7f {
            return Ok(Value::UInt(b as u64));
        }
        if b >= 0xe0 {
            return Ok(Value::Int(b as i8 as i64));
        }
        if (b & 0xe0) == 0xa0 {
            let n = (b & 0x1f) as usize;
            return Ok(Value::Str(self.read_bytes(n)?));
        }
        if (b & 0xf0) == 0x90 {
            let n = (b & 0x0f) as usize;
            return self.read_array(n, depth);
        }
        if (b & 0xf0) == 0x80 {
            let n = (b & 0x0f) as usize;
            return self.read_map(n, depth);
        }
        match b {
            0xcc => Ok(Value::UInt(self.read_u8()? as u64)),
            0xcd => Ok(Value::UInt(self.read_be_u16()? as u64)),
            0xce => Ok(Value::UInt(self.read_be_u32()? as u64)),
            0xcf => Ok(Value::UInt(self.read_be_u64()?)),
            0xd0 => Ok(Value::Int(self.read_u8()? as i8 as i64)),
            0xd1 => Ok(Value::Int(self.read_be_i16()? as i64)),
            0xd2 => Ok(Value::Int(self.read_be_i32()? as i64)),
            0xd3 => Ok(Value::Int(self.read_be_i64()?)),
            0xca => Ok(Value::Float(self.read_f32()? as f64)),
            0xcb => Ok(Value::Float(self.read_f64()?)),
            0xd9 => {
                let n = self.read_u8()? as usize;
                Ok(Value::Str(self.read_bytes(n)?))
            }
            0xda => {
                let n = self.read_be_u16()? as usize;
                Ok(Value::Str(self.read_bytes(n)?))
            }
            0xdb => {
                let n = self.read_be_u32()? as usize;
                Ok(Value::Str(self.read_bytes(n)?))
            }
            0xc4 => {
                let n = self.read_u8()? as usize;
                Ok(Value::Bin(self.read_bytes(n)?))
            }
            0xc5 => {
                let n = self.read_be_u16()? as usize;
                Ok(Value::Bin(self.read_bytes(n)?))
            }
            0xc6 => {
                let n = self.read_be_u32()? as usize;
                Ok(Value::Bin(self.read_bytes(n)?))
            }
            0xdc => {
                let n = self.read_be_u16()? as usize;
                self.read_array(n, depth)
            }
            0xdd => {
                let n = self.read_be_u32()? as usize;
                self.read_array(n, depth)
            }
            0xde => {
                let n = self.read_be_u16()? as usize;
                self.read_map(n, depth)
            }
            0xdf => {
                let n = self.read_be_u32()? as usize;
                self.read_map(n, depth)
            }
            0xd4 => self.read_fixext(1, depth),
            0xd5 => self.read_fixext(2, depth),
            0xd6 => self.read_fixext(4, depth),
            0xd7 => self.read_fixext(8, depth),
            0xd8 => self.read_fixext(16, depth),
            0xc7 => self.read_ext8(),
            0xc8 => self.read_ext16(),
            0xc9 => self.read_ext32(),
            _ => Err(Error::MsgPack),
        }
    }

    fn read_array(&mut self, n: usize, depth: usize) -> Result<Value<'a>> {
        self.alloc_check(n.saturating_mul(std::mem::size_of::<Value<'a>>()))?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.read_object(depth + 1)?);
        }
        Ok(Value::Array(v))
    }

    fn read_map(&mut self, n: usize, depth: usize) -> Result<Value<'a>> {
        self.alloc_check(n.saturating_mul(2 * std::mem::size_of::<Value<'a>>()))?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let k = self.read_object(depth + 1)?;
            let val = self.read_object(depth + 1)?;
            v.push((k, val));
        }
        Ok(Value::Map(v))
    }

    fn read_fixext(&mut self, size: usize, _depth: usize) -> Result<Value<'a>> {
        let typ = self.read_u8()? as i8;
        if typ == -1 {
            if size == 4 {
                let sec = self.read_be_u32()? as i64;
                return Ok(Value::Timestamp(sec));
            }
            if size == 8 {
                return Ok(Value::Timestamp(self.read_be_i64()?));
            }
        }
        Ok(Value::Ext {
            typ,
            data: self.read_bytes(size)?,
        })
    }

    fn read_ext8(&mut self) -> Result<Value<'a>> {
        let size = self.read_u8()? as usize;
        let typ = self.read_u8()? as i8;
        if typ == -1 && (size == 4 || size == 8 || size == 12) {
            if size == 4 {
                return Ok(Value::Timestamp(self.read_be_u32()? as i64));
            }
            if size == 8 {
                return Ok(Value::Timestamp(self.read_be_i64()?));
            }
            let _ns = self.read_be_u32()?;
            return Ok(Value::Timestamp(self.read_be_i64()?));
        }
        Ok(Value::Ext {
            typ,
            data: self.read_bytes(size)?,
        })
    }

    fn read_ext16(&mut self) -> Result<Value<'a>> {
        let size = self.read_be_u16()? as usize;
        let typ = self.read_u8()? as i8;
        Ok(Value::Ext {
            typ,
            data: self.read_bytes(size)?,
        })
    }

    fn read_ext32(&mut self) -> Result<Value<'a>> {
        let size = self.read_be_u32()? as usize;
        let typ = self.read_u8()? as i8;
        Ok(Value::Ext {
            typ,
            data: self.read_bytes(size)?,
        })
    }

    fn read_top(&mut self) -> Result<Value<'a>> {
        self.cur_alloc = 0;
        let v = self.read_object(0)?;
        if self.pos != self.data.len() {
            return Err(Error::MsgPack);
        }
        Ok(v)
    }
}

#[derive(Debug)]
enum Value<'a> {
    Nil,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Float(f64),
    Str(&'a [u8]),
    Bin(&'a [u8]),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Timestamp(i64),
    Ext { typ: i8, data: &'a [u8] },
}

fn is_str<'a>(v: &Value<'a>) -> Option<&'a [u8]> {
    match v {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

/// Decode exactly one MsgPack string; copies payload into `buf`.
pub fn decode_string_only(data: &[u8], buf: &mut [u8]) -> Result<usize> {
    if buf.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut r = Reader::new(data, DECODE_MAX_DEPTH, DECODE_MAX_ALLOC);
    let obj = r.read_top()?;
    let s = is_str(&obj).ok_or(Error::MsgPack)?;
    if s.len() >= buf.len() {
        return Err(Error::MsgPack);
    }
    buf[..s.len()].copy_from_slice(s);
    buf[s.len()] = 0;
    Ok(s.len())
}

fn append(buf: &mut [u8], off: &mut usize, s: &str) -> Result<()> {
    let b = s.as_bytes();
    if *off + b.len() > buf.len() {
        return Err(Error::MsgPack);
    }
    buf[*off..*off + b.len()].copy_from_slice(b);
    *off += b.len();
    Ok(())
}

fn append_escaped(buf: &mut [u8], off: &mut usize, s: &[u8]) -> Result<()> {
    append(buf, off, "\"")?;
    for &c in s {
        if c == b'\\' || c == b'"' {
            append(buf, off, &format!("\\{}", c as char))?;
        } else if (32..127).contains(&c) {
            append(buf, off, &format!("{}", c as char))?;
        } else {
            append(buf, off, &format!("\\x{:02x}", c))?;
        }
    }
    append(buf, off, "\"")
}

fn fmt_obj(v: &Value<'_>, buf: &mut [u8], off: &mut usize, depth: usize) -> Result<()> {
    if depth > FMT_MAX_DEPTH {
        return Err(Error::MsgPack);
    }
    match v {
        Value::Nil => append(buf, off, "nil"),
        Value::Bool(b) => append(buf, off, if *b { "true" } else { "false" }),
        Value::UInt(u) => append(buf, off, &format!("{u}")),
        Value::Int(i) => append(buf, off, &format!("{i}")),
        Value::Float(f) => append(buf, off, &format!("{f:.17e}")),
        Value::Timestamp(t) => append(buf, off, &format!("timestamp({t})")),
        Value::Str(s) => append_escaped(buf, off, s),
        Value::Bin(b) => {
            append(buf, off, "bin(")?;
            let maxshow = b.len().min(48);
            for &byte in &b[..maxshow] {
                append(buf, off, &format!("{byte:02x}"))?;
            }
            if b.len() > 48 {
                append(buf, off, "...")?;
            }
            append(buf, off, ")")
        }
        Value::Array(a) => {
            append(buf, off, "[")?;
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    append(buf, off, ",")?;
                }
                fmt_obj(item, buf, off, depth + 1)?;
            }
            append(buf, off, "]")
        }
        Value::Map(m) => {
            append(buf, off, "{")?;
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    append(buf, off, ",")?;
                }
                fmt_obj(k, buf, off, depth + 1)?;
                append(buf, off, ":")?;
                fmt_obj(val, buf, off, depth + 1)?;
            }
            append(buf, off, "}")
        }
        Value::Ext { typ, data } => append(buf, off, &format!("ext(type={typ},len={})", data.len())),
    }
}

/// Format any single top-level MsgPack value for display (quoted strings, etc.).
pub fn format_decoded(data: &[u8], buf: &mut [u8]) -> Result<usize> {
    if buf.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut r = Reader::new(data, DECODE_MAX_DEPTH, DECODE_MAX_ALLOC);
    let obj = r.read_top()?;
    let mut off = 0usize;
    fmt_obj(&obj, buf, &mut off, 0)?;
    Ok(off)
}

/// `true` if plaintext is MsgPack string `"quit"`.
pub fn payload_is_quit(p: &[u8]) -> bool {
    let mut r = Reader::new(p, QUIT_MAX_DEPTH, QUIT_MAX_ALLOC);
    match r.read_top() {
        Ok(Value::Str(s)) => s == b"quit",
        _ => false,
    }
}

pub fn pack_line_vec(ascii: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; MAX_MSG + 64];
    let n = pack_line(ascii, &mut out)?;
    out.truncate(n);
    Ok(out)
}

pub fn decode_string_only_vec(data: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; MAX_MSG + 1];
    let n = decode_string_only(data, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
