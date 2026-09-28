// A tiny JSON writer for the two reports media-jail emits (--self-check and the
// per-run status line). Hand-written so the crate keeps no serde dependency;
// the shapes are small and fixed. Only what those reports need: objects,
// arrays, strings, bools and integers.

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A JSON value, kept simple: enough for the reports and nothing more.
pub enum Val {
    Str(String),
    Bool(bool),
    Int(i64),
    Null,
    Arr(Vec<Val>),
    Obj(Vec<(String, Val)>),
}

impl Val {
    pub fn s(v: impl Into<String>) -> Val {
        Val::Str(v.into())
    }
    pub fn write(&self, out: &mut String) {
        match self {
            Val::Str(s) => {
                out.push('"');
                out.push_str(&escape(s));
                out.push('"');
            }
            Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Val::Int(n) => out.push_str(&n.to_string()),
            Val::Null => out.push_str("null"),
            Val::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Val::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    out.push_str(&escape(k));
                    out.push_str("\":");
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

impl std::fmt::Display for Val {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quotes() {
        assert_eq!(escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
        assert_eq!(escape("\u{0001}"), "\\u0001");
    }

    #[test]
    fn writes_nested() {
        let v = Val::Obj(vec![
            ("ok".into(), Val::Bool(true)),
            ("n".into(), Val::Int(3)),
            ("list".into(), Val::Arr(vec![Val::s("a"), Val::Null])),
        ]);
        assert_eq!(v.to_string(), r#"{"ok":true,"n":3,"list":["a",null]}"#);
    }
}
