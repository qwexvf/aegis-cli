//! Order-independent structural JSON equality — the parity gate's core.
//!
//! Two `--json` outputs are "equal" for parity when they carry the same data
//! regardless of object-key order or array element order. Object keys are
//! matched by name; arrays are matched as multisets (each golden element must
//! have a canonical-equal partner in the actual, and vice-versa via the length
//! check). [`diff`] returns the first mismatch as a `$`-rooted path so a
//! failing case points straight at the divergent field.

use serde_json::Value;

/// Compare `golden` against `actual`. Returns `None` when structurally equal,
/// else a human-readable description of the first mismatch, path-scoped from
/// `$` (the document root).
pub fn diff(golden: &Value, actual: &Value) -> Option<String> {
    diff_at("$", golden, actual)
}

/// True when `golden` and `actual` are structurally equal (order-independent).
#[allow(dead_code)] // engine API exercised by the test suite
pub fn structural_eq(golden: &Value, actual: &Value) -> bool {
    diff(golden, actual).is_none()
}

fn diff_at(path: &str, golden: &Value, actual: &Value) -> Option<String> {
    match (golden, actual) {
        (Value::Object(g), Value::Object(a)) => {
            for k in g.keys() {
                if !a.contains_key(k) {
                    return Some(format!("{path}: key {k:?} in golden, missing in actual"));
                }
            }
            for k in a.keys() {
                if !g.contains_key(k) {
                    return Some(format!("{path}: key {k:?} in actual, absent from golden"));
                }
            }
            for (k, gv) in g {
                if let Some(m) = diff_at(&format!("{path}.{k}"), gv, &a[k]) {
                    return Some(m);
                }
            }
            None
        }
        (Value::Array(g), Value::Array(a)) => {
            if g.len() != a.len() {
                return Some(format!(
                    "{path}: array length {} in golden vs {} in actual",
                    g.len(),
                    a.len()
                ));
            }
            // Order-independent: consume each golden element's canonical-equal
            // partner from the actual side.
            let mut remaining: Vec<&Value> = a.iter().collect();
            for (i, gx) in g.iter().enumerate() {
                let cx = canonical(gx);
                match remaining.iter().position(|y| canonical(y) == cx) {
                    Some(pos) => {
                        remaining.remove(pos);
                    }
                    None => {
                        return Some(format!(
                            "{path}[{i}]: golden element has no match in actual: {cx}"
                        ));
                    }
                }
            }
            None
        }
        (g, a) if g == a => None,
        (g, a) => Some(format!("{path}: {g} != {a}")),
    }
}

/// Canonical, order-independent string form of a value: object keys sorted,
/// array elements sorted by their own canonical form. Used to compare array
/// elements as a multiset.
fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{k:?}:{}", canonical(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => {
            let mut parts: Vec<String> = a.iter().map(canonical).collect();
            parts.sort();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn equal_ignoring_object_key_order() {
        let g = json!({"a": 1, "b": 2});
        let a = json!({"b": 2, "a": 1});
        assert!(structural_eq(&g, &a));
        assert_eq!(diff(&g, &a), None);
    }

    #[test]
    fn equal_ignoring_array_order() {
        let g = json!({"findings": [{"id": "A"}, {"id": "B"}]});
        let a = json!({"findings": [{"id": "B"}, {"id": "A"}]});
        assert!(structural_eq(&g, &a));
    }

    #[test]
    fn nested_array_order_independence() {
        let g = json!([{"x": [1, 2, 3]}, {"y": ["p", "q"]}]);
        let a = json!([{"y": ["q", "p"]}, {"x": [3, 1, 2]}]);
        assert!(structural_eq(&g, &a));
    }

    #[test]
    fn scalar_mismatch_reports_path() {
        let g = json!({"score": 9.8});
        let a = json!({"score": 5.0});
        let m = diff(&g, &a).unwrap();
        assert!(m.contains("$.score"), "{m}");
    }

    #[test]
    fn missing_key_reported() {
        let g = json!({"a": 1, "b": 2});
        let a = json!({"a": 1});
        let m = diff(&g, &a).unwrap();
        assert!(
            m.contains("\"b\"") && m.contains("missing in actual"),
            "{m}"
        );
    }

    #[test]
    fn extra_key_reported() {
        let g = json!({"a": 1});
        let a = json!({"a": 1, "c": 3});
        let m = diff(&g, &a).unwrap();
        assert!(
            m.contains("\"c\"") && m.contains("absent from golden"),
            "{m}"
        );
    }

    #[test]
    fn array_length_mismatch_reported() {
        let g = json!({"items": [1, 2]});
        let a = json!({"items": [1, 2, 3]});
        let m = diff(&g, &a).unwrap();
        assert!(m.contains("$.items") && m.contains("length"), "{m}");
    }

    #[test]
    fn array_element_no_match_reported() {
        let g = json!([{"id": "A"}, {"id": "B"}]);
        let a = json!([{"id": "A"}, {"id": "C"}]);
        let m = diff(&g, &a).unwrap();
        assert!(m.contains("no match in actual"), "{m}");
    }

    #[test]
    fn type_mismatch_reported() {
        let g = json!({"v": [1]});
        let a = json!({"v": 1});
        let m = diff(&g, &a).unwrap();
        assert!(m.contains("$.v"), "{m}");
    }

    #[test]
    fn deep_nested_path_pinpointed() {
        let g = json!({"a": {"b": {"c": [{"d": 1}]}}});
        let a = json!({"a": {"b": {"c": [{"d": 2}]}}});
        // Array multiset: the {"d":1} element has no {"d":2} partner.
        let m = diff(&g, &a).unwrap();
        assert!(m.contains("$.a.b.c"), "{m}");
    }
}
