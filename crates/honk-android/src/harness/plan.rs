//! The run plan: a JSON file, checked once here (unknown fields, ranges, disjoint role CPUs) and
//! trusted from then on; and the order its measurements run in.

use super::load::WRITE_SIZE;
use crate::sys;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Flows of one bulk measurement.
pub const MAX_FLOWS: u32 = 256;
/// Every duration in a plan is at most this long, so a run always ends.
pub const MAX_SECONDS: u64 = 3600;
pub const MAX_REPEAT: u32 = 100;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub engines: Vec<Engine>,
    pub mtu: Vec<u16>,
    pub cases: Vec<Case>,
    pub pin: Pin,
    pub repeat: u32,
    pub cooldown_seconds: u64,
    pub interleave: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Hev,
    Honk,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    /// The generator sends, the sink receives.
    Up,
    /// The sink sends, the generator receives.
    Down,
}

/// One entry of `cases`; `bulk` expands to one measurement per flow count.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Case {
    Bulk {
        dir: Dir,
        flows: Vec<u32>,
        seconds: u64,
    },
    Idle {
        seconds: u64,
    },
    Tail {
        burst_seconds: u64,
        observe_seconds: u64,
    },
    Sparse {
        interval_ms: u64,
        bytes: u32,
        seconds: u64,
    },
}

/// The CPUs of each role, pairwise disjoint. `relay` is required when the plan runs hev.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub engine: Cpus,
    pub generator: Cpus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Cpus>,
    pub sink: Cpus,
}

/// A non-empty set of CPUs, ascending; written as a CPU list ("7", "0-1", "0-2,7").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cpus(Vec<usize>);

impl Cpus {
    pub fn as_slice(&self) -> &[usize] {
        &self.0
    }
}

impl fmt::Display for Cpus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&sys::format_cpu_list(&self.0))
    }
}

impl<'de> Deserialize<'de> for Cpus {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Cpus, D::Error> {
        let s = String::deserialize(d)?;
        let mut cpus = sys::parse_cpu_list(&s).map_err(serde::de::Error::custom)?;
        cpus.sort_unstable();
        cpus.dedup();
        if cpus.is_empty() {
            return Err(serde::de::Error::custom("empty CPU list"));
        }
        Ok(Cpus(cpus))
    }
}

impl Serialize for Cpus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// One measurement: a plan case at one of its flow counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step {
    /// 1-based repetition.
    pub rep: u32,
    pub engine: Engine,
    pub mtu: u16,
    /// Index of the case in `cases`.
    pub case: usize,
    /// A bulk case's flow count; 0 for idle, 1 for tail and sparse.
    pub flows: u32,
}

impl Plan {
    pub fn parse(json: &str) -> Result<Plan, String> {
        let plan: Plan = serde_json::from_str(json).map_err(|e| format!("plan: {e}"))?;
        plan.validate().map_err(|e| format!("plan: {e}"))?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), String> {
        if self.engines.is_empty() {
            return Err("engines is empty".into());
        }
        if (1..self.engines.len()).any(|i| self.engines[..i].contains(&self.engines[i])) {
            return Err("engines lists an engine twice".into());
        }
        if self.mtu.is_empty() || self.mtu.iter().any(|&m| m < 1280) {
            return Err("mtu must list values of at least 1280".into());
        }
        if self.cases.is_empty() {
            return Err("cases is empty".into());
        }
        for (i, case) in self.cases.iter().enumerate() {
            case.check().map_err(|e| format!("cases[{i}].{e}"))?;
        }
        if !(1..=MAX_REPEAT).contains(&self.repeat) {
            return Err(format!("repeat must be 1-{MAX_REPEAT}"));
        }
        if self.cooldown_seconds > MAX_SECONDS {
            return Err(format!("cooldown_seconds must be at most {MAX_SECONDS}"));
        }
        if self.engines.contains(&Engine::Hev) && self.pin.relay.is_none() {
            return Err("pin.relay is required to run hev".into());
        }
        self.pin.check_disjoint()
    }

    /// Every measurement in run order. With `interleave`, each repetition runs every MTU and
    /// case point once per engine, back to back, and even repetitions reverse the engine order
    /// (A B, B A, ...) so neither engine always runs warmer. Without it, each engine runs all
    /// its repetitions before the next engine starts.
    pub fn schedule(&self) -> Vec<Step> {
        let points: Vec<(usize, u32)> = self
            .cases
            .iter()
            .enumerate()
            .flat_map(|(i, case)| {
                let flows = match case {
                    Case::Bulk { flows, .. } => flows.clone(),
                    Case::Idle { .. } => vec![0],
                    Case::Tail { .. } | Case::Sparse { .. } => vec![1],
                };
                flows.into_iter().map(move |n| (i, n))
            })
            .collect();
        let mut out = Vec::new();
        let mut push = |rep, engine, mtu, (case, flows)| {
            out.push(Step {
                rep,
                engine,
                mtu,
                case,
                flows,
            })
        };
        if self.interleave {
            for rep in 1..=self.repeat {
                let mut engines = self.engines.clone();
                if rep % 2 == 0 {
                    engines.reverse();
                }
                for &mtu in &self.mtu {
                    for &point in &points {
                        for &engine in &engines {
                            push(rep, engine, mtu, point);
                        }
                    }
                }
            }
        } else {
            for &engine in &self.engines {
                for rep in 1..=self.repeat {
                    for &mtu in &self.mtu {
                        for &point in &points {
                            push(rep, engine, mtu, point);
                        }
                    }
                }
            }
        }
        out
    }
}

impl Case {
    /// Checks each field's range; the error names the field and its range.
    fn check(&self) -> Result<(), String> {
        let secs = |name: &str, v: u64| {
            if (1..=MAX_SECONDS).contains(&v) {
                Ok(())
            } else {
                Err(format!("{name}: 1-{MAX_SECONDS} s"))
            }
        };
        match *self {
            Case::Bulk {
                ref flows, seconds, ..
            } => {
                if flows.is_empty() || !flows.iter().all(|n| (1..=MAX_FLOWS).contains(n)) {
                    return Err(format!("flows: 1-{MAX_FLOWS} each, at least one"));
                }
                secs("seconds", seconds)
            }
            Case::Idle { seconds } => secs("seconds", seconds),
            Case::Tail {
                burst_seconds,
                observe_seconds,
            } => secs("burst_seconds", burst_seconds)
                .and_then(|()| secs("observe_seconds", observe_seconds)),
            Case::Sparse {
                interval_ms,
                bytes,
                seconds,
            } => {
                let max_ms = MAX_SECONDS * 1000;
                if !(1..=max_ms).contains(&interval_ms) {
                    return Err(format!("interval_ms: 1-{max_ms} ms"));
                }
                if !(1..=WRITE_SIZE as u32).contains(&bytes) {
                    return Err(format!("bytes: 1-{WRITE_SIZE}"));
                }
                secs("seconds", seconds)
            }
        }
    }
}

impl Pin {
    fn check_disjoint(&self) -> Result<(), String> {
        let roles = self.roles();
        for (i, (a, x)) in roles.iter().enumerate() {
            for (b, y) in &roles[i + 1..] {
                if let Some(c) = x.0.iter().find(|c| y.0.contains(c)) {
                    return Err(format!("pin.{a} and pin.{b} share CPU {c}"));
                }
            }
        }
        Ok(())
    }

    /// Every role this pin sets, with its name.
    fn roles(&self) -> Vec<(&'static str, &Cpus)> {
        let mut roles = vec![("engine", &self.engine), ("generator", &self.generator)];
        if let Some(relay) = &self.relay {
            roles.push(("relay", relay));
        }
        roles.push(("sink", &self.sink));
        roles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example in the design doc, with the relay pinned and the roles on separate CPUs.
    const EXAMPLE: &str = r#"{
      "engines": ["hev", "honk"],
      "mtu": [8500],
      "cases": [
        { "kind": "bulk", "dir": "up",   "flows": [1, 4], "seconds": 10 },
        { "kind": "bulk", "dir": "down", "flows": [1, 4], "seconds": 10 },
        { "kind": "idle", "seconds": 60 },
        { "kind": "tail", "burst_seconds": 5, "observe_seconds": 10 },
        { "kind": "sparse", "interval_ms": 1000, "bytes": 64, "seconds": 60 }
      ],
      "pin": { "engine": "7", "generator": "0-1", "relay": "6", "sink": "2-3" },
      "repeat": 5,
      "cooldown_seconds": 30,
      "interleave": true
    }"#;

    fn with(from: &str, to: &str) -> String {
        let json = EXAMPLE.replacen(from, to, 1);
        assert_ne!(json, EXAMPLE, "{from:?} not in the example");
        json
    }

    fn rejected(from: &str, to: &str) -> String {
        match Plan::parse(&with(from, to)) {
            Ok(_) => panic!("accepted {to:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn parses_the_example() {
        let p = Plan::parse(EXAMPLE).unwrap();
        assert_eq!(p.engines, vec![Engine::Hev, Engine::Honk]);
        assert_eq!(p.mtu, vec![8500]);
        assert_eq!(p.cases.len(), 5);
        assert_eq!(
            p.cases[3],
            Case::Tail {
                burst_seconds: 5,
                observe_seconds: 10
            }
        );
        assert_eq!(p.pin.engine.as_slice(), [7]);
        assert_eq!(p.pin.generator.as_slice(), [0, 1]);
        assert_eq!(p.pin.relay.as_ref().unwrap().as_slice(), [6]);
        assert_eq!((p.repeat, p.cooldown_seconds, p.interleave), (5, 30, true));
        let pin = serde_json::to_value(&p.pin).unwrap();
        assert_eq!(
            pin,
            serde_json::json!({"engine": "7", "generator": "0-1", "relay": "6", "sink": "2-3"})
        );
    }

    #[test]
    fn relay_pin_is_optional_without_hev() {
        let honk = with("\"hev\", \"honk\"", "\"honk\"").replace(", \"relay\": \"6\"", "");
        assert_eq!(Plan::parse(&honk).unwrap().pin.relay, None);
        let e = rejected(", \"relay\": \"6\"", "");
        assert!(e.contains("pin.relay is required"), "{e}");
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        for (from, to) in [
            ("\"repeat\": 5", "\"repeat\": 5, \"warmup\": 1"),
            (
                "\"kind\": \"idle\", \"seconds\": 60",
                "\"kind\": \"idle\", \"seconds\": 60, \"x\": 1",
            ),
            ("\"dir\": \"up\",", "\"dir\": \"up\", \"burst_seconds\": 1,"),
            ("\"sink\": \"2-3\"", "\"sink\": \"2-3\", \"runner\": \"4\""),
        ] {
            let e = rejected(from, to);
            assert!(e.contains("unknown field"), "{to}: {e}");
        }
        for (from, to) in [
            ("\"kind\": \"idle\"", "\"kind\": \"nap\""),
            ("\"hev\", \"honk\"", "\"hev\", \"wg\""),
            ("\"dir\": \"up\"", "\"dir\": \"sideways\""),
        ] {
            let e = rejected(from, to);
            assert!(e.contains("unknown variant"), "{to}: {e}");
        }
        let e = rejected("\"interleave\": true", "\"interleave2\": true");
        assert!(e.contains("unknown field"), "{e}");
        let e = rejected("\"cooldown_seconds\": 30,", "");
        assert!(e.contains("missing field"), "{e}");
    }

    #[test]
    fn rejects_out_of_range_values() {
        for (from, to, field) in [
            ("\"hev\", \"honk\"", "", "engines is empty"),
            ("\"hev\", \"honk\"", "\"honk\", \"honk\"", "engines lists"),
            ("[8500]", "[]", "mtu must"),
            ("[8500]", "[576]", "mtu must"),
            ("\"repeat\": 5", "\"repeat\": 0", "repeat must be 1-100"),
            ("\"repeat\": 5", "\"repeat\": 101", "repeat must be 1-100"),
            (
                "\"cooldown_seconds\": 30",
                "\"cooldown_seconds\": 3601",
                "cooldown_seconds must be at most 3600",
            ),
            (
                "\"flows\": [1, 4]",
                "\"flows\": [0]",
                "cases[0].flows: 1-256",
            ),
            (
                "\"flows\": [1, 4]",
                "\"flows\": []",
                "cases[0].flows: 1-256",
            ),
            (
                "\"flows\": [1, 4]",
                "\"flows\": [257]",
                "cases[0].flows: 1-256",
            ),
            (
                "\"flows\": [1, 4], \"seconds\": 10",
                "\"flows\": [1], \"seconds\": 0",
                "cases[0].seconds: 1-3600 s",
            ),
            (
                "\"idle\", \"seconds\": 60",
                "\"idle\", \"seconds\": 3601",
                "cases[2].seconds: 1-3600 s",
            ),
            (
                "\"burst_seconds\": 5",
                "\"burst_seconds\": 0",
                "cases[3].burst_seconds: 1-3600 s",
            ),
            (
                "\"observe_seconds\": 10",
                "\"observe_seconds\": 0",
                "cases[3].observe_seconds: 1-3600 s",
            ),
            (
                "\"interval_ms\": 1000",
                "\"interval_ms\": 0",
                "cases[4].interval_ms: 1-3600000 ms",
            ),
            ("\"bytes\": 64", "\"bytes\": 0", "cases[4].bytes: 1-65536"),
            (
                "\"bytes\": 64",
                "\"bytes\": 65537",
                "cases[4].bytes: 1-65536",
            ),
        ] {
            let e = rejected(from, to);
            assert!(e.contains(field), "{to}: {e}");
        }
        // Type errors come from serde, which names the line and column.
        for (from, to) in [
            ("[8500]", "[70000]"),
            ("\"cooldown_seconds\": 30", "\"cooldown_seconds\": -1"),
            ("\"engine\": \"7\"", "\"engine\": \"\""),
            ("\"engine\": \"7\"", "\"engine\": \"7-x\""),
            ("\"engine\": \"7\"", "\"engine\": \"9-8\""),
            ("\"engine\": \"7\"", "\"engine\": 7"),
        ] {
            let e = rejected(from, to);
            assert!(e.contains(" at line "), "{to}: {e}");
        }
    }

    #[test]
    fn rejects_overlapping_role_cpus() {
        for (from, to, pair) in [
            (
                "\"engine\": \"7\"",
                "\"engine\": \"1\"",
                "pin.engine and pin.generator share CPU 1",
            ),
            (
                "\"engine\": \"7\"",
                "\"engine\": \"5-7\"",
                "pin.engine and pin.relay share CPU 6",
            ),
            (
                "\"relay\": \"6\"",
                "\"relay\": \"3\"",
                "pin.relay and pin.sink share CPU 3",
            ),
            (
                "\"sink\": \"2-3\"",
                "\"sink\": \"0,4\"",
                "pin.generator and pin.sink share CPU 0",
            ),
            (
                "\"sink\": \"2-3\"",
                "\"sink\": \"7\"",
                "pin.engine and pin.sink share CPU 7",
            ),
        ] {
            let e = rejected(from, to);
            assert!(e.contains(pair), "{to}: {e}");
        }
    }

    #[test]
    fn interleaved_schedule_alternates_engine_order() {
        let p = Plan::parse(EXAMPLE).unwrap();
        let s = p.schedule();
        // 4 bulk points + idle + tail + sparse = 7 points, 2 engines, 5 repetitions.
        assert_eq!(s.len(), 7 * 2 * 5);
        let first: Vec<_> = s.iter().take(4).map(|x| (x.rep, x.engine)).collect();
        assert_eq!(
            first,
            vec![
                (1, Engine::Hev),
                (1, Engine::Honk),
                (1, Engine::Hev),
                (1, Engine::Honk)
            ]
        );
        assert_eq!((s[2].case, s[2].flows), (0, 4));
        let cases: Vec<usize> = s.iter().take(14).step_by(2).map(|x| x.case).collect();
        assert_eq!(cases, vec![0, 0, 1, 1, 2, 3, 4]);
        let flows: Vec<u32> = s.iter().take(14).step_by(2).map(|x| x.flows).collect();
        assert_eq!(flows, vec![1, 4, 1, 4, 0, 1, 1]);
        let rep2 = s.iter().position(|x| x.rep == 2).unwrap();
        assert_eq!(rep2, 14);
        assert_eq!(s[rep2].engine, Engine::Honk);
        assert_eq!(s[rep2 + 1].engine, Engine::Hev);
    }

    #[test]
    fn sequential_schedule_runs_one_engine_at_a_time() {
        let s = Plan::parse(&with("\"interleave\": true", "\"interleave\": false"))
            .unwrap()
            .schedule();
        assert_eq!(s.len(), 70);
        assert!(s[..35].iter().all(|x| x.engine == Engine::Hev));
        assert!(s[35..].iter().all(|x| x.engine == Engine::Honk));
        assert_eq!((s[0].rep, s[7].rep, s[34].rep), (1, 2, 5));
    }
}
