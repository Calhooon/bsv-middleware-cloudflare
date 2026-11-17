/// The work-budget fixtures (the vectors as payments, honest chains of
/// several widths and hops, a locktime, the hostile body) read the same
/// subject and verdict as the linking read (`payment_subject_read.rs`).
#[test]
fn work_budget_fixtures_read_the_same_subject() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let mut payments: Vec<(String, Payment)> = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| (s(case, "name").to_string(), vector_payment(case)))
        .collect();
    for (k, hops) in [(1, 1), (2, 3), (5, 2), (1, 8)] {
        payments.push((format!("honest {k}x{hops}"), honest(k, hops)));
    }
    payments.push((
        "honest with a locktime".into(),
        honest_with_lock(2, 2, 800_000),
    ));
    payments.push(("hostile".into(), hostile(16).0));
    let mut tally = subject_read::Tally::default();
    for (name, p) in &payments {
        for output_index in [p.output_index, 1, 2] {
            let terms = subject_read::Terms {
                server_key: &p.server_key,
                sender: &p.sender,
                prefix: &p.prefix,
                suffix: &p.suffix,
                output_index,
                required: p.required,
            };
            tally.add(subject_read::compare(name, &terms, &p.beef));
        }
    }
    println!("work-budget fixtures: {tally:?}");
    assert_eq!(tally.bodies, 3 * payments.len());
    assert_eq!(tally.link_bound_only, 0);
    assert!(tally.verified >= 6 + 8, "{tally:?}");
}

#[path = "support/subject_read.rs"]
mod subject_read;

include!("support/work_budget.rs");
