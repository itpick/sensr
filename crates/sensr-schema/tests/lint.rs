//! `lint-model` rules as compile errors (T-0348..T-0363).

#[test]
fn lint_model_rules_t0348_t0349_t0350_t0351_t0352_t0353_t0354_t0355_t0359_t0360_t0361_t0362_t0363()
{
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
