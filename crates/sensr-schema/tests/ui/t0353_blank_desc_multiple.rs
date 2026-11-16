#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(multiple, blank_desc = "Pick some")]
    a: Vec<String>,
}
fn main() {}
