#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(required, blank_desc = "Pick one")]
    a: String,
}
fn main() {}
