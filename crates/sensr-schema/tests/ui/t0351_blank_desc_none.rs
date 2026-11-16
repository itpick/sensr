#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(blank_desc = "None")]
    a: String,
}
fn main() {}
