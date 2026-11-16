#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(required = false)]
    a: String,
}
fn main() {}
