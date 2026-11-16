#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(required, default = "")]
    a: String,
}
fn main() {}
