#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(default = "x")]
    a: String,
}
fn main() {}
