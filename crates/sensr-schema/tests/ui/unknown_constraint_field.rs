#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(depend(with(nope)))]
    a: String,
}
fn main() {}
