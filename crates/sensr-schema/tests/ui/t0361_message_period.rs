#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(required, message = "Not a valid number")]
    a: String,
}
fn main() {}
