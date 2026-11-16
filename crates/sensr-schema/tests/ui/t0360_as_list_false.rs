#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(as_list = false)]
    a: String,
}
fn main() {}
