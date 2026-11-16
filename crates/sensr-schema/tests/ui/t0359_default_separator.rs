#[derive(sensr_schema::SensrModel)]
#[sensr(description = "M")]
struct M {
    #[sensr(as_list, separator = ",")]
    a: Vec<String>,
}
fn main() {}
