#[derive(sensr_schema::SensrOptions)]
#[serde(rename_all = "lowercase")]
#[derive(serde::Serialize)]
enum E {
    #[sensr(label = "keep")]
    Keep,
}
fn main() {}
