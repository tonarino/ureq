use ureq::Error;

pub fn main() -> Result<(), Error> {
    env_logger::init();

    let agent = ureq::builder().build();

    let body: String = agent
        .get("unix:/tmp/axum/helloworld")
        .call()?
        .into_string()?;

    dbg!(body);

    Ok(())
}
