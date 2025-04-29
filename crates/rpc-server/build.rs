use std::{env, error::Error};

const LRC_20_PROTO: &str = "../../proto";
const OUT_DIR: &str = "src/proto";

fn main() -> Result<(), Box<dyn Error>> {
    let build_enabled = env::var("BUILD_ENABLED").map(|v| v == "1").unwrap_or(false);

    if !build_enabled {
        return Ok(());
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir(OUT_DIR)
        .compile_protos(
            &[proto_path("v1", "types"), proto_path("v1", "service")],
            &[LRC_20_PROTO],
        )?;

    Ok(())
}

fn proto_path(version: &str, proto_file: &str) -> String {
    format!("{}/rpc/{version}/{proto_file}.proto", LRC_20_PROTO)
}
