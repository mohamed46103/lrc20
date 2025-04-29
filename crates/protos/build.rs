use std::{env, error::Error};

const LRC_20_PROTO: &str = "../../proto";
pub const OUT_DIR: &str = "src/proto";

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("BUILD_SERVER").map_or(true, |val| val != "true") {
        println!("BUILD_SERVER is not set to true. Skipping protobufs generation.");
        return Ok(());
    }

    tonic_build::configure()
        .file_descriptor_set_path(format!("{OUT_DIR}/spark_service_descriptor.bin"))
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
