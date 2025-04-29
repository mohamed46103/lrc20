import os
import subprocess
from pathlib import Path

from grpc_tools import protoc


def main():
    repo_root = get_repo_root()
    proto_dir = repo_root / "proto"
    output_dir = repo_root / "python-sdk" / "lrc20-py" / "lrc20" / "protos"

    # Get protobuf include directory directly from grpc_tools
    proto_include = str(Path(protoc.__file__).parent / "_proto")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    # Create __init__.py in the output directory if it doesn't exist
    Path(output_dir / "__init__.py").touch(exist_ok=True)
    # Generate Python code from proto files
    protoc.main(
        [
            "",
            "-I" + str(proto_include),
            "-I" + str(proto_dir),
            "-I" + str(repo_root),
            "--python_out=" + str(output_dir),
            "--grpc_python_out=" + str(output_dir),
            f"--mypy_out=quiet:{output_dir}",  # 'quiet' reduces noise in output
            f"--mypy_grpc_out={output_dir}",
            str(proto_dir / "rpc" / "v1" / "types.proto"),
            str(proto_dir / "rpc" / "v1" / "service.proto"),
        ]
    )

    service_pb2_grpc = output_dir / "rpc" / "v1" / "service_pb2_grpc.py"
    service_pb2 = output_dir / "rpc" / "v1" / "service_pb2.py"
    types_pb2 = output_dir / "rpc" / "v1" / "types_pb2.py"

    service_pb2_grpc_pyi = output_dir / "rpc" / "v1" / "service_pb2_grpc.pyi"
    service_pb2_pyi = output_dir / "rpc" / "v1" / "service_pb2.pyi"
    types_pb2_pyi = output_dir / "rpc" / "v1" / "types_pb2.pyi"

    for file in [
        service_pb2,
        types_pb2,
        service_pb2_grpc,
        service_pb2_pyi,
        types_pb2_pyi,
        service_pb2_grpc_pyi,
    ]:
        if file.exists():
            content = file.read_text()
            content = content.replace("from rpc.v1", "from lrc20.protos.rpc.v1")
            file.write_text(content)


def get_repo_root() -> Path:
    """Get the git repository root path."""
    try:
        repo_root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
        return Path(repo_root)
    except subprocess.CalledProcessError:
        raise RuntimeError("Not in a git repository")


if __name__ == "__main__":
    main()
