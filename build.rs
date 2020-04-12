// The following method for generating Rust code from .proto files is
// adapted from a recommendation of the `rust-protobuf` library:
//
// https://github.com/stepancheg/rust-protobuf/tree/master/protoc-rust

#[cfg(feature = "proto-gen")]
use protoc_rust;

// NOTE: When this feature is enabled, the build will always run, even if the
// .proto file has not changed. This happens because the .rs file always gets
// updated, since this function unconditionally creates it.
#[cfg(feature = "proto-gen")]
fn proto_gen() {
    protoc_rust::Codegen::new()
        .out_dir("proto/")
        .inputs(&["proto/metadata.proto"])
        .include(".")
        .run()
        .expect("Error during generation of Rust code from .proto files");
}

fn main() {
    #[cfg(feature = "proto-gen")]
    proto_gen()
}
