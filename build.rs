// The following method for generating Rust code from .proto files is
// adapted from a recommendation of the `rust-protobuf` library:
//
// https://github.com/stepancheg/rust-protobuf/tree/master/protoc-rust

#[cfg(feature = "proto-gen")]
use protobuf_codegen;
#[cfg(feature = "proto-gen")]
use std::fs;

// NOTE: When this feature is enabled, the build will always run, even if the
// .proto file has not changed. This happens because the .rs file always gets
// updated, since this function unconditionally creates it.
#[cfg(feature = "proto-gen")]
fn proto_gen() {
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir("proto/")
        .includes(&["proto/"])
        .input("proto/metadata.proto")
        .run_from_script();

    // Allow missing docs for the generated code, since its not under our
    // control.
    let proto_mod_rs =
        fs::read_to_string("proto/mod.rs").expect("Unable to open file");
    let header = "// Header added by Tindercrypt's build.rs script\n\
                  #![allow(missing_docs)]\n\n";
    let new_proto_mod_rs = header.to_owned() + &proto_mod_rs;
    fs::write("proto/mod.rs", new_proto_mod_rs).expect("Unable to write file");
}

fn main() {
    #[cfg(feature = "proto-gen")]
    proto_gen()
}
