// Include the `items` module, which is generated from items.proto.
// It is important to maintain the same structure as in the proto.
pub mod metadata {
    include!(concat!(env!("OUT_DIR"), "/metadata.rs"));
}
