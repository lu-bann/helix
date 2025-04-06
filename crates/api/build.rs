fn main() {
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .protoc_arg("--experimental_allow_proto3_optional") 
        .compile(&["src/gossiper/proto/gossipclient.proto"], &["src/gossiper/proto"])
        .unwrap();
}
