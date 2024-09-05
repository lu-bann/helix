fn main() {
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["src/gossiper/proto/gossipclient.proto"], &["src/gossiper/proto"])
        .unwrap();
}
