#[cfg(feature = "fuse")]
fn main() {
    env_logger::init();
    use securefs::lite::fuse::testing::simple_test_fuse_main;

    simple_test_fuse_main().expect("run should succeed");
}

#[cfg(not(feature = "fuse"))]
fn main() {}
