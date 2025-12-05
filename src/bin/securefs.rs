use securefs::lite::fuse::testing::simple_test_fuse_main;

fn main() {
    env_logger::init();

    simple_test_fuse_main().expect("run should succeed");
}
