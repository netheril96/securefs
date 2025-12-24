use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .init();
    #[cfg(feature = "fuse")]
    {
        use securefs::lite::fuse::testing::simple_test_fuse_main;

        simple_test_fuse_main().expect("run should succeed");
    }

    #[cfg(windows)]
    {
        use securefs::lite::win::testing::test_main;

        test_main().expect("run should succeed");
    }
}
