extern crate cc;


fn main() {
    cc::Build::new()
        .file("ext/md6/md6_compress.c")
        .file("ext/md6/md6_compression_hook.c")
        .file("ext/md6/md6_mode.c")
        .file("ext/md6/md6_nist.c")
        .compile("libmd6.a");
}
