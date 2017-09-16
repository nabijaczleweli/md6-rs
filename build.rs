extern crate gcc;


fn main() {
    gcc::Build::new()
        .file("ext/md6/md6_compress.c")
        .file("ext/md6/md6_mode.c")
        .file("ext/md6/md6_nist.c")
        .compile("libmd6.a");
}
