extern crate gcc;


fn main() {
    gcc::compile_library("libmd6.a", &["ext/md6/md6_compress.c", "ext/md6/md6_mode.c", "ext/md6/md6_nist.c"]);
}
