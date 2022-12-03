fn main() {
    println!("cargo:rustc-link-lib=static=wpcap");
    println!("cargo:rustc-link-search=native=C:/Users/lucio/Desktop/rustProject/SDK_npcap/Lib/x64");
}