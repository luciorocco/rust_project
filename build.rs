fn main() {
    println!("cargo:rustc-link-lib=static=wpcap");
    println!("cargo:rustc-link-search=native=C:/Users/lucio/Desktop/rustProject/SDK_npcap/Lib/x64");
    //println!("cargo:rustc-link-search=native=C:/Users/Simone/Desktop/PDS/npcap-sdk-1.13/Lib/x64");
    //println!("cargo:rustc-link-search=native=C:/Users/Utente/OneDrive - Politecnico di Bari/Da spostare/POLITECNICO DI TORINO/+-- PROGRAMMAZIONE DI SISTEMA 7,75 +/npcap-sdk-1.13/Lib/x64");
}