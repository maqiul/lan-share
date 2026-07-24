fn main() {
    // Link dokan.lib from Dokan 0.7.4 installation
    println!("cargo:rustc-link-search=native=C:\\Program Files\\Dokan\\DokanLibrary");
    println!("cargo:rustc-link-lib=static=dokan");
}
