fn main() {
    let mainptr = main as *const fn();
    println!("entry point is: {:p}", unsafe { *mainptr });
}
