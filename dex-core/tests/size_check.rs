use dex_core::bytecode::Instruction;
#[test]
fn size() {
    println!("Instruction size: {} bytes", std::mem::size_of::<Instruction>());
    println!("Option<Box<SwitchPayload>>: {} bytes", std::mem::size_of::<Option<Box<dex_core::bytecode::SwitchPayload>>>());
}
