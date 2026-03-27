//! Smali disassembler for DEX bytecode.
//!
//! This module provides functionality to convert Dalvik bytecode instructions
//! into human-readable Smali format.

use std::fmt::Write;

use crate::{
    bytecode::Instruction,
    error::{DexError, DexResult},
    format::MethodIdx,
    model::{DexFile, MethodHandle},
};

/// Disassembled output for a single method.
#[derive(Debug, Clone)]
pub struct DisassembledMethod {
    /// Method descriptor (e.g., "Lpkg/Class;->method()V")
    pub descriptor: String,
    /// Access flags string (e.g., "public static")
    pub access_flags: String,
    /// Smali code lines
    pub code: Vec<String>,
}

/// Disassemble a single method.
pub fn disassemble_method(dex: &DexFile<'_>, method: &MethodHandle<'_>) -> DexResult<DisassembledMethod> {
    let descriptor = format_method_descriptor(dex, method)?;
    let access_flags = format_access_flags(dex, method.index());
    
    let mut code = Vec::new();
    
    // Method header
    code.push(format!(".method {} {}", access_flags, descriptor));
    
    // Try to get code item
    match dex.decode_instructions(method.index()) {
        Ok(instructions) if !instructions.is_empty() => {
            // Register info
            if let Some(code_item) = dex.code_item(method.index()) {
                code.push(format!("    .registers {}", code_item.registers_size));
            }
            
            // Disassemble instructions
            for instr in &instructions {
                let line = format_instruction(dex, instr);
                code.push(format!("    {}", line));
            }
        }
        _ => {
            // Abstract or native method
            code.push("    # (no code - abstract or native)".to_string());
        }
    }
    
    code.push(".end method".to_string());
    
    Ok(DisassembledMethod { descriptor, access_flags, code })
}

/// Format a method handle into a Smali method descriptor.
fn format_method_descriptor(dex: &DexFile<'_>, method: &MethodHandle<'_>) -> DexResult<String> {
    let name = method.name()?;
    let proto = method.prototype()?;
    
    // Get return type descriptor
    let return_type_idx = proto.return_type_idx;
    let return_type = dex.type_descriptor(return_type_idx)
        .unwrap_or("<unknown>");
    
    // Get parameter types
    let mut params = String::new();
    if proto.parameters_off != 0 {
        if let Some(type_list) = dex.type_list(proto.parameters_off) {
            for type_idx in &type_list.types {
                if let Some(type_desc) = dex.type_descriptor(*type_idx) {
                    params.push_str(type_desc);
                }
            }
        }
    }
    
    Ok(format!("{}({}){}", name, params, return_type))
}

/// Format access flags to Smali style.
fn format_access_flags(dex: &DexFile<'_>, method_idx: MethodIdx) -> String {
    let flags = match dex.method_access_flags(method_idx) {
        Some(f) => f,
        None => return String::new(),
    };
    
    let mut parts = Vec::new();
    
    if flags.contains(crate::format::AccessFlags::PUBLIC) {
        parts.push("public");
    }
    if flags.contains(crate::format::AccessFlags::PRIVATE) {
        parts.push("private");
    }
    if flags.contains(crate::format::AccessFlags::PROTECTED) {
        parts.push("protected");
    }
    if flags.contains(crate::format::AccessFlags::STATIC) {
        parts.push("static");
    }
    if flags.contains(crate::format::AccessFlags::FINAL) {
        parts.push("final");
    }
    if flags.contains(crate::format::AccessFlags::SYNCHRONIZED) {
        parts.push("synchronized");
    }
    if flags.contains(crate::format::AccessFlags::BRIDGE) {
        parts.push("bridge");
    }
    if flags.contains(crate::format::AccessFlags::VARARGS) {
        parts.push("varargs");
    }
    if flags.contains(crate::format::AccessFlags::NATIVE) {
        parts.push("native");
    }
    if flags.contains(crate::format::AccessFlags::ABSTRACT) {
        parts.push("abstract");
    }
    if flags.contains(crate::format::AccessFlags::STRICT) {
        parts.push("strictfp");
    }
    if flags.contains(crate::format::AccessFlags::SYNTHETIC) {
        parts.push("synthetic");
    }
    if flags.contains(crate::format::AccessFlags::CONSTRUCTOR) {
        parts.push("constructor");
    }
    if flags.contains(crate::format::AccessFlags::DECLARED_SYNCHRONIZED) {
        parts.push("declared_synchronized");
    }
    
    parts.join(" ")
}

/// Format a single instruction to Smali.
fn format_instruction(dex: &DexFile<'_>, instr: &Instruction) -> String {
    let mut result = String::new();
    
    // Program counter
    let _ = write!(result, "{:04x}: ", instr.pc);
    
    // Opcode name
    result.push_str(instr.name);
    
    // Format arguments
    let args = format_instruction_args(dex, instr);
    if !args.is_empty() {
        result.push_str(&args);
    }
    
    result
}

/// Format instruction arguments.
fn format_instruction_args(dex: &DexFile<'_>, instr: &Instruction) -> String {
    let mut result = String::new();
    
    // Format registers
    if !instr.registers.is_empty() {
        result.push_str(" {");
        for (i, reg) in instr.registers.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
            result.push_str(&format!("v{}", reg));
        }
        result.push('}');
    }
    
    // Format literal
    if let Some(lit) = instr.literal {
        result.push_str(&format!(" {}", lit));
    }
    
    // Format reference
    if let Some(reference) = &instr.reference {
        let ref_str = format_reference(dex, reference);
        result.push_str(&format!(" {}", ref_str));
    }
    
    // Format offset
    if let Some(offset) = instr.offset {
        result.push_str(&format!(" -> {:04x}", (instr.pc as i32 + offset) as u32));
    }
    
    result
}

/// Format a reference to a string, type, field, or method.
fn format_reference(dex: &DexFile<'_>, reference: &crate::bytecode::Reference) -> String {
    match reference {
        crate::bytecode::Reference::String(idx) => {
            match dex.string(*idx) {
                Some(s) => format!("\"{}\"", escape_string(s)),
                None => format!("<string @ {}>", idx.raw()),
            }
        }
        crate::bytecode::Reference::Type(idx) => {
            match dex.type_descriptor(*idx) {
                Some(t) => t.to_string(),
                None => format!("<type @ {}>", idx.raw()),
            }
        }
        crate::bytecode::Reference::Field(idx) => {
            match dex.field_id(*idx) {
                Some(f) => {
                    let class = dex.type_descriptor(f.class_idx)
                        .unwrap_or("<unknown>");
                    let name = dex.string(f.name_idx)
                        .unwrap_or("<unknown>");
                    let type_desc = dex.type_descriptor(f.type_idx)
                        .unwrap_or("<unknown>");
                    format!("{}->{}:{}", class, name, type_desc)
                }
                None => format!("<field @ {}>", idx.raw()),
            }
        }
        crate::bytecode::Reference::Method(idx) => {
            match dex.method(*idx) {
                Some(m) => {
                    let class = m.class()
                        .and_then(|c| c.descriptor().ok())
                        .unwrap_or("<unknown>");
                    let name = m.name().unwrap_or("<unknown>");
                    
                    // Build signature
                    let proto = m.prototype().ok();
                    let signature = proto.map(|p| {
                        let mut params = String::new();
                        if p.parameters_off != 0 {
                            if let Some(type_list) = dex.type_list(p.parameters_off) {
                                for type_idx in &type_list.types {
                                    params.push_str(dex.type_descriptor(*type_idx).unwrap_or("?"));
                                }
                            }
                        }
                        let ret = dex.type_descriptor(p.return_type_idx).unwrap_or("?");
                        format!("({}){}", params, ret)
                    }).unwrap_or_else(|| "(?)?".to_string());
                    
                    format!("{}->{}{}", class, name, signature)
                }
                None => format!("<method @ {}>", idx.raw()),
            }
        }
        crate::bytecode::Reference::Proto(idx) => {
            format!("<proto @ {}>", idx.raw())
        }
        crate::bytecode::Reference::CallSite(idx) => {
            format!("<callsite @ {}>", idx.raw())
        }
        crate::bytecode::Reference::MethodHandle(idx) => {
            format!("<methodhandle @ {}>", idx.raw())
        }
    }
}

/// Escape special characters in a string for Smali output.
fn escape_string(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".to_string().chars().collect::<Vec<_>>(),
            '\\' => "\\\\".to_string().chars().collect::<Vec<_>>(),
            '\n' => "\\n".to_string().chars().collect::<Vec<_>>(),
            '\r' => "\\r".to_string().chars().collect::<Vec<_>>(),
            '\t' => "\\t".to_string().chars().collect::<Vec<_>>(),
            c if c.is_control() => format!("\\u{:04x}", c as u32).chars().collect::<Vec<_>>(),
            c => vec![c],
        })
        .collect()
}

/// Get disassembled code for a specific method.
pub fn get_method_smali(dex: &DexFile<'_>, method_idx: MethodIdx) -> DexResult<Vec<String>> {
    let method = dex.method(method_idx).ok_or(DexError::Malformed {
        context: "method_idx",
        message: "method not found",
    })?;
    
    let disassembled = disassemble_method(dex, &method)?;
    Ok(disassembled.code)
}
