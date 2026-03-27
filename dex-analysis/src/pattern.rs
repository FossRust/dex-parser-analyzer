//! 全面的 Android 安全静态分析规则
//! 
//! 本模块实现了全面的安全检测规则，涵盖：
//! - 硬编码密钥检测（改进版，减少误报）
//! - 弱加密算法
//! - 不安全通信
//! - 日志泄露
//! - 不安全随机数
//! - WebView 安全
//! - 组件暴露
//! - 权限滥用
//! - 反射/动态加载
//! - 调试风险
//! - 证书校验绕过
//! - 命令注入
//! - 路径遍历
//! - 等等

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use dex_core::{
    format::{MethodIdx, StringIdx},
    graphs,
    model::DexFile,
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;

use crate::{
    config::AnalysisConfig,
    model::{Finding, Location, Severity, VulnerabilityKind},
};

const SECRET_MIN_LENGTH: usize = 12;
const ENTROPY_THRESHOLD: f32 = 4.5;

// ============================================================================
// 密钥检测正则 - 只检测高置信度的密钥模式
// ============================================================================
static SECRET_REGEXES: Lazy<Vec<(&str, Regex, Severity)>> = Lazy::new(|| {
    vec![
        // AWS
        ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), Severity::Critical),
        ("aws_secret", Regex::new(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}").unwrap(), Severity::Critical),
        
        // Google
        ("google_api_key", Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(), Severity::Critical),
        ("google_oauth", Regex::new(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com").unwrap(), Severity::High),
        
        // GitHub
        ("github_token", Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(), Severity::Critical),
        ("github_oauth", Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(), Severity::Critical),
        
        // Slack
        ("slack_token", Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(), Severity::Critical),
        ("slack_webhook", Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}").unwrap(), Severity::High),
        
        // JWT
        ("jwt_token", Regex::new(r"eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}").unwrap(), Severity::High),
        
        // 私钥
        ("private_key_rsa", Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(), Severity::Critical),
        ("private_key_openssh", Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(), Severity::Critical),
        ("private_key_generic", Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(), Severity::Critical),
        
        // 支付相关
        ("stripe_key", Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(), Severity::Critical),
        ("stripe_restricted", Regex::new(r"rk_live_[0-9a-zA-Z]{24,}").unwrap(), Severity::Critical),
        ("paypal_client", Regex::new(r"(?i)paypal[_-]?client[_-]?(id|secret)\s*[=:]\s*[A-Za-z0-9_-]{16,}").unwrap(), Severity::Critical),
        
        // 云服务
        ("azure_key", Regex::new(r"(?i)azure[_-]?(key|secret)\s*[=:]\s*[A-Za-z0-9_-]{32,}").unwrap(), Severity::Critical),
        ("alicloud_key", Regex::new(r"LTAI[0-9a-zA-Z]{12,}").unwrap(), Severity::Critical),
        
        // 数据库连接
        ("mongodb_uri", Regex::new(r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+").unwrap(), Severity::Critical),
        ("redis_uri", Regex::new(r"redis://:[^@]+@[^/]+").unwrap(), Severity::Critical),
        ("mysql_uri", Regex::new(r"mysql://[^:]+:[^@]+@[^/]+").unwrap(), Severity::Critical),
        
        // 通用密钥模式（高置信度）
        ("bearer_token", Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}").unwrap(), Severity::High),
        ("basic_auth", Regex::new(r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}").unwrap(), Severity::High),
    ]
});

// ============================================================================
// 密钥关键词 - 用于辅助检测
// ============================================================================
static SECRET_KEYWORDS: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::new([
        // 密码相关
        "password=",
        "password:",
        "passwd=",
        "passwd:",
        "pwd=",
        "pwd:",
        // 密钥相关
        "secret=",
        "secret:",
        "api_key=",
        "api_key:",
        "apikey=",
        "apikey:",
        "access_key=",
        "access_key:",
        "accesskey=",
        "accesskey:",
        "private_key=",
        "private_key:",
        // Token 相关
        "token=",
        "token:",
        "auth_token=",
        "auth_token:",
        "access_token=",
        "access_token:",
        "refresh_token=",
        "refresh_token:",
        // 认证相关
        "authorization: basic",
        "authorization:bearer",
        // 云服务商
        "aws_secret",
        "aws_access",
        "google_api",
        "azure_key",
    ])
    .expect("aho-corasick build failed")
});

// ============================================================================
// 弱加密关键词
// ============================================================================
static WEAK_CRYPTO_KEYWORDS: &[(&str, &'static str, Severity)] = &[
    ("md5", "MD5", Severity::High),
    ("sha1", "SHA1", Severity::Medium),
    ("sha-1", "SHA1", Severity::Medium),
    ("des", "DES", Severity::High),
    ("desede", "3DES", Severity::Medium),
    ("tripledes", "3DES", Severity::Medium),
    ("rc4", "RC4", Severity::High),
    ("rc2", "RC2", Severity::High),
    ("blowfish", "Blowfish", Severity::Low),
    ("ecb", "ECB 模式", Severity::High),
    ("pkcs1v1.5", "PKCS#1 v1.5", Severity::Medium),
];

// ============================================================================
// 不安全 HTTP 关键词
// ============================================================================
static INSECURE_HTTP_PATTERNS: &[&str] = &[
    "http://",
    "http://192.168",
    "http://10.",
    "http://172.16",
    "http://172.17",
    "http://172.18",
    "http://172.19",
    "http://172.2",
    "http://172.30",
    "http://172.31",
    "http://localhost",
    "http://127.0.0.1",
];

// ============================================================================
// 日志泄露关键词
// ============================================================================
static LOG_SENSITIVE_KEYWORDS: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::new([
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "credential",
        "credit card",
        "card number",
        "cvv",
        "ssn",
        "id card",
        "phone",
        "email",
        "address",
        "birth",
        "bank",
        "account",
        "login",
        "auth",
    ])
    .expect("aho-corasick build failed")
});

// ============================================================================
// 危险方法签名
// ============================================================================
static DANGEROUS_METHODS: &[(&str, &str, &str, &str, Severity)] = &[
    // 命令执行
    ("Ljava/lang/Runtime;", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", "命令执行", Severity::Critical),
    ("Ljava/lang/ProcessBuilder;", "start", "()Ljava/lang/Process;", "进程创建", Severity::Critical),
    
    // 反射
    ("Ljava/lang/Class;", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", "反射加载类", Severity::High),
    ("Ljava/lang/Class;", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", "反射获取方法", Severity::High),
    ("Ljava/lang/Class;", "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", "反射获取方法", Severity::High),
    ("Ljava/lang/reflect/Method;", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", "反射调用", Severity::High),
    
    // 动态加载
    ("Ldalvik/system/DexClassLoader;", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V", "动态加载 DEX", Severity::Critical),
    ("Ldalvik/system/PathClassLoader;", "<init>", "(Ljava/lang/String;Ljava/lang/ClassLoader;)V", "动态加载 DEX", Severity::High),
    ("Ljava/lang/ClassLoader;", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", "类加载器", Severity::High),
    
    // 加密相关
    ("Ljavax/crypto/Cipher;", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", "加密实例", Severity::Medium),
    ("Ljava/security/MessageDigest;", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", "消息摘要", Severity::Medium),
    ("Ljava/security/Signature;", "getInstance", "(Ljava/lang/String;)Ljava/security/Signature;", "签名实例", Severity::Medium),
    
    // 随机数
    ("Ljava/util/Random;", "<init>", "()V", "随机数生成", Severity::Low),
    ("Ljava/lang/Math;", "random", "()D", "随机数生成", Severity::Low),
    
    // WebView
    ("Landroid/webkit/WebView;", "addJavascriptInterface", "(Ljava/lang/Object;Ljava/lang/String;)V", "JS 接口", Severity::High),
    ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V", "启用 JS", Severity::Medium),
    ("Landroid/webkit/WebSettings;", "setAllowFileAccess", "(Z)V", "文件访问", Severity::High),
    ("Landroid/webkit/WebView;", "loadUrl", "(Ljava/lang/String;)V", "加载 URL", Severity::Low),
    
    //  SharedPreferences
    ("Landroid/content/SharedPreferences$Editor;", "putString", "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;", "存储字符串", Severity::Low),
    
    // 网络
    ("Ljava/net/URL;", "<init>", "(Ljava/lang/String;)V", "URL 创建", Severity::Low),
    ("Ljava/net/HttpURLConnection;", "setRequestMethod", "(Ljava/lang/String;)V", "HTTP 请求", Severity::Low),
    
    // 文件
    ("Ljava/io/File;", "<init>", "(Ljava/lang/String;)V", "文件操作", Severity::Low),
    ("Ljava/io/FileOutputStream;", "<init>", "(Ljava/lang/String;)V", "文件写入", Severity::Low),
    
    // 数据库
    ("Landroid/database/sqlite/SQLiteDatabase;", "execSQL", "(Ljava/lang/String;)V", "SQL 执行", Severity::High),
    ("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery", "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;", "SQL 查询", Severity::Medium),
    
    // 系统属性
    ("Ljava/lang/System;", "getProperty", "(Ljava/lang/String;)Ljava/lang/String;", "系统属性", Severity::Medium),
    ("Ljava/lang/Runtime;", "getRuntime", "()Ljava/lang/Runtime;", "运行时", Severity::Low),
    
    // 调试
    ("Landroid/util/Log;", "d", "(Ljava/lang/String;Ljava/lang/String;)I", "调试日志", Severity::Low),
    ("Landroid/util/Log;", "e", "(Ljava/lang/String;Ljava/lang/String;)I", "错误日志", Severity::Low),
    ("Landroid/util/Log;", "i", "(Ljava/lang/String;Ljava/lang/String;)I", "信息日志", Severity::Low),
    ("Landroid/util/Log;", "v", "(Ljava/lang/String;Ljava/lang/String;)I", "详细日志", Severity::Low),
    ("Landroid/util/Log;", "w", "(Ljava/lang/String;Ljava/lang/String;)I", "警告日志", Severity::Low),
];

// ============================================================================
// 证书校验绕过特征
// ============================================================================
static CERT_BYPASS_PATTERNS: &[&str] = &[
    "checkServerTrusted",
    "checkClientTrusted",
    "TrustAllManager",
    "FakeX509TrustManager",
    "AllowAllHostnameVerifier",
    "ALLOW_ALL_HOSTNAME_VERIFIER",
    "SSLSocketFactory",
    "TrustManager",
];

// ============================================================================
// 组件暴露检测
// ============================================================================
static COMPONENT_EXPORT_PATTERNS: &[(&str, Severity)] = &[
    ("android.intent.action.MAIN", Severity::Low),
    ("android.intent.exported", Severity::Medium),
    ("android.permission", Severity::Low),
];

// ============================================================================
// 辅助函数：计算字符串熵值
// ============================================================================
fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    
    let mut freq = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    
    let len = s.len() as f32;
    let mut entropy = 0.0;
    
    for count in freq.values() {
        let p = *count as f32 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

// ============================================================================
// 辅助函数：判断字符串是否为可读文本（非密钥）
// ============================================================================
fn is_readable_text(s: &str) -> bool {
    // 检查是否包含中文字符
    if s.chars().any(|c| c.is_ascii() == false && c.is_chinese() == false) {
        // 包含非 ASCII 字符
        let chinese_ratio = s.chars().filter(|c| c.is_chinese()).count() as f32 / s.len() as f32;
        if chinese_ratio > 0.3 {
            return true; // 主要是中文，可能是提示文本
        }
    }
    
    // 检查是否为常见文件路径
    if s.starts_with('/') || s.starts_with('\\') || s.contains('/') || s.contains('\\') {
        if s.ends_with(".xml") || s.ends_with(".json") || s.ends_with(".properties") {
            return true;
        }
    }
    
    // 检查是否为 URL 但不含敏感参数
    if s.starts_with("http://") || s.starts_with("https://") {
        if !s.contains("token=") && !s.contains("key=") && !s.contains("secret=") && !s.contains("password=") {
            return true;
        }
    }
    
    // 检查是否为错误消息或提示
    let common_messages = ["error", "fail", "success", "ok", "cancel", "confirm", "loading", "请", "确", "失", "成", "功", "败"];
    for msg in common_messages {
        if s.to_lowercase().contains(msg) {
            return true;
        }
    }
    
    false
}

// 添加 is_chinese 辅助 trait
trait CharExt {
    fn is_chinese(&self) -> bool;
}

impl CharExt for char {
    fn is_chinese(&self) -> bool {
        matches!(*self as u32,
            0x4E00..=0x9FFF |  // CJK Unified Ideographs
            0x3400..=0x4DBF |  // CJK Extension A
            0x20000..=0x2A6DF | // CJK Extension B
            0x2A700..=0x2B73F | // CJK Extension C
            0x2B740..=0x2B81F | // CJK Extension D
            0x2B820..=0x2CEAF | // CJK Extension E
            0xF900..=0xFAFF |   // CJK Compatibility Ideographs
            0x2F800..=0x2FA1F   // CJK Compatibility Supplement
        )
    }
}

// ============================================================================
// 辅助函数：分类密钥类型
// ============================================================================
fn classify_secret(value: &str) -> Option<(&'static str, Severity)> {
    // 首先检查是否为可读文本（误报过滤）
    if is_readable_text(value) {
        return None;
    }
    
    // 检查正则匹配
    for (name, regex, severity) in SECRET_REGEXES.iter() {
        if regex.is_match(value) {
            return Some((*name, *severity));
        }
    }
    
    // 检查关键词 + 熵值
    if SECRET_KEYWORDS.find(value.as_bytes()).is_some() {
        let entropy = calculate_entropy(value);
        if entropy >= ENTROPY_THRESHOLD && value.len() >= SECRET_MIN_LENGTH {
            return Some(("high_entropy_secret", Severity::Medium));
        }
    }
    
    None
}

// ============================================================================
// 辅助函数：截断长字符串用于显示
// ============================================================================
fn preview_literal(value: &str) -> String {
    let trimmed = value.trim();
    const MAX_LEN: usize = 64;
    if trimmed.len() <= MAX_LEN {
        trimmed.to_string()
    } else {
        let truncated: String = trimmed.chars().take(MAX_LEN).collect();
        format!("{}…", truncated)
    }
}

// ============================================================================
// 构建字符串到方法的映射
// ============================================================================
fn build_string_to_methods(xrefs: &graphs::Xrefs) -> HashMap<u32, Vec<u32>> {
    let mut map = HashMap::new();
    for (method, string) in &xrefs.method_strings {
        map.entry(*string).or_insert_with(Vec::new).push(*method);
    }
    map
}

// ============================================================================
// 构建方法到字符串的映射
// ============================================================================
fn invert_string_map(map: &HashMap<u32, Vec<u32>>) -> HashMap<u32, HashSet<u32>> {
    let mut result = HashMap::new();
    for (string, methods) in map {
        for method in methods {
            result.entry(*method).or_insert_with(HashSet::new).insert(*string);
        }
    }
    result
}

// ============================================================================
// 构建危险方法查找表
// ============================================================================
fn build_dangerous_method_lookup(dex: &DexFile<'_>) -> HashMap<String, (&'static str, &'static str, Severity)> {
    let mut map = HashMap::new();
    
    for (class, name, sig, desc, severity) in DANGEROUS_METHODS {
        // 查找匹配的方法
        for method_idx in 0..dex.method_count() {
            if let Some(method) = dex.method(MethodIdx::new(method_idx as u32)) {
                if let Ok(method_name) = method.name() {
                    if method_name == *name {
                        let key = format!("{}->{}{}", 
                            dex.type_descriptor(method.id().class_idx).unwrap_or("?"),
                            name, sig);
                        map.insert(key, (*desc, *class, *severity));
                    }
                }
            }
        }
    }
    
    map
}

// ============================================================================
// 主入口：执行所有模式检测
// ============================================================================
pub fn run_pattern_checks(
    dex: &DexFile<'_>,
    config: &AnalysisConfig,
    findings: &mut Vec<Finding>,
    _stats: &mut crate::model::AnalysisStats,
) {
    let Ok(xrefs) = graphs::build_xrefs(dex) else {
        return;
    };
    
    let string_to_methods = build_string_to_methods(&xrefs);
    
    // 1. 硬编码密钥检测
    detect_hardcoded_secrets(dex, config, findings, &string_to_methods);
    
    // 2. 不安全 HTTP 检测
    detect_insecure_http(dex, findings, &string_to_methods);
    
    // 3. 弱加密检测
    detect_weak_crypto(dex, findings, &xrefs, &string_to_methods);
    
    // 4. 日志泄露检测
    detect_log_leaks(dex, findings, &string_to_methods);
    
    // 5. 不安全随机数检测
    detect_insecure_random(dex, findings);
    
    // 6. WebView 安全检测
    detect_webview_issues(dex, findings);
    
    // 7. 危险方法调用检测
    detect_dangerous_methods(dex, findings);
    
    // 8. 证书校验绕过检测
    detect_cert_bypass(dex, findings, &string_to_methods);
    
    // 9. 组件暴露检测
    detect_component_exposure(dex, findings, &string_to_methods);
    
    // 10. 文件路径遍历检测
    detect_path_traversal(dex, findings, &string_to_methods);
    
    // 11. SQL 注入风险检测
    detect_sql_injection_risk(dex, findings);
    
    // 12. 调试配置检测
    detect_debug_issues(dex, findings, &string_to_methods);
}

// ============================================================================
// 1. 硬编码密钥检测
// ============================================================================
fn detect_hardcoded_secrets(
    dex: &DexFile<'_>,
    config: &AnalysisConfig,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    
    for idx in 0..dex.string_count() {
        let string_idx = StringIdx::new(idx as u32);
        let Some(value) = dex.string(string_idx) else {
            continue;
        };
        
        if value.trim().is_empty() {
            continue;
        }
        
        let trigger = match classify_secret(value) {
            Some(trigger) => trigger,
            None => continue,
        };
        
        let methods = string_map.get(&(idx as u32));
        if let Some(methods) = methods {
            for method in methods {
                if !emitted.insert((*method, trigger.0)) {
                    continue;
                }
                
                let (kind, message) = get_vulnerability_info(trigger.0);
                
                findings.push(Finding {
                    id: format!("SEC_{}", trigger.0).into(),
                    kind: VulnerabilityKind::HardcodedSecret,
                    severity: trigger.1,
                    location: Location::from_method(dex, MethodIdx::new(*method), None),
                    message: format!("{}: `{}`", message, preview_literal(value)),
                    extra: json!({
                        "pattern": trigger.0,
                        "literal": value,
                        "type": kind,
                    }),
                });
            }
        }
    }
}

// ============================================================================
// 2. 不安全 HTTP 检测
// ============================================================================
fn detect_insecure_http(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    
    for idx in 0..dex.string_count() {
        let Some(value) = dex.string(StringIdx::new(idx as u32)) else {
            continue;
        };
        
        let value_lower = value.to_lowercase();
        for pattern in INSECURE_HTTP_PATTERNS {
            if value_lower.starts_with(pattern) || value_lower.contains(pattern) {
                // 跳过 localhost 和测试地址
                if value.contains("localhost") || value.contains("127.0.0.1") || value.contains("10.0.2.2") {
                    continue;
                }
                
                let methods = string_map.get(&(idx as u32));
                if let Some(methods) = methods {
                    for method in methods {
                        if !emitted.insert((*method, idx as u32)) {
                            continue;
                        }
                        
                        findings.push(Finding {
                            id: "NET_001_INSECURE_HTTP".into(),
                            kind: VulnerabilityKind::InsecureCommunication,
                            severity: Severity::Medium,
                            location: Location::from_method(dex, MethodIdx::new(*method), None),
                            message: format!("使用不安全的 HTTP 协议：`{}`", preview_literal(value)),
                            extra: json!({
                                "url": value,
                                "risk": "数据可能被窃听",
                                "suggestion": "使用 HTTPS 替代 HTTP",
                            }),
                        });
                    }
                }
                break;
            }
        }
    }
}

// ============================================================================
// 3. 弱加密检测
// ============================================================================
fn detect_weak_crypto(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    _xrefs: &graphs::Xrefs,
    string_to_methods: &HashMap<u32, Vec<u32>>,
) {
    let method_to_strings = invert_string_map(string_to_methods);
    let mut emitted = HashSet::new();
    
    for (caller, strings) in &method_to_strings {
        for string_idx in strings {
            if let Some(value) = dex.string(StringIdx::new(*string_idx)) {
                let value_lower = value.to_lowercase();
                for (keyword, algo, severity) in WEAK_CRYPTO_KEYWORDS {
                    if value_lower.contains(keyword) {
                        if !emitted.insert((*caller, *keyword)) {
                            continue;
                        }
                        
                        findings.push(Finding {
                            id: "CRY_001_WEAK_ALGO".into(),
                            kind: VulnerabilityKind::WeakCrypto,
                            severity: *severity,
                            location: Location::from_method(dex, MethodIdx::new(*caller), None),
                            message: format!("使用弱加密算法：{}", algo),
                            extra: json!({
                                "algorithm": algo,
                                "value": value,
                                "risk": get_crypto_risk(algo),
                                "suggestion": get_crypto_suggestion(algo),
                            }),
                        });
                        break;
                    }
                }
            }
        }
    }
}

fn get_crypto_risk(algo: &str) -> &'static str {
    match algo {
        "MD5" => "碰撞攻击可行，不适合数字签名",
        "SHA1" => "碰撞攻击已演示，不建议用于安全场景",
        "DES" => "密钥长度仅 56 位，可被暴力破解",
        "3DES" => "存在中间相遇攻击，已被 NIST 弃用",
        "RC4" => "存在多个严重漏洞，已被 TLS 禁用",
        "RC2" => "设计过时，存在已知弱点",
        "ECB 模式" => "相同明文产生相同密文，泄露数据模式",
        _ => "可能存在安全风险",
    }
}

fn get_crypto_suggestion(algo: &str) -> &'static str {
    match algo {
        "MD5" | "SHA1" => "使用 SHA-256 或 SHA-3",
        "DES" | "3DES" => "使用 AES-256",
        "RC4" | "RC2" => "使用 AES-GCM 或 ChaCha20",
        "ECB 模式" => "使用 CBC、GCM 或 CTR 模式",
        _ => "使用现代加密算法",
    }
}

// ============================================================================
// 4. 日志泄露检测
// ============================================================================
fn detect_log_leaks(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    // 查找 Log 类的方法
    let log_methods: Vec<MethodIdx> = (0..dex.method_count())
        .filter_map(|i| {
            let idx = MethodIdx::new(i as u32);
            if let Some(method) = dex.method(idx) {
                if let Some(class) = method.class() {
                    if let Ok(desc) = class.descriptor() {
                        if desc == "Landroid/util/Log;" {
                            return Some(idx);
                        }
                    }
                }
            }
            None
        })
        .collect();
    
    if log_methods.is_empty() {
        return;
    }
    
    let mut emitted = HashSet::new();
    
    for (method_idx, strings) in &invert_string_map(string_map) {
        // 检查是否调用了 Log 方法
        let calls_log = dex.method(MethodIdx::new(*method_idx))
            .and_then(|m| m.class())
            .and_then(|c| c.descriptor().ok())
            .map(|d| !log_methods.is_empty())
            .unwrap_or(false);
        
        if !calls_log {
            continue;
        }
        
        for string_idx in strings {
            if let Some(value) = dex.string(StringIdx::new(*string_idx)) {
                if LOG_SENSITIVE_KEYWORDS.find(value.as_bytes()).is_some() {
                    if !emitted.insert((*method_idx, *string_idx)) {
                        continue;
                    }
                    
                    findings.push(Finding {
                        id: "LOG_001_SENSITIVE".into(),
                        kind: VulnerabilityKind::Custom("日志泄露".into()),
                        severity: Severity::High,
                        location: Location::from_method(dex, MethodIdx::new(*method_idx), None),
                        message: format!("日志可能包含敏感信息：`{}`", preview_literal(value)),
                        extra: json!({
                            "content": value,
                            "risk": "敏感信息可能被记录到日志",
                            "suggestion": "避免在日志中输出敏感数据",
                        }),
                    });
                }
            }
        }
    }
}

// ============================================================================
// 5. 不安全随机数检测
// ============================================================================
fn detect_insecure_random(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
) {
    for method_idx in 0..dex.method_count() {
        let idx = MethodIdx::new(method_idx as u32);
        if let Some(method) = dex.method(idx) {
            if let Some(class) = method.class() {
                if let Ok(desc) = class.descriptor() {
                    if desc == "Ljava/util/Random;" || desc == "Ljava/lang/Math;" {
                        findings.push(Finding {
                            id: "RND_001_INSECURE".into(),
                            kind: VulnerabilityKind::InsecureRandom,
                            severity: Severity::Medium,
                            location: Location::from_method(dex, idx, None),
                            message: "使用不安全的随机数生成器".to_string(),
                            extra: json!({
                                "risk": "Random 和 Math.random() 不适合加密用途",
                                "suggestion": "使用 java.security.SecureRandom",
                            }),
                        });
                    }
                }
            }
        }
    }
}

// ============================================================================
// 6. WebView 安全检测
// ============================================================================
fn detect_webview_issues(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
) {
    let mut emitted = HashSet::new();
    
    for method_idx in 0..dex.method_count() {
        let idx = MethodIdx::new(method_idx as u32);
        if let Some(method) = dex.method(idx) {
            if let Ok(code) = dex.decode_instructions(idx) {
                for instr in &code {
                    if let Some(ref ref_info) = instr.reference {
                        let ref_str = format!("{:?}", ref_info);
                        
                        if ref_str.contains("addJavascriptInterface") && !emitted.insert((method_idx, 1)) {
                            findings.push(Finding {
                                id: "WEB_001_JS_INTERFACE".into(),
                                kind: VulnerabilityKind::Custom("WebView 安全".into()),
                                severity: Severity::Critical,
                                location: Location::from_method(dex, idx, Some(instr.pc)),
                                message: "WebView 添加了 JavaScript 接口".to_string(),
                                extra: json!({
                                    "risk": "可能导致远程代码执行漏洞",
                                    "suggestion": "仅在绝对必要时使用，并限制暴露的方法",
                                }),
                            });
                        }
                        
                        if ref_str.contains("setAllowFileAccess") && !emitted.insert((method_idx, 2)) {
                            findings.push(Finding {
                                id: "WEB_002_FILE_ACCESS".into(),
                                kind: VulnerabilityKind::Custom("WebView 安全".into()),
                                severity: Severity::High,
                                location: Location::from_method(dex, idx, Some(instr.pc)),
                                message: "WebView 启用了文件访问".to_string(),
                                extra: json!({
                                    "risk": "可能读取本地文件",
                                    "suggestion": "禁用文件访问除非必要",
                                }),
                            });
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 7. 危险方法调用检测
// ============================================================================
fn detect_dangerous_methods(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
) {
    let mut emitted = HashSet::new();
    
    for method_idx in 0..dex.method_count() {
        let idx = MethodIdx::new(method_idx as u32);
        if let Some(method) = dex.method(idx) {
            if let Some(class) = method.class() {
                if let Ok(class_desc) = class.descriptor() {
                    if let Ok(name) = method.name() {
                        for (target_class, target_name, _, desc, severity) in DANGEROUS_METHODS {
                            if class_desc == *target_class && name == *target_name {
                                if !emitted.insert((idx, *target_name)) {
                                    continue;
                                }
                                
                                findings.push(Finding {
                                    id: format!("DANGER_{}", target_name.replace(" ", "_")).into(),
                                    kind: VulnerabilityKind::Custom((*desc).into()),
                                    severity: *severity,
                                    location: Location::from_method(dex, idx, None),
                                    message: format!("调用{}方法", desc),
                                    extra: json!({
                                        "method": format!("{}->{}", class_desc, name),
                                        "risk": get_dangerous_method_risk(target_name),
                                        "suggestion": get_dangerous_method_suggestion(target_name),
                                    }),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

fn get_dangerous_method_risk(name: &str) -> &'static str {
    match name {
        "exec" => "可能执行系统命令",
        "start" => "可能创建新进程",
        "forName" => "可能加载恶意类",
        "getMethod" | "getDeclaredMethod" => "可能访问私有方法",
        "invoke" => "可能执行任意方法",
        "loadClass" => "可能动态加载恶意类",
        "addJavascriptInterface" => "可能导致 RCE 漏洞",
        "setAllowFileAccess" => "可能泄露本地文件",
        "execSQL" => "可能存在 SQL 注入风险",
        _ => "可能存在安全风险",
    }
}

fn get_dangerous_method_suggestion(name: &str) -> &'static str {
    match name {
        "exec" | "start" => "避免执行外部命令，使用白名单验证输入",
        "forName" | "loadClass" => "限制可加载的类，使用类加载器沙箱",
        "invoke" => "验证方法调用的合法性",
        "addJavascriptInterface" => "使用 @JavascriptInterface 注解限制暴露的方法",
        "setAllowFileAccess" => "禁用文件访问或使用 ContentProvider",
        "execSQL" => "使用参数化查询，避免字符串拼接",
        _ => "仔细审查使用场景，确保输入验证",
    }
}

// ============================================================================
// 8. 证书校验绕过检测
// ============================================================================
fn detect_cert_bypass(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    
    for idx in 0..dex.string_count() {
        let Some(value) = dex.string(StringIdx::new(idx as u32)) else {
            continue;
        };
        
        for pattern in CERT_BYPASS_PATTERNS {
            if value.contains(pattern) {
                let methods = string_map.get(&(idx as u32));
                if let Some(methods) = methods {
                    for method in methods {
                        if !emitted.insert((*method, pattern)) {
                            continue;
                        }
                        
                        findings.push(Finding {
                            id: "SSL_001_CERT_BYPASS".into(),
                            kind: VulnerabilityKind::Custom("证书校验绕过".into()),
                            severity: Severity::Critical,
                            location: Location::from_method(dex, MethodIdx::new(*method), None),
                            message: format!("检测到证书校验绕过代码：`{}`", pattern),
                            extra: json!({
                                "pattern": pattern,
                                "risk": "中间人攻击风险",
                                "suggestion": "实现正确的证书校验逻辑",
                            }),
                        });
                    }
                }
                break;
            }
        }
    }
}

// ============================================================================
// 9. 组件暴露检测
// ============================================================================
fn detect_component_exposure(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    
    for idx in 0..dex.string_count() {
        let Some(value) = dex.string(StringIdx::new(idx as u32)) else {
            continue;
        };
        
        for (pattern, severity) in COMPONENT_EXPORT_PATTERNS {
            if value.contains(pattern) {
                let methods = string_map.get(&(idx as u32));
                if let Some(methods) = methods {
                    for method in methods {
                        if !emitted.insert((*method, idx as u32)) {
                            continue;
                        }
                        
                        findings.push(Finding {
                            id: "CMP_001_EXPOSED".into(),
                            kind: VulnerabilityKind::Custom("组件暴露".into()),
                            severity: *severity,
                            location: Location::from_method(dex, MethodIdx::new(*method), None),
                            message: format!("检测到组件暴露配置：`{}`", preview_literal(value)),
                            extra: json!({
                                "config": value,
                                "risk": "恶意应用可能调用暴露的组件",
                                "suggestion": "设置 android:exported=\"false\" 或添加权限保护",
                            }),
                        });
                    }
                }
                break;
            }
        }
    }
}

// ============================================================================
// 10. 文件路径遍历检测
// ============================================================================
fn detect_path_traversal(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let mut emitted = HashSet::new();
    let traversal_patterns = ["../", "..\\", "%2e%2e%2f", "%2e%2e/"];
    
    for idx in 0..dex.string_count() {
        let Some(value) = dex.string(StringIdx::new(idx as u32)) else {
            continue;
        };
        
        let value_lower = value.to_lowercase();
        for pattern in traversal_patterns {
            if value_lower.contains(pattern) {
                let methods = string_map.get(&(idx as u32));
                if let Some(methods) = methods {
                    for method in methods {
                        if !emitted.insert((*method, idx as u32)) {
                            continue;
                        }
                        
                        findings.push(Finding {
                            id: "FILE_001_TRAVERSAL".into(),
                            kind: VulnerabilityKind::Custom("路径遍历".into()),
                            severity: Severity::High,
                            location: Location::from_method(dex, MethodIdx::new(*method), None),
                            message: format!("检测到路径遍历模式：`{}`", preview_literal(value)),
                            extra: json!({
                                "pattern": value,
                                "risk": "可能访问未授权的文件",
                                "suggestion": "验证并规范化文件路径",
                            }),
                        });
                    }
                }
                break;
            }
        }
    }
}

// ============================================================================
// 11. SQL 注入风险检测
// ============================================================================
fn detect_sql_injection_risk(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
) {
    // 查找使用 execSQL 或 rawQuery 的方法
    for method_idx in 0..dex.method_count() {
        let idx = MethodIdx::new(method_idx as u32);
        if let Some(method) = dex.method(idx) {
            if let Some(class) = method.class() {
                if let Ok(desc) = class.descriptor() {
                    if desc.contains("Landroid/database/sqlite/") {
                        if let Ok(name) = method.name() {
                            if name == "execSQL" || name == "rawQuery" {
                                findings.push(Finding {
                                    id: "SQL_001_INJECTION".into(),
                                    kind: VulnerabilityKind::Custom("SQL 注入风险".into()),
                                    severity: Severity::High,
                                    location: Location::from_method(dex, idx, None),
                                    message: format!("使用{}方法，可能存在 SQL 注入风险", name),
                                    extra: json!({
                                        "method": format!("{}->{}", desc, name),
                                        "risk": "用户输入可能拼接进 SQL 语句",
                                        "suggestion": "使用参数化查询或 SQLiteQueryBuilder",
                                    }),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 12. 调试配置检测
// ============================================================================
fn detect_debug_issues(
    dex: &DexFile<'_>,
    findings: &mut Vec<Finding>,
    string_map: &HashMap<u32, Vec<u32>>,
) {
    let debug_patterns = [
        ("debuggable", "true", Severity::High),
        ("android:debuggable", "true", Severity::High),
        ("testOnly", "true", Severity::Medium),
        ("android:testOnly", "true", Severity::Medium),
    ];
    
    let mut emitted = HashSet::new();
    
    for idx in 0..dex.string_count() {
        let Some(value) = dex.string(StringIdx::new(idx as u32)) else {
            continue;
        };
        
        let value_lower = value.to_lowercase();
        for (pattern, target, severity) in debug_patterns {
            if value_lower.contains(&pattern.to_lowercase()) && value_lower.contains(&target.to_lowercase()) {
                let methods = string_map.get(&(idx as u32));
                if let Some(methods) = methods {
                    for method in methods {
                        if !emitted.insert((*method, pattern)) {
                            continue;
                        }
                        
                        findings.push(Finding {
                            id: "DBG_001_ENABLED".into(),
                            kind: VulnerabilityKind::Custom("调试配置".into()),
                            severity: severity,
                            location: Location::from_method(dex, MethodIdx::new(*method), None),
                            message: format!("检测到调试配置启用：`{}`", preview_literal(value)),
                            extra: json!({
                                "config": value,
                                "risk": if pattern == "debuggable" {
                                    "应用可被调试，可能导致代码注入"
                                } else {
                                    "测试应用不应发布到生产环境"
                                },
                                "suggestion": "发布前禁用调试选项",
                            }),
                        });
                    }
                }
                break;
            }
        }
    }
}

// ============================================================================
// 辅助函数：获取漏洞类型描述
// ============================================================================
fn get_vulnerability_info(pattern: &str) -> (&'static str, &'static str) {
    match pattern {
        "aws_access_key" => ("AWS 密钥", "检测到 AWS Access Key"),
        "aws_secret" => ("AWS 密钥", "检测到 AWS Secret Key"),
        "google_api_key" => ("Google API 密钥", "检测到 Google API Key"),
        "google_oauth" => ("Google OAuth", "检测到 Google OAuth 客户端 ID"),
        "github_token" => ("GitHub Token", "检测到 GitHub Token"),
        "github_oauth" => ("GitHub OAuth", "检测到 GitHub OAuth Token"),
        "slack_token" => ("Slack Token", "检测到 Slack Token"),
        "slack_webhook" => ("Slack Webhook", "检测到 Slack Webhook URL"),
        "jwt_token" => ("JWT Token", "检测到 JWT Token"),
        "private_key_rsa" => ("RSA 私钥", "检测到 RSA 私钥"),
        "private_key_openssh" => ("OpenSSH 私钥", "检测到 OpenSSH 私钥"),
        "private_key_generic" => ("私钥", "检测到私钥"),
        "stripe_key" => ("Stripe 密钥", "检测到 Stripe API Key"),
        "paypal_client" => ("PayPal 配置", "检测到 PayPal 客户端配置"),
        "azure_key" => ("Azure 密钥", "检测到 Azure 密钥"),
        "alicloud_key" => ("阿里云密钥", "检测到阿里云 Access Key"),
        "mongodb_uri" => ("MongoDB 连接", "检测到 MongoDB 连接字符串"),
        "redis_uri" => ("Redis 连接", "检测到 Redis 连接字符串"),
        "mysql_uri" => ("MySQL 连接", "检测到 MySQL 连接字符串"),
        "bearer_token" => ("Bearer Token", "检测到 Bearer Token"),
        "basic_auth" => ("Basic Auth", "检测到 Basic Auth 凭证"),
        "high_entropy_secret" => ("高熵值密钥", "检测到高熵值疑似密钥"),
        _ => ("疑似密钥", "检测到疑似硬编码密钥"),
    }
}
