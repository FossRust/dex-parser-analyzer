

# **An Architectural Blueprint for Dalvik Static Analysis in Rust and WebAssembly**

## **I. Executive Summary**

This report provides a comprehensive architectural blueprint for a high-performance, sandboxed static analysis engine (SAST) targeting Android Dalvik Executable (DEX) files. The primary technical constraints, as stipulated, are that the engine is implemented in the Rust programming language and is fully compilable to the wasm32-unknown-unknown WebAssembly target. This architecture makes it uniquely suitable for novel, in-browser security analysis, on-demand CI/CD scanners, or as a sandboxed plugin for larger analysis platforms.  
The analysis herein formalizes the entire engine, beginning with the foundational graph-based primitives the Rust parser must provide. This is not limited to simple parsing but includes the algorithms for generating:

1. Intra-procedural Control Flow Graphs (CFGs), including sound handling of Dalvik exception tables.  
2. Inter-procedural Call Graphs (CGs), augmented with Class Hierarchy Analysis (CHA) for accurate virtual-dispatch resolution.  
3. A comprehensive Cross-Reference (XREF) Database, which serves as the central bridge between all analysis layers.

A critical architectural constraint of the wasm32-unknown-unknown target is its single-threaded nature and limited std library support.1 This renders common, data-parallel Rust dataflow crates (e.g., differential-dataflow 3) architecturally incompatible. The formal solution detailed in this report is a custom, single-threaded, iterative fixed-point dataflow engine, modeled after the principles of rustc\_mir\_dataflow 5 and the waffle framework.6  The first iteration of this solver now ships in `dex_core::analysis::data_flow`, exposing a reusable worklist driver + trait API so higher layers can plug in taint/state lattices without rewriting CFG plumbing.  
Using this analysis framework, this report formalizes the detection of a wide array of vulnerabilities, mapping them to the OWASP Mobile Top 10\.7 These detection algorithms are stratified by cost:

* **Pattern-Based Analysis:** Fast, low-cost detection of hardcoded secrets (OWASP M1) 8, weak cryptography (OWASP M10) 9, and insecure communication (OWASP M5).10  
* **Structural Analysis:** Stateful, CFG-based detection of insecure WebView configurations (OWASP M7) 11 and insecure data storage (OWASP M9).13  
* **Taint Analysis:** Advanced, data-flow-driven detection of sensitive data logging (OWASP M6) 15, SQL injection (OWASP M7) 16, and Cross-Site Scripting (XSS).12

Finally, this report provides concrete recommendations on the Rust crate ecosystem, high-performance data interchange (FFI) strategies 17, and a two-part architectural design (core vs. runner) to ensure maximum portability, performance, and analytical soundness.

## **II. Foundational Analysis Primitives for a Rust-DEX Engine**

The foundation of any static analysis tool is not the parser itself, but the data structures the parser *builds*. The parser's role is to transform the flat, linear DEX file format into a rich, queryable, graph-based representation. The following capabilities are non-negotiable prerequisites for the analyses requested.

### **A. DEX Format Parsing and Semantic Resolution**

The Dalvik machine model is register-based, and method frames are fixed-size upon creation.19 The Rust parser's first task is to read the DEX file and its constituent structures: header, string\_ids, type\_ids, proto\_ids, field\_ids, method\_ids, and class\_defs.20  
The parser capability must extend beyond simple deserialization. It must provide a "semantic resolution" layer. An analysis engine cannot operate on raw IDs; it must be able to ask, for example, dex.get\_string(string\_id) and receive a Rust \&str, or dex.get\_method\_name(method\_id) and receive a fully-qualified method name. This resolution is the foundation for all subsequent symbolic analysis.  
For implementation, the nom parser-combinator crate is highly recommended. It is widely used, high-performance, and maintains excellent compatibility with no-std environments, a prerequisite for the wasm32-unknown-unknown target.1  
A significant architectural synergy exists between the parser's *target* and its *runtime*. Both the DEX file format and the WebAssembly binary specification make extensive use of the LEB128 variable-length integer encoding.22 This means that no-std Rust crates for parsing LEB128 (e.g., nom-leb128) are battle-tested, robust, and efficient within the Rust-WASM ecosystem. The parser will be using an encoding that is "native" to both its input and its own runtime environment, which is a strong validation of this architectural choice.

### **B. Control Flow Graph (CFG) Construction**

A Control Flow Graph (CFG) is an abstract representation of a program using nodes for basic blocks and directed edges for jumps between them.26 All serious data-flow analysis, including taint analysis, dead code elimination, and path analysis, is performed on the CFG.28  
The parser must provide a capability build\_cfg(method: \&Method) \-\> Graph\<BasicBlock, EdgeType\>. The algorithm to build this graph from a method's bytecode is as follows 30:

1. **Identify Leaders:** A "leader" is the first instruction of a basic block. The following are leaders:  
   * The very first instruction in the method.  
   * Any instruction that is the *target* of a branch or switch instruction (e.g., if-eqz, goto, packed-switch target).19  
   * Any instruction that *immediately follows* a terminator (a conditional branch, unconditional branch, or throw) instruction.  
2. **Create Basic Blocks:** For each leader, a BasicBlock node is created, containing all instructions from the leader up to and including the next terminator instruction (or the instruction just before the next leader).  
3. **Add Edges:** Edges are created to represent control flow:  
   * **Sequential:** An edge from Block A to Block B is added if Block B's leader immediately follows Block A's terminator and the terminator is *not* an unconditional branch.  
   * **Conditional:** For a conditional branch like if-test vA, vB, \+CCCC 19, two edges are added: one to the target address \+CCCC (the "taken" edge) and one to the next instruction (the "fall-through" edge).  
   * **Switch:** For packed-switch or sparse-switch 33, the associated data payload (a jump table) must be parsed, and an edge must be added for *every* case in the table, plus the default (fall-through) case.

However, a naive CFG algorithm that only models explicit branches is *unsound* for Dalvik. As stated in analysis of exception-based control flow, "Ignoring exceptions is unsound".34 Dalvik's try\_item and catch\_handler structures create non-obvious, implicit control flow edges that are critical for security analysis. A vulnerability report 35 details a bug where a register v5 holds a String in the main execution path but an Object (the caught JSONException) in the exception handler path. When these two paths converge, a type-verification error occurs.  
A sound static analysis engine *must* model this. Therefore, the build\_cfg capability *must* parse the tries\_and\_catches array for a method's code. For every try\_item, the algorithm must add a potential control-flow edge from *every single instruction* within the try block's range to the start of its corresponding catch\_handler block.36 This correctly models the flow of exception objects (via the move-exception vA instruction) and is the only way to perform sound data-flow analysis.

### **C. Inter-procedural Call Graph (CG) Construction**

A Call Graph (CG) represents all the invocation relationships between methods in an application.37 The parser must provide a capability to build this graph, build\_cg(dex\_files: &). The builder iterates all instructions in all methods, and for each invoke-\* opcode, it adds an edge in the graph. Dalvik has several such opcodes:

* invoke-static: For static methods.  
* invoke-direct: For private methods and constructors.  
* invoke-virtual: For standard public/protected object methods.  
* invoke-interface: For methods on an interface.  
* invoke-polymorphic: For signature-polymorphic methods like MethodHandle\#invoke.40

A CG based on simple instruction cross-references is incomplete and misleading for an object-oriented language. The targets of invoke-virtual and invoke-interface are statically unresolved. They reference a method on a *base type* (e.g., Ljava/io/OutputStream;-\>write(...)), but the *actual* method executed depends on the object's *runtime type* (e.g., Ljava/io/FileOutputStream;-\>write(...)).  
If the static analyzer only registers the call to the base method, it will miss countless vulnerabilities, such as a malicious class overriding a benign method. Therefore, the parser must provide an additional capability: **Class Hierarchy Analysis (CHA)**. The parser must iterate all class\_defs, parse their superclass\_idx and interfaces\_off fields, and build a complete inheritance and implementation tree for the entire application.  
When the build\_cg capability encounters an invoke-virtual to BaseClass.foo(), it must use CHA to find *every* class that inherits from BaseClass and overrides foo(). It must then add a potential edge to *each* of these implementations. This over-approximation is the standard, sound static approach to resolving virtual dispatch and is essential for any serious vulnerability analysis.

### **D. Cross-Reference (XREF) Generation**

A Cross-Reference (XREF) database maps any given identifier (method, field, string) to all locations in the code that reference it.39 This is arguably the most critical "glue" capability the parser must provide. The engine must be ableto perform, at minimum, two types of queries:

1. **xref\_to(Id):** Given a method ID, field ID, or string ID, find all instructions that use it.  
2. **xref\_from(InstructionAddress):** Given the address of an instruction, find the ID (method, field, etc.) that it references.

This XREF database is the central architectural bridge that enables the entire multi-layered analysis pipeline. It supports both the "cheap" pattern-matching analyses and the "expensive" data-flow analyses.

* **For Cheap/Syntactic Analysis:** To find weak cryptography (OWASP M10) 9, the analysis does not need to build a full data-flow graph. It can simply query: xref\_to("DES"). This returns a list of addresses. For each address, it queries xref\_from(address) to see if the instruction is const-string and is immediately followed by an invoke-virtual to Ljavax/crypto/Cipher;-\>getInstance(...). This is an extremely fast, sub-second query.  
* **For Expensive/Data-Flow Analysis:** The taint analysis engine (see Section VI) must model the effect of method calls. When its CFG traversal hits an invoke-virtual instruction, it uses the XREF database (xref\_from(instr\_addr)) to get the method\_id. It then queries its taint model (a table of sources, sinks, and sanitizers) for that method\_id to determine the instruction's effect on the taint state.

The XREF capability is not merely "a feature"; it is the central index that enables all other analyses to function and communicate.

## **III. Architecting the Analysis Engine for WebAssembly**

The primary constraint is that the entire Rust system must compile to the wasm32-unknown-unknown target. This has profound architectural implications that dictate the engine's design, choice of dependencies, and data-flow-analysis strategy.

### **A. The wasm32-unknown-unknown Target and its std Limitations**

The wasm32-unknown-unknown target is the "minimal" WebAssembly target, designed for environments that do not assume any specific OS or importable functions.1 It is the standard target for use with wasm-bindgen to facilitate interoperability with JavaScript.41  
This target *does* support the Rust std library, but it is a *crippled* version.1 Any std functionality that relies on OS-level features will fail.

* std::thread::spawn will panic.1  
* std::fs functions will always return errors.1  
* std::net and std::process are non-existent.  
* However, std::core, std::alloc (e.g., Vec, Box), and std::collections (e.g., HashMap) are fully supported and functional.1

A common pitfall is to assume this target requires a pure \#\!\[no\_std\] crate.43 This is not only untrue but makes development unnecessarily difficult. The practical, expert-level recommendation is *not* to enforce \#\!\[no\_std\], but to be **std-aware**. The developers *can* and *should* use Vec, String, and HashMap for their convenience and performance. They must simply *never* use std::thread, std::fs, or any other component that implies an OS. This "std-aware" approach is critical for making the project feasible.

### **B. Dataflow Frameworks in a WASM Context**

The user query requires a data-flow analysis (DFA) engine.28 The premier Rust dataflow frameworks are timely-dataflow 4 and differential-dataflow.3 These are powerful, incremental, data-parallel engines.  
However, these frameworks are fundamentally and architecturally incompatible with the wasm32-unknown-unknown target. timely-dataflow is described as a "distributed data-parallel compute engine".4 The browser environment, where WASM runs, inherently has a single main thread.2 As established, the WASM target panics on std::thread::spawn.1 Attempting to use timely-dataflow or differential-dataflow will fail at compile-time due to incompatible std dependencies 21 or panic at runtime.  
This leads to a critical architectural pivot. The "additional capability" the Rust engine must provide is its own **custom, single-threaded, iterative dataflow engine**. The model for this engine should be rustc\_mir\_dataflow 5 or the waffle framework.6 waffle is an existing Rust project for Wasm-to-Wasm analysis that is itself WASM-compatible. It implements a CFG with SSA and blockparams.6 The DEX analysis engine must follow this pattern: it will feed its CFG (from Section II.B) into a *single-threaded fixed-point worklist algorithm*.47 This is a major, required deviation from using an off-the-shelf DFA engine.

### **C. High-Performance FFI and Data Marshaling**

A primary performance bottleneck for WebAssembly is not its computation speed (which is near-native 48), but the cost of "chatty" communication across the JavaScript-to-WASM boundary.50 An architecture that requires many small calls (e.g., get\_method\_count(), then get\_method\_name(i) for each method) will be unacceptably slow.  
The architecture *must* be "batch-oriented".51 wasm-bindgen is the tool to build this bridge.41 The optimal data interchange strategy is as follows:

1. **Input (JS \-\> WASM):** The JavaScript host application loads the *entire* DEX file into a single Uint8Array.  
2. **JS Call:** The host calls *one* primary Rust function: \#\[wasm\_bindgen\] pub fn analyze\_dex(file\_bytes: &\[u8\]) \-\> Result\<JsValue, JsValue\>. The file\_bytes: &\[u8\] argument is a zero-copy slice of the WASM linear memory, which wasm-bindgen manages automatically.17  
3. **Compute (WASM):** The Rust engine performs *all* analysis internally—parsing, CFG/CG/XREF generation, and vulnerability detection—generating a Vec\<VulnerabilityReport\>.  
4. **Output (WASM \-\> JS):** The Rust function serializes this *entire* result vector *once* using serde\_wasm\_bindgen::to\_value(\&reports)?.18 This returns an opaque JsValue which manifests in JavaScript as a native array of objects.

This "batch" model minimizes FFI overhead. It is critical to use serde-wasm-bindgen 18 instead of serde\_json. serde\_json would create a large String in WASM, copy it into JS, and then require JS to parse it. serde-wasm-bindgen avoids the string intermediate, converting Rust structs directly to native JS objects, which is significantly faster.50  
A summary of the recommended FFI data interchange strategy is provided in Table 1\.  
**Table 1: High-Performance JS-WASM Data Interchange Strategy**

| Data Direction | Data Type | JavaScript Type | Rust Type | wasm-bindgen Method | Performance |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Input** | DEX File | Uint8Array | &\[u8\] | \#\[wasm\_bindgen\] | **Excellent** (Zero-copy view) 17 |
| **Input** | Configuration | Object | MyConfig struct | serde\_wasm\_bindgen::from\_value(val) | **Good** (Deserialization) 55 |
| **Output** | Vulnerability Report | JsValue (Array) | Vec\<MyReport\> | serde\_wasm\_bindgen::to\_value(\&vec) | **Excellent** (Native JS-object conversion) 18 |
| **Output** | Error | JsValue (Error) | MyError struct | Err(serde\_wasm\_bindgen::to\_value(\&e)?) | **Excellent** (Maps Rust Result to JS try/catch) |
| **Output** (Avoid) | Report (Slow) | String (JSON) | Vec\<MyReport\> | serde\_json::to\_string(\&vec) | **Poor** (Unnecessary string serialization) 50 |

## **IV. Formalizing Vulnerability Detection: Pattern-Based & Syntactic Analysis**

This section details the "low-cost" analyses that can be performed using the foundational capabilities, primarily by querying the string pool and the XREF database.

### **A. Detection of Hardcoded Secrets (OWASP M1: Improper Credential Usage)**

This vulnerability class maps to OWASP M1: Improper Credential Usage.7 Secrets such as API keys, passwords, and tokens are frequently hardcoded into const-string instructions.58  
The standard detection method involves iterating through all strings and applying heuristics. However, this method is notoriously prone to false positives.59 A more robust, context-aware algorithm is required.  
**Formalization (Algorithm):**

1. **Iterate string\_ids:** Loop through every string s in the DEX string pool.  
2. **Entropy Calculation:** For each s, calculate its Shannon entropy. H(s) \= \-Σ(p\_i \* log2(p\_i)) where p\_i is the probability of character i.  
3. **Regex Matching:** Run a pre-compiled regex set against s to find patterns for common secrets (e.g., AWS keys, RSA private keys).8  
4. **Flagging:** A string s is a *candidate* if H(s) \> 4.5 (a common heuristic for high randomness) OR regex.matches(s).  
5. **Context-Aware Reporting:** Simple flagging is too noisy.61 The "additional capability" is to provide *context* using the XREF database.39 Instead of just reporting the string, the engine reports:  
   * The string itself (e.g., "AKIAIOSFODNN7EXAMPLE").  
   * The heuristic that triggered (e.g., "High Entropy: 4.8" or "Regex: AWS Key").  
   * **All usage locations (from xref\_to(s)):** \[Lcom/example/Config;-\>\<init\>()V @ 0x04\], \[Lcom/example/Api;-\>doHttp()V @ 0x1A\]

This XREF-powered context allows the end user (or a subsequent automated step) to distinguish a real, in-use secret from a placeholder or dummy key, as described in.61

### **B. Detection of Insecure Cryptography (OWASP M10: Insufficient Cryptography)**

This maps to OWASP M10: Insufficient Cryptography.7 This vulnerability involves the use of known-broken or weak cryptographic algorithms, such as DES, MD5, SHA1, or the use of insecure modes like ECB.9  
A simple string search for "DES" is insufficient. The engine must prove the string is *used* in a security-critical context. This is a perfect use case for the XREF database. The specific signature for this is defined as CWE-327.9  
**Formalization (XREF Query):**

1. Identify Weak Strings: Create a set of "weak" strings from the string\_ids pool:  
   \`S\_weak \= {s | s in string\_ids where s.contains("DES") |

| s.contains("ECB") |  
| s.contains("MD5") |  
| s.contains("SHA1")}. 2\. \*\*Identify Crypto Sinks:\*\* Create a set of "sink" methods from the method\_ids: M\_sink \= {m | m in method\_ids where m.name \== "javax.crypto.Cipher.getInstance" |  
| m.name \== "java.security.MessageDigest.getInstance"}. 3\. \*\*Correlate Usages:\*\* \* For each weak string sinS\_weak: \* Get all usages: U\_s \= xref\_to(s). \* For each usage uinU\_s(which is an instruction address): \* Analyze the instruction atu. It is likely const-string vA, s. \* Scan the next few instructions in the \*same basic block\*. \* If a subsequent instruction is invoke-virtual {vA,...}, MwhereMis inM\_sink\`, **report a vulnerability**.  
This formalism proves not just the *presence* of the string "DES", but its *use* as the algorithm parameter in Cipher.getInstance, as exemplified in.9

### **C. Detection of Insecure Communication (OWASP M5: Insecure Communication)**

This maps to OWASP M5: Insecure Communication.7 This vulnerability involves the transmission of data over unencrypted, plaintext HTTP, making it vulnerable to interception. A critical variant is the loading of executable code from an http:// URL, which allows a man-in-the-middle attacker to inject malicious code.10  
**Formalization (Regex on string\_ids):**

1. **Iterate string\_ids:** Loop through every string s in the DEX string pool.  
2. **Regex Matching:** Run a compiled regex: re \= "http://\[^\\s\\"'\]+".  
3. **Flagging & Context:** Flag every match. As with secrets, the report should be enriched with XREF data. An http:// string is a finding, but its *context* determines its severity:  
   * **High Severity:** Used in Ldalvik/system/DexClassLoader;-\>\<init\>(...) (Potential RCE).10  
   * **High Severity:** Used in Landroid/webkit/WebView;-\>loadUrl(...) (Potential XSS/data injection).66  
   * **Medium Severity:** Used in Ljava/net/URL;-\>\<init\>(...) (Potential data leakage).

## **V. Formalizing Vulnerability Detection: Structural & API Misuse Analysis**

This class of analysis is more complex, requiring the engine to analyze sequences of API calls or object states *within* a method. This relies heavily on the intra-procedural CFG.

### **A. Detection of Insecure WebView Configurations (OWASP M7: Client Code Quality)**

This is a major vulnerability class under OWASP M7: Client Code Quality.7 WebView is a common source of vulnerabilities, including:

* **Remote Code Execution:** Calling addJavascriptInterface on any Android API level below 17 allows JavaScript in the WebView to execute arbitrary Java code via reflection.11  
* **File-Based XSS:** Enabling both setJavaScriptEnabled(true) and setAllowFileAccess(true) can allow malicious JavaScript to access and exfiltrate local app files.12

Detecting this requires a *stateful, intra-procedural analysis* that tracks the state of a WebSettings object.  
**Formalization (Intra-procedural CFG Analysis):**

1. **Identify Target Methods:** Use the Call Graph to find all methods M that contain an invoke-virtual to android.webkit.WebView.getSettings(). This call returns a WebSettings object.  
2. **Initialize State:** For each such method M, begin a forward scan from the getSettings() call, noting the register vR that holds the WebSettings object. Initialize a state object: state \= { js\_enabled: false, js\_interface: false, file\_access: false }.  
3. **Traverse CFG:** Perform a forward traversal (e.g., depth-first search) of the method's CFG, starting from the basic block containing the getSettings() call. Propagate the state object.  
4. **Update State:** At each instruction that operates on vR:  
   * If invoke-virtual {vR, true}, Landroid/webkit/WebSettings;-\>setJavaScriptEnabled(Z)V is found, set state.js\_enabled \= true.  
   * If invoke-virtual {vR,...}, Landroid/webkit/WebSettings;-\>addJavascriptInterface(...)V is found, set state.js\_interface \= true.  
   * If invoke-virtual {vR, true}, Landroid/webkit/WebSettings;-\>setAllowFileAccess(Z)V is found, set state.file\_access \= true.  
5. **Report:** At the exit nodes of the method (or when states merge at a CFG join point), check the combined state:  
   * if state.js\_enabled && state.js\_interface: Report **Critical RCE Vulnerability**.71  
   * if state.js\_enabled && state.fs\_access: Report **High XSS Vulnerability**.12

This stateful analysis on the CFG is far more precise than a simple check for the *presence* of these calls, as it confirms they are being set on the *same* WebSettings object.

### **B. Detection of Insecure Data Storage (OWASP M9: Insecure Data Storage)**

This maps to OWASP M9: Insecure Data Storage.7 This vulnerability occurs when sensitive data is stored in plaintext on the device, where it can be easily accessed by attackers with physical access or other malware.  
The most common culprits are unencrypted SharedPreferences 13 and SQLiteDatabase.14  
**Formalization (CG/XREF Query with Heuristics):**

1. **Identify Insecure Sinks:** Use the CG/XREF database to find *all* invocations of known-insecure storage APIs:  
   * Landroid/content/Context;-\>getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;  
   * Landroid/database/sqlite/SQLiteDatabase;-\>openDatabase(...)  
   * Landroid/database/sqlite/SQLiteDatabase;-\>rawQuery(...)  
   * Landroid/os/Environment;-\>getExternalStorageDirectory()  
2. **Identify Secure Alternatives (Heuristic):** To reduce false positives, the engine should scan the application's type\_ids for the *presence* of known-secure libraries.  
   * Landroidx/security/crypto/EncryptedSharedPreferences; 76  
   * Lnet/zetetic/database/sqlcipher/SQLiteDatabase; 14  
3. **Report:**  
   * Report all uses of the insecure sinks (from step 1\) as **High Severity**.  
   * If, however, the secure alternatives (from step 2\) are *also* found in the application, the engine can (optionally) downgrade the severity to **Medium** or **Warning**. This heuristic accounts for the possibility that the developer is aware of the issue and is using the secure libraries, though it cannot *prove* that no sensitive data is ever sent to the insecure ones (a job for taint analysis).

## **VI. Formalizing Vulnerability Detection: Data Flow and Taint Analysis**

This is the most advanced capability of the engine. It requires the custom, single-threaded data-flow engine (from Section III.B) built on top of the CFG and CG. Taint analysis tracks the flow of untrusted data ("taint") from a "source" (e.g., user input) to a "sink" (e.g., a logging function or a database query).27 Tools like Mariana Trench 79 and ScanDal 80 are built on this principle for Dalvik.

### **A. Taint Analysis Engine Formalism**

The analysis can be formally defined using a **Monotone Framework**, a standard data-flow analysis technique.47

1. **Lattice:** A simple taint lattice L is defined: L \= { ⊥ (Untainted), T (Tainted) }. ⊥ is the bottom element. The join operator ⊔ is defined as ⊥ ⊔ T \= T, T ⊔ T \= T, etc. This means a register is tainted if *any* path reaching it was tainted.  
2. **Analysis State:** The state at any program point p is a map M: V \-\> L, where V is the set of all registers (v0...vN) and relevant static fields.  
3. **Algorithm:** A single-threaded, inter-procedural, iterative fixed-point worklist algorithm is used.  
   Worklist \= {all Method.entry\_nodes}  
   AnalysisState\[all\_nodes\] \= ⊥  // Initialize all states to Untainted

   while Worklist is not empty:  
       node \= Worklist.pop() // 'node' is a BasicBlock

       // Join states from all predecessor blocks  
       InState \= ⊔(AnalysisState\[predecessors\_of\_node\]) 

       // Compute the output state by applying the block's transfer function  
       OutState \= TransferFunction\_Block(node, InState)

       // If the state changed, update it and add successors to the worklist  
       if OutState\!= AnalysisState\[node\]:  
           AnalysisState\[node\] \= OutState  
           Worklist.push(node.successors)

4. **Transfer Function:** The TransferFunction\_Block applies the TransferFunction\_Instruction for each instruction in the block. The instruction-level transfer function models Dalvik opcodes:  
   * **Propagation:** move vA, vB  
     * OutState\[vA\] \= InState  
   * **Propagation (Field Write):** iput vA, vB, Lmy/Field; (writes register vA into field)  
     * OutState\[Field\] \= InState\[vA\]  
   * **Propagation (Field Read):** iget vA, vB, Lmy/Field; (reads field into register vA)  
     * OutState\[vA\] \= InState\[Field\]  
   * **Source:** invoke-virtual {...}, Lmy/Source;-\>getFoo()Ljava/lang/String;  
     * OutState\[return\_register\] \= T (The return value is now Tainted)  
   * **Sink:** invoke-virtual {vArg,...}, Lmy/Sink;-\>log(Ljava/lang/String;)V  
     * if InState\[vArg\] \== T: report\_vulnerability()  
   * **Sanitizer:** invoke-virtual {vArg,...}, Lmy/Sanitizer;-\>encode(Ljava/lang/String;)Ljava/lang/String;  
     * OutState\[return\_register\] \= ⊥ (The value is now considered Untainted)

This formalism is *driven* by a configuration that defines the Source, Sink, and Sanitizer method sets, which are identified using the XREF/CG capabilities. This is precisely how production tools like Mariana Trench are configured.81

### **B. Detection of Sensitive Data Logging (OWASP M6: Inadequate Privacy Controls)**

This vulnerability, mapping to OWASP M6 7, is a classic taint-flow problem.83 An application must not leak Personally Identifiable Information (PII) or credentials to device logs.15  
**Formalism (Taint Configuration):**

* **Sources:**  
  * Landroid/widget/EditText;-\>getText()  
  * Landroid/telephony/TelephonyManager;-\>getLine1Number()  
  * Landroid/telephony/TelephonyManager;-\>getDeviceId()  
  * Landroid/location/Location;-\>getLatitude()  
  * Landroid/location/Location;-\>getLongitude()  
  * Landroid/accounts/Account;-\>name  
* **Sinks:**  
  * Landroid/util/Log;-\>v(Ljava/lang/String;Ljava/lang/String;)I  
  * Landroid/util/Log;-\>d(...)  
  * Landroid/util/Log;-\>i(...)  
  * Landroid/util/Log;-\>w(...)  
  * Landroid/util/Log;-\>e(...)  
  * Landroid/util/Log;-\>wtf(...) 84

### **C. Detection of Client-Side Injection (OWASP M7: Client Code Quality)**

This maps to OWASP M7 7 and includes vulnerabilities like SQL Injection 16 and WebView-based XSS.12 Mariana Trench explicitly models these as "User input flows into raw SQL statement" and "User input flows into WebView load".82  
**Formalism (Taint Configuration):**

* **Vulnerability:** SQL Injection  
  * **Sources:** Landroid/widget/EditText;-\>getText(), Landroid/content/Intent;-\>getStringExtra()  
  * **Sinks:** Landroid/database/sqlite/SQLiteDatabase;-\>rawQuery(...), Landroid/database/sqlite/SQLiteDatabase;-\>execSQL(...) 16  
* **Vulnerability:** WebView XSS  
  * **Sources:** Landroid/widget/EditText;-\>getText(), Landroid/content/Intent;-\>getStringExtra()  
  * **Sinks:** Landroid/webkit/WebView;-\>loadUrl(Ljava/lang/String;)V 12, Landroid/webkit/WebView;-\>loadData(...)

Table 2 provides a formal matrix that serves as the "brain" or configuration file for the taint analysis engine.  
**Table 2: Dalvik Taint Analysis Source/Sink Matrix**

| Vulnerability Class | OWASP Category | Taint Sources (Dalvik Methods) | Taint Sinks (Dalvik Methods) | Sanitizers (Heuristic) |
| :---- | :---- | :---- | :---- | :---- |
| **Sensitive Data Log** | M6: Inadequate Privacy | Landroid/widget/EditText;-\>getText() Landroid/telephony/TelephonyManager;-\>getLine1Number() Landroid/location/Location;-\>getLatitude() | Landroid/util/Log;-\>v(Ljava/lang/String;Ljava/lang/String;)I Landroid/util/Log;-\>d(...) Landroid/util/Log;-\>i(...) 85 | N/A |
| **SQL Injection** | M7: Client Code Quality | Landroid/widget/EditText;-\>getText() Landroid/content/Intent;-\>getStringExtra() | Landroid/database/sqlite/SQLiteDatabase;-\>rawQuery(...) Landroid/database/sqlite/SQLiteDatabase;-\>execSQL(...) 16 | Landroid/database/sqlite/SQLiteStatement;-\>... (Prepared Stmt) |
| **WebView XSS** | M7: Client Code Quality | Landroid/widget/EditText;-\>getText() Landroid/content/Intent;-\>getStringExtra() | Landroid/webkit/WebView;-\>loadUrl(Ljava/lang/String;)V 12 Landroid/webkit/WebView;-\>loadData(...) | Landroid/net/Uri;-\>parse(Ljava/lang/String;)V (and check host) |
| **RCE (Code Load)** | M2: Inad. Supply Chain | Landroid/widget/EditText;-\>getText() Ljava/net/URL;-\>openStream() (from HTTP URL) | Ldalvik/system/DexClassLoader;-\>\<init\>(...) 10 Ljava/lang/Runtime;-\>exec(...) | N/A |
| **Path Traversal** | M4: Insuff. Validation | Landroid/widget/EditText;-\>getText() Landroid/content/Intent;-\>getStringExtra() | Ljava/io/File;-\>\<init\>(Ljava/lang/String;)V Ljava/io/FileInputStream;-\>\<init\>(...) | Ljava/io/File;-\>getCanonicalPath() (and check prefix) |

## **VII. Final Architectural Recommendations and Conclusion**

### **A. Recommended Crate Ecosystem**

Based on the wasm32-unknown-unknown constraint, the following Rust crates are recommended:

* **Parsing:** nom 1 and nom-leb128.22 These provide no-std compatible, high-performance parser-combinators.  
* **Graph Structures:** petgraph.38 This is a robust, general-purpose graph library that can be used for the CFG and CG.  
* **FFI:** wasm-bindgen 41 for defining the JavaScript-Rust API, and serde-wasm-bindgen 18 for high-performance data marshaling. Avoid serde\_json for FFI data transfer.50  
* **Analysis Engine Template:** The waffle framework 6 should be studied. As a Rust-based, WASM-compatible, SSA-based analysis framework, its architecture is the *perfect model* for the custom, single-threaded data-flow engine required for this project.  
* **Visualization:** The Rust engine should not perform visualization. It should return the graph data (e.g., in DOT format or as node/edge lists). The *JavaScript host* can then use a library like plotters (which has WASM-compatible backends) to render the graphs.86

### **B. Architectural Separation: core vs. runner**

To maximize portability, a monolithic architecture should be avoided. A two-crate architecture is strongly recommended:

1. **dex-parser-core:** This crate should be pure \#\!\[no\_std\].43 Its *only* responsibility is to take &\[u8\] (the DEX file) and produce the serialized CFG, CG, and XREF data structures. It has zero std dependencies and performs no analysis.  
2. **dex-analysis-runner:** This crate *consumes* the core crate. This is the "std-aware" crate compiled for wasm32-unknown-unknown.1 It *can* use HashMap and Vec. Its job is to implement the fixed-point data-flow algorithm 47 and all the vulnerability-specific detection logic (e.g., the taint engine).

This separation allows the dex-parser-core to be reused in *any* Rust environment, including native (non-WASM) tools or other no-std embedded contexts, while the dex-analysis-runner is specialized for the WASM environment.

### **C. Performance Considerations and Limitations**

This architecture is powerful, but it is not without limitations imposed by the WASM sandbox.

* **Single-Threaded Bottleneck:** The primary limitation is that all analysis will be single-threaded.2 For very large DEX files (e.g., 50MB+), the analysis *will* be slow. The JavaScript host can (and should) run the WASM module in a Web Worker to avoid blocking the main UI thread, but the computation within that worker will still be single-threaded.51  
* **WASM Memory Management:** A critical and non-obvious limitation of WebAssembly is that its linear memory can grow but *cannot shrink*.51 An analysis of a large DEX file will cause the WASM module's memory heap to grow significantly. This memory will *not* be returned to the browser or OS until the *entire WASM instance is destroyed*. A long-running single-page application (SPA) that repeatedly uses the analyzer will suffer a massive memory leak. The JavaScript host *must* be architected to destroy and re-initialize the WASM module after a large analysis.  
* **FFI Cost:** As detailed in Section III.C, the "batch" FFI architecture is non-negotiable. A "chatty" API will nullify all performance gains from Rust/WASM.51

### **D. Conclusion**

This report has formalized the end-to-end architecture for a Rust-based, WASM-native DEX static analysis engine. It is not only feasible but presents a powerful new direction for sandboxed security tooling. We have established the required foundational parser capabilities (CFG, CG, XREF), identified the critical architectural pivot *away* from multi-threaded data-flow engines like differential-dataflow, and provided concrete formalisms for detecting a wide range of OWASP Mobile vulnerabilities. By adhering to the "batch" FFI pattern, maintaining a "std-aware" (not no-std) approach, and implementing the core/runner separation, this architecture provides a robust, high-performance, and powerful blueprint for a next-generation static analysis tool.

#### **Works cited**

1. wasm32-unknown-unknown \- The rustc book \- Rust Documentation, accessed November 15, 2025, [https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-unknown-unknown.html](https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-unknown-unknown.html)  
2. Multi-Threading the Web is not so impossible. And WASM is AWSM | by Quin Carter, accessed November 15, 2025, [https://medium.com/@quincarter/wasm-is-awsm-and-multi-threading-the-web-is-not-so-impossible-297870a6c10](https://medium.com/@quincarter/wasm-is-awsm-and-multi-threading-the-web-is-not-so-impossible-297870a6c10)  
3. An implementation of differential dataflow using timely dataflow on Rust. \- GitHub, accessed November 15, 2025, [https://github.com/TimelyDataflow/differential-dataflow](https://github.com/TimelyDataflow/differential-dataflow)  
4. A modular implementation of timely dataflow in Rust \- GitHub, accessed November 15, 2025, [https://github.com/TimelyDataflow/timely-dataflow](https://github.com/TimelyDataflow/timely-dataflow)  
5. Streamlined dataflow analysis code in rustc \- Nicholas Nethercote, accessed November 15, 2025, [https://nnethercote.github.io/2024/12/19/streamlined-dataflow-analysis-code-in-rustc.html](https://nnethercote.github.io/2024/12/19/streamlined-dataflow-analysis-code-in-rustc.html)  
6. bytecodealliance/waffle: Wasm Analysis Framework For ... \- GitHub, accessed November 15, 2025, [https://github.com/bytecodealliance/waffle](https://github.com/bytecodealliance/waffle)  
7. OWASP Mobile Top 10, accessed November 15, 2025, [https://owasp.org/www-project-mobile-top-10/](https://owasp.org/www-project-mobile-top-10/)  
8. Evaluating Large Language Models in detecting Secrets in Android Apps \- arXiv, accessed November 15, 2025, [https://arxiv.org/html/2510.18601v1](https://arxiv.org/html/2510.18601v1)  
9. Automatic Detection of Java Cryptographic API Misuses: Are We There Yet? \- IEEE Xplore, accessed November 15, 2025, [https://ieeexplore.ieee.org/ielaam/32/10008953/9711933-aam.pdf](https://ieeexplore.ieee.org/ielaam/32/10008953/9711933-aam.pdf)  
10. Execute This\! Analyzing Unsafe and Malicious Dynamic Code Loading in Android Applications, accessed November 15, 2025, [https://www.ndss-symposium.org/wp-content/uploads/2017/09/10\_5\_0.pdf](https://www.ndss-symposium.org/wp-content/uploads/2017/09/10_5_0.pdf)  
11. WebView addJavascriptInterface Remote Code Execution | WithSecure™ Labs, accessed November 15, 2025, [https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution](https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution)  
12. WebViews – Unsafe File Inclusion | Security \- Android Developers, accessed November 15, 2025, [https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion)  
13. Insecure Storage (Shared Preference) | by Shadab Ahmed Ansari | Medium, accessed November 15, 2025, [https://shadabahmedansari06.medium.com/insecure-storage-shared-preference-3bde5995f459](https://shadabahmedansari06.medium.com/insecure-storage-shared-preference-3bde5995f459)  
14. Unpacking Android Security: Part 2 — Insecure Data Storage | by Ed Holloway-George, accessed November 15, 2025, [https://proandroiddev.com/unpacking-android-security-part-2-insecure-data-storage-71f35107052a](https://proandroiddev.com/unpacking-android-security-part-2-insecure-data-storage-71f35107052a)  
15. Log Info Disclosure | Security \- Android Developers, accessed November 15, 2025, [https://developer.android.com/privacy-and-security/risks/log-info-disclosure](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)  
16. Risk Analysis and Android Application Penetration Testing Based on OWASP 2016, accessed November 15, 2025, [https://www.researchgate.net/publication/348902248\_Risk\_Analysis\_and\_Android\_Application\_Penetration\_Testing\_Based\_on\_OWASP\_2016](https://www.researchgate.net/publication/348902248_Risk_Analysis_and_Android_Application_Penetration_Testing_Based_on_OWASP_2016)  
17. Pass file from Javascript to u8 in Rust WebAssembly \- Stack Overflow, accessed November 15, 2025, [https://stackoverflow.com/questions/56685410/pass-file-from-javascript-to-u8-in-rust-webassembly](https://stackoverflow.com/questions/56685410/pass-file-from-javascript-to-u8-in-rust-webassembly)  
18. serde\_wasm\_bindgen \- Rust \- Docs.rs, accessed November 15, 2025, [https://docs.rs/serde-wasm-bindgen](https://docs.rs/serde-wasm-bindgen)  
19. Dalvik bytecode format | Android Open Source Project, accessed November 15, 2025, [https://source.android.com/docs/core/runtime/dalvik-bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode)  
20. Dalvik executable format \- Android Open Source Project, accessed November 15, 2025, [https://source.android.com/docs/core/runtime/dex-format](https://source.android.com/docs/core/runtime/dex-format)  
21. pallet \- The wasm32-unknown-unknown target is not supported by default \- Substrate and Polkadot Stack Exchange, accessed November 15, 2025, [https://substrate.stackexchange.com/questions/4174/the-wasm32-unknown-unknown-target-is-not-supported-by-default/4175](https://substrate.stackexchange.com/questions/4174/the-wasm32-unknown-unknown-target-is-not-supported-by-default/4175)  
22. LEB128 \- Wikipedia, accessed November 15, 2025, [https://en.wikipedia.org/wiki/LEB128](https://en.wikipedia.org/wiki/LEB128)  
23. LEB128 or Little Endian Base 128 \- GitHub, accessed November 15, 2025, [https://github.com/mohanson/leb128](https://github.com/mohanson/leb128)  
24. WebAssembly Specification, accessed November 15, 2025, [https://webassembly.github.io/spec/versions/core/WebAssembly-2.0.pdf](https://webassembly.github.io/spec/versions/core/WebAssembly-2.0.pdf)  
25. A WebAssembly study \- Boxbase, accessed November 15, 2025, [https://boxbase.org/entries/2016/oct/10/webassembly/](https://boxbase.org/entries/2016/oct/10/webassembly/)  
26. How to create a Control-Flow Graph of a Rust crate?, accessed November 15, 2025, [https://users.rust-lang.org/t/how-to-create-a-control-flow-graph-of-a-rust-crate/132943](https://users.rust-lang.org/t/how-to-create-a-control-flow-graph-of-a-rust-crate/132943)  
27. Static Code Analysis \- OWASP Foundation, accessed November 15, 2025, [https://owasp.org/www-community/controls/Static\_Code\_Analysis](https://owasp.org/www-community/controls/Static_Code_Analysis)  
28. oxc\_cfg \- crates.io: Rust Package Registry, accessed November 15, 2025, [https://crates.io/crates/oxc\_cfg](https://crates.io/crates/oxc_cfg)  
29. Lack of Binary Protections Mobile Top 10, accessed November 15, 2025, [http://www.cs.toronto.edu/\~arnold/427/15s/csc427/owasp/M10/report.pdf](http://www.cs.toronto.edu/~arnold/427/15s/csc427/owasp/M10/report.pdf)  
30. How to generate a Control Flow Graph from Assembly? \- Stack Overflow, accessed November 15, 2025, [https://stackoverflow.com/questions/17715147/how-to-generate-a-control-flow-graph-from-assembly](https://stackoverflow.com/questions/17715147/how-to-generate-a-control-flow-graph-from-assembly)  
31. Survey of Malware Analysis through Control Flow Graph using Machine Learning \- arXiv, accessed November 15, 2025, [https://arxiv.org/pdf/2305.08993](https://arxiv.org/pdf/2305.08993)  
32. Dalvik opcodes, accessed November 15, 2025, [http://pallergabor.uw.hu/androidblog/dalvik\_opcodes.html](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)  
33. Difference between packed switch and sparse switch dalvik opcode \- Stack Overflow, accessed November 15, 2025, [https://stackoverflow.com/questions/19855800/difference-between-packed-switch-and-sparse-switch-dalvik-opcode](https://stackoverflow.com/questions/19855800/difference-between-packed-switch-and-sparse-switch-dalvik-opcode)  
34. Data Flow Analysis with exceptions \- Computer Science Stack Exchange, accessed November 15, 2025, [https://cs.stackexchange.com/questions/59832/data-flow-analysis-with-exceptions](https://cs.stackexchange.com/questions/59832/data-flow-analysis-with-exceptions)  
35. Reference vs. Precise Reference in Dalvik Verifier \- Stack Overflow, accessed November 15, 2025, [https://stackoverflow.com/questions/43554462/reference-vs-precise-reference-in-dalvik-verifier](https://stackoverflow.com/questions/43554462/reference-vs-precise-reference-in-dalvik-verifier)  
36. ControlFlowGraph (checker-framework 3.52.0 API), accessed November 15, 2025, [https://checkerframework.org/api/org/checkerframework/dataflow/cfg/ControlFlowGraph.html](https://checkerframework.org/api/org/checkerframework/dataflow/cfg/ControlFlowGraph.html)  
37. Construct Call Graphs of Rust programs \- help, accessed November 15, 2025, [https://users.rust-lang.org/t/construct-call-graphs-of-rust-programs/13632](https://users.rust-lang.org/t/construct-call-graphs-of-rust-programs/13632)  
38. Visualize rust struct call graph within one crate \- The Rust Programming Language Forum, accessed November 15, 2025, [https://users.rust-lang.org/t/visualize-rust-struct-call-graph-within-one-crate/125038](https://users.rust-lang.org/t/visualize-rust-struct-call-graph-within-one-crate/125038)  
39. How to get Call graph using Androguard API · Issue \#464 \- GitHub, accessed November 15, 2025, [https://github.com/androguard/androguard/issues/464](https://github.com/androguard/androguard/issues/464)  
40. How to Generate INVOKE-POLYMORPHIC opcodes in Dalvik \- Stack Overflow, accessed November 15, 2025, [https://stackoverflow.com/questions/49027506/how-to-generate-invoke-polymorphic-opcodes-in-dalvik](https://stackoverflow.com/questions/49027506/how-to-generate-invoke-polymorphic-opcodes-in-dalvik)  
41. Compiling from Rust to WebAssembly \- MDN Web Docs, accessed November 15, 2025, [https://developer.mozilla.org/en-US/docs/WebAssembly/Guides/Rust\_to\_Wasm](https://developer.mozilla.org/en-US/docs/WebAssembly/Guides/Rust_to_Wasm)  
42. Are all Rust libs on crates compatible with WASM \- Reddit, accessed November 15, 2025, [https://www.reddit.com/r/rust/comments/g80pv0/are\_all\_rust\_libs\_on\_crates\_compatible\_with\_wasm/](https://www.reddit.com/r/rust/comments/g80pv0/are_all_rust_libs_on_crates_compatible_with_wasm/)  
43. Rust \`no\_std\` Playbook \- HackMD, accessed November 15, 2025, [https://hackmd.io/@alxiong/rust-no-std](https://hackmd.io/@alxiong/rust-no-std)  
44. no\_std \- The Embedded Rust Book, accessed November 15, 2025, [https://docs.rust-embedded.org/book/intro/no-std.html](https://docs.rust-embedded.org/book/intro/no-std.html)  
45. Building Differential Dataflow from Scratch \- Materialize, accessed November 15, 2025, [https://materialize.com/blog/differential-from-scratch/](https://materialize.com/blog/differential-from-scratch/)  
46. Tutorial on "Dataflow programming in Rust", accessed November 15, 2025, [https://users.rust-lang.org/t/tutorial-on-dataflow-programming-in-rust/64130](https://users.rust-lang.org/t/tutorial-on-dataflow-programming-in-rust/64130)  
47. Static Taint Analysis in Rust, accessed November 15, 2025, [https://projekter.aau.dk/projekter/files/421583418/Static\_Taint\_Analysis\_in\_Rust.pdf](https://projekter.aau.dk/projekter/files/421583418/Static_Taint_Analysis_in_Rust.pdf)  
48. Bringing Rust's Performance to the Web with WebAssembly | Leapcell, accessed November 15, 2025, [https://leapcell.io/blog/bringing-rust-s-performance-to-the-web-with-webassembly](https://leapcell.io/blog/bringing-rust-s-performance-to-the-web-with-webassembly)  
49. Optimizing Frontend Performance with WebAssembly and Rust \- DEV Community, accessed November 15, 2025, [https://dev.to/joshuawasike/optimizing-frontend-performance-with-webassembly-and-rust-5b2k](https://dev.to/joshuawasike/optimizing-frontend-performance-with-webassembly-and-rust-5b2k)  
50. why wasm-bindgen with serde\_json slower 10 times than nodejs JSON.parse : r/rust, accessed November 15, 2025, [https://www.reddit.com/r/rust/comments/1h9ikt7/why\_wasmbindgen\_with\_serde\_json\_slower\_10\_times/](https://www.reddit.com/r/rust/comments/1h9ikt7/why_wasmbindgen_with_serde_json_slower_10_times/)  
51. Is Rust \+ WASM a good choice for a computation heavy frontend? \- Reddit, accessed November 15, 2025, [https://www.reddit.com/r/rust/comments/1i179jy/is\_rust\_wasm\_a\_good\_choice\_for\_a\_computation/](https://www.reddit.com/r/rust/comments/1i179jy/is_rust_wasm_a_good_choice_for_a_computation/)  
52. Support for u8 slices · Issue \#5 · wasm-bindgen/wasm-bindgen \- GitHub, accessed November 15, 2025, [https://github.com/rustwasm/wasm-bindgen/issues/5](https://github.com/rustwasm/wasm-bindgen/issues/5)  
53. How to pass an array of primitive element type from javascript to wasm in Rust fast?, accessed November 15, 2025, [https://stackoverflow.com/questions/64887395/how-to-pass-an-array-of-primitive-element-type-from-javascript-to-wasm-in-rust-f](https://stackoverflow.com/questions/64887395/how-to-pass-an-array-of-primitive-element-type-from-javascript-to-wasm-in-rust-f)  
54. serde-wasm-bindgen \- crates.io: Rust Package Registry, accessed November 15, 2025, [https://crates.io/crates/serde-wasm-bindgen](https://crates.io/crates/serde-wasm-bindgen)  
55. Arbitrary Data with Serde \- The \`wasm-bindgen\` Guide \- Rust and WebAssembly, accessed November 15, 2025, [https://rustwasm.github.io/docs/wasm-bindgen/reference/arbitrary-data-with-serde.html](https://rustwasm.github.io/docs/wasm-bindgen/reference/arbitrary-data-with-serde.html)  
56. Top 10 Mobile Risks \- OWASP Mobile Top 10 2024 \- Final Release, accessed November 15, 2025, [https://owasp.org/www-project-mobile-top-10/2023-risks/](https://owasp.org/www-project-mobile-top-10/2023-risks/)  
57. OWASP Mobile Top 10 Vulnerabilities \[2025 Updated\]: Key Impacts & Preventions, accessed November 15, 2025, [https://strobes.co/blog/owasp-mobile-top-10-vulnerabilities-2024-updated/](https://strobes.co/blog/owasp-mobile-top-10-vulnerabilities-2024-updated/)  
58. HackingTeam back for your Androids, now extra insecure\! \- RedNaga Security, accessed November 15, 2025, [https://rednaga.io/2016/11/14/hackingteam\_back\_for\_your\_androids/](https://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/)  
59. Beyond Regex: Detect the Generic Secrets Other Tools Miss with Cycode's AI-Powered Precision & Custom Rules, accessed November 15, 2025, [https://cycode.com/blog/generic-secrets-detection/](https://cycode.com/blog/generic-secrets-detection/)  
60. Building reliable secrets detection \- Secrets in source code (episode 3/3) \- GitGuardian Blog, accessed November 15, 2025, [https://blog.gitguardian.com/secrets-in-source-code-episode-3-3-building-reliable-secrets-detection/](https://blog.gitguardian.com/secrets-in-source-code-episode-3-3-building-reliable-secrets-detection/)  
61. Leaking Secrets : Building an LLM-Powered Secret Scanner for Codebases \- Medium, accessed November 15, 2025, [https://medium.com/@athreya258/leaking-secrets-building-an-llm-powered-secret-scanner-for-codebases-9b76270c3694](https://medium.com/@athreya258/leaking-secrets-building-an-llm-powered-secret-scanner-for-codebases-9b76270c3694)  
62. M5: Insufficient Cryptography \- OWASP Foundation, accessed November 15, 2025, [https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography](https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography)  
63. Static and Dynamic Analysis in Cryptographic-API ... \- William & Mary, accessed November 15, 2025, [https://scholarworks.wm.edu/bitstreams/9b372b8a-d43c-4c9a-b237-ee5507dd5d79/download](https://scholarworks.wm.edu/bitstreams/9b372b8a-d43c-4c9a-b237-ee5507dd5d79/download)  
64. arXiv:2205.05573v4 \[cs.CR\] 6 Jul 2022, accessed November 15, 2025, [https://arxiv.org/pdf/2205.05573](https://arxiv.org/pdf/2205.05573)  
65. M5: Insecure Communication \- OWASP Foundation, accessed November 15, 2025, [https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)  
66. Helping Developers Construct Secure Mobile Applications \- Berkeley EECS, accessed November 15, 2025, [https://www2.eecs.berkeley.edu/Pubs/TechRpts/2013/EECS-2013-58.pdf](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2013/EECS-2013-58.pdf)  
67. M7: Client Code Quality \- Kotlin SCP, accessed November 15, 2025, [https://checkmarx.github.io/Kotlin-SCP/m7-client-code-quality/](https://checkmarx.github.io/Kotlin-SCP/m7-client-code-quality/)  
68. M7: Poor Code Quality | OWASP Foundation, accessed November 15, 2025, [https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality](https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality)  
69. OWASP M7: Poor Code Quality \- CloudDefense.AI, accessed November 15, 2025, [https://www.clouddefense.ai/owasp/2016/7](https://www.clouddefense.ai/owasp/2016/7)  
70. CVE-2012-6636 Detail \- NVD, accessed November 15, 2025, [https://nvd.nist.gov/vuln/detail/CVE-2012-6636](https://nvd.nist.gov/vuln/detail/CVE-2012-6636)  
71. Remediation for JavaScript Interface Injection Vulnerability \- Google Help, accessed November 15, 2025, [https://support.google.com/faqs/answer/9095419?hl=en](https://support.google.com/faqs/answer/9095419?hl=en)  
72. Cross-app scripting | Security \- Android Developers, accessed November 15, 2025, [https://developer.android.com/privacy-and-security/risks/cross-app-scripting](https://developer.android.com/privacy-and-security/risks/cross-app-scripting)  
73. M2: Insecure Data Storage | OWASP Foundation, accessed November 15, 2025, [https://owasp.org/www-project-mobile-top-10/2014-risks/m2-insecure-data-storage](https://owasp.org/www-project-mobile-top-10/2014-risks/m2-insecure-data-storage)  
74. Android Pentesting: Writeup of DIVA Insecure Data Storage for Parrot OS \- DEV Community, accessed November 15, 2025, [https://dev.to/christinec\_dev/android-pentesting-writeup-of-diva-insecure-data-storage-for-parrot-os-5165](https://dev.to/christinec_dev/android-pentesting-writeup-of-diva-insecure-data-storage-for-parrot-os-5165)  
75. security \- Insecure Local Storage in Android \- Stack Overflow, accessed November 15, 2025, [https://stackoverflow.com/questions/72528482/insecure-local-storage-in-android](https://stackoverflow.com/questions/72528482/insecure-local-storage-in-android)  
76. Encrypted Shared Preferences in Android \- GeeksforGeeks, accessed November 15, 2025, [https://www.geeksforgeeks.org/android/encrypted-shared-preferences-in-android/](https://www.geeksforgeeks.org/android/encrypted-shared-preferences-in-android/)  
77. Overview | Mariana Trench, accessed November 15, 2025, [https://mariana-tren.ch/docs/overview/](https://mariana-tren.ch/docs/overview/)  
78. Understanding Sources and Sinks: A Guide to Taint Analysis \- BreachForce, accessed November 15, 2025, [https://breachforce.net/source-and-sinks](https://breachforce.net/source-and-sinks)  
79. facebook/mariana-trench: A security focused static analysis tool for Android and Java applications. \- GitHub, accessed November 15, 2025, [https://github.com/facebook/mariana-trench](https://github.com/facebook/mariana-trench)  
80. Static Taint Analysis Tools to Detect Information Flows \- UCCS Faculty Sites, accessed November 15, 2025, [https://faculty.uccs.edu/kwalcott/wp-content/uploads/sites/49/2024/01/SERP18DanBoxler.pdf](https://faculty.uccs.edu/kwalcott/wp-content/uploads/sites/49/2024/01/SERP18DanBoxler.pdf)  
81. Analysis Configuration Options \- Mariana Trench, accessed November 15, 2025, [https://mariana-tren.ch/docs/configuration/](https://mariana-tren.ch/docs/configuration/)  
82. A journey using Android static source code analysis tools \- Stackered, accessed November 15, 2025, [https://stackered.com/blog/android-static-analysis/](https://stackered.com/blog/android-static-analysis/)  
83. Mobile Application Security \- OWASP Cheat Sheet Series, accessed November 15, 2025, [https://cheatsheetseries.owasp.org/cheatsheets/Mobile\_Application\_Security\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html)  
84. Android Log.v(), Log.d(), Log.i(), Log.w(), Log.e() \- When to use each one?, accessed November 15, 2025, [https://stackoverflow.com/questions/7959263/android-log-v-log-d-log-i-log-w-log-e-when-to-use-each-one](https://stackoverflow.com/questions/7959263/android-log-v-log-d-log-i-log-w-log-e-when-to-use-each-one)  
85. MASTG-TEST-0003: Testing Logs for Sensitive Data \- OWASP Mobile Application Security, accessed November 15, 2025, [https://mas.owasp.org/MASTG-TEST-0003/](https://mas.owasp.org/MASTG-TEST-0003/)  
86. plotters-rs/plotters: A rust drawing library for high quality data plotting for both WASM and native, statically and realtimely \- GitHub, accessed November 15, 2025, [https://github.com/plotters-rs/plotters](https://github.com/plotters-rs/plotters)  
87. Visualization — list of Rust libraries/crates // Lib.rs, accessed November 15, 2025, [https://lib.rs/visualization](https://lib.rs/visualization)  
88. Rust \+ Wasm for High-Performance Data Tools | by Nikulsinh Rajput | Sep, 2025 | Medium, accessed November 15, 2025, [https://medium.com/@hadiyolworld007/rust-wasm-for-high-performance-data-tools-b7ffe6f534f1](https://medium.com/@hadiyolworld007/rust-wasm-for-high-performance-data-tools-b7ffe6f534f1)
