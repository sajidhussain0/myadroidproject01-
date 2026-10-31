/*
 * hook_template.js
 *
 * Reusable Frida hooking template distilled from the Hextree Dynamic
 * Instrumentation labs (io.hextree.fridatarget). Copy this file per
 * target, fill in the TODOs, and run with:
 *
 *   frida -H 127.0.0.1:27042 -n FridaTarget -l hook_template.js
 *   # or spawn:
 *   frida -H 127.0.0.1:27042 -f io.hextree.fridatarget -l hook_template.js
 *
 * Only use against your own apps or authorized training targets.
 */

Java.perform(() => {

  // ---------------------------------------------------------------
  // 1. BASIC CLASS LOOKUP — confirm a class exists / inspect it
  // ---------------------------------------------------------------
  // const Target = Java.use("fully.qualified.ClassName");
  // console.log("[*] Loaded class:", Target);

  // ---------------------------------------------------------------
  // 2. CONSTRUCTOR HOOK ($init)
  // ---------------------------------------------------------------
  // const FlagClass = Java.use("io.hextree.fridatarget.FlagClass");
  // const ctor = FlagClass.$init.overload(); // add arg types if constructor takes args
  // ctor.implementation = function (...args) {
  //   console.log("[*] FlagClass constructor called with:", args);
  //   return ctor.call(this, ...args); // always call through unless you deliberately skip it
  // };

  // ---------------------------------------------------------------
  // 3. METHOD HOOK — log original return value, pass it through (safe default)
  // ---------------------------------------------------------------
  // const Target2 = Java.use("fully.qualified.ClassName");
  // const safeMethod = Target2.methodName.overload(); // or .overload("java.lang.String", ...)
  // safeMethod.implementation = function (...args) {
  //   const result = safeMethod.call(this, ...args);
  //   console.log("[*] methodName() original result:", result);
  //   return result; // pass-through: does not change behavior
  // };

  // ---------------------------------------------------------------
  // 4. METHOD HOOK — replace return value (lab / authorized use only)
  // ---------------------------------------------------------------
  // const Target3 = Java.use("fully.qualified.ClassName");
  // const overrideMethod = Target3.methodName.overload();
  // overrideMethod.implementation = function (...args) {
  //   const result = overrideMethod.call(this, ...args);
  //   console.log("[*] Original:", result, "-> replacing with LAB_REPLACEMENT");
  //   return "LAB_REPLACEMENT"; // type must match the method's declared return type
  // };

  // ---------------------------------------------------------------
  // 5. ENUMERATE OVERLOADS — find the right signature before hooking
  // ---------------------------------------------------------------
  // const ToInspect = Java.use("fully.qualified.ClassName");
  // ToInspect.methodName.overloads.forEach((ov) => console.log("[*] overload:", ov));

  console.log("[*] hook_template.js loaded. Edit the TODO sections above and re-run.");
});

/*
 * ---------------------------------------------------------------
 * REFERENCE: frida-trace one-liners (run from shell, not in this file)
 * ---------------------------------------------------------------
 * Trace all Java methods in a package namespace:
 *   frida-trace -H 127.0.0.1:27042 -j 'io.hextree.!' -n FridaTarget
 *
 * Trace a specific lifecycle method:
 *   frida-trace -H 127.0.0.1:27042 -j 'android.app.Activity!onResume' -n FridaTarget
 *
 * Trace native library exports:
 *   frida-trace -H 127.0.0.1:27042 -n FridaTarget -I 'libhextree.so'
 *
 * Trace Java + native together:
 *   frida-trace -H 127.0.0.1:27042 -n FridaTarget -j 'io.hextree.!' -I 'libhextree.so'
 *
 * Reminders:
 *   - A constructor is $init.
 *   - this.methodName(...) inside its own hook can recurse — use the saved
 *     overload's .call(this, ...) instead.
 *   - "Started tracing 0 functions" means the pattern matched nothing; it
 *     does not prove the class/method is absent.
 *   - Verify every class name / signature against the live target first.
 */
