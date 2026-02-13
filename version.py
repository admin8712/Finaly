#!/usr/bin/env python3
import os, sys, subprocess, shutil, re, time, random, string

# --- TEMA NEON CYBERPUNK (ULTIMATUM X V100.5 IDENTITY) ---
C_CYAN    = "\033[38;5;51m"
C_PINK    = "\033[38;5;201m"
C_GREEN   = "\033[38;5;46m"
C_RED     = "\033[38;5;196m"
C_YELLOW  = "\033[38;5;226m"
C_ORANGE  = "\033[38;5;208m"
C_WHITE   = "\033[38;5;255m"
C_GRAY    = "\033[38;5;240m"
C_BOLD    = "\033[1m"
C_RESET   = "\033[0m"

# Icon Status
ICON_INFO = f"{C_GRAY}[•]{C_RESET}"
ICON_WARN = f"{C_GRAY}[!] {C_RESET}"
ICON_ERR  = f"{C_GRAY}[X] {C_RESET}"
ICON_OK   = f"{C_GREEN}[✓] {C_RESET}"
ICON_INPUT= f"{C_GRAY}[?]{C_RESET}"

def clear(): os.system('clear' if os.name == 'posix' else 'cls')
def get_terminal_width():
    try: return shutil.get_terminal_size().columns
    except: return 80

def print_line(char="═"):
    w = get_terminal_width()
    print(f"{C_CYAN}{char * w}{C_RESET}")

def print_center(text):
    w = get_terminal_width()
    print(text.center(w))

def stream_output(cmd, env=None):
    """Fungsi untuk menangkap output dan mewarnainya menjadi BIRU CYAN"""
    process = subprocess.Popen(cmd, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        if line.strip():
            print(f"{C_CYAN}{line.strip()}{C_RESET}")
    process.wait()
    return process.returncode

def banner():
    w = get_terminal_width()
    logo_lines = [
        f"{C_CYAN}██╗  ██╗ █████╗ ██████╗ ██╗",
        f"██║  ██║██╔══██╗██╔══██╗██║",
        f"███████║███████║██║  ██║██║",
        f"██╔══██║██╔══██║██║  ██║██║",
        f"██║  ██║██║  ██║██████╔╝██║",
        f"╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝{C_RESET}"
    ]
    print_line("═")
    for line in logo_lines:
        clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        padding = (w - len(clean_line)) // 2
        print(" " * padding + line)
    print_center(f"{C_GRAY}Version: V100.5 Injection Mooder{C_RESET}")
    print_center(f"{C_GRAY}Tools Mooder Indonesian{C_RESET}")
    print_line("─")

class GodEngineV100:
    def __init__(self):
        self.work_dir = os.path.join(os.getcwd(), ".vault_v100")
        self.tmp_dir = os.path.expanduser("~/tmp")
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.menus = [
            "Deep Intent Interceptor", "Global Network Sniffer", "Supreme SSL Unpin v8", "Root-Beer Absolute Kill",
            "Anti-Debug JDWP Stripper", "Dynamic String Decryptor", "Native Method Tracer", "Transparent Proxy Kill",
            "SQL Query Hijacker", "HTTP Header Manipulator", "JWT Auth Extractor", "Hardware ID Ghoster",
            "MAC Address Faker", "IMEI/IMSI Obfuscator", "GMS Core Emulator", "Firebase Remote Hijack",
            "Analytics Blackhole", "System Update Blocker", "Sandbox/VM Cloaker", "Emulator Ghosting",
            "Magisk/Zygisk Hider", "Play Integrity Mock", "Signature Verification Kill", "Ad-Server Sinkhole",
            "Billing Flow Emulator", "IAP Transaction Faker", "Native Heap Monitor", "SharedPrefs Real-Time",
            "System Time Freezer", "Refresh Rate Unlocker", "View Hierarchy Editor", "Force-Quit Shield",
            "Logcat Scrubber", "Reflective Method Hijack", "Native Library Sniper", "pairip bypas",
            "Universal Pass Sniffer", "Ultimate Pass Overrider", "EXIT / KELUAR"
        ]

    def build_foundation_dex(self, custom_val):
        """Membangun pondasi DEX baru (Dex Builder) untuk bypass login"""
        smali_folders = [d for d in os.listdir(self.work_dir) if d.startswith('smali')]
        next_idx = len(smali_folders) + 1
        foundation_path = os.path.join(self.work_dir, f"smali_classes{next_idx}", "com", "hadi", "foundation")
        os.makedirs(foundation_path, exist_ok=True)
        
        smali_code = f""".class public Lcom/hadi/foundation/LoginSystem;
.super Ljava/lang/Object;

.method public static checkAccess()Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method

.method public static getIdentity()Ljava/lang/String;
    .registers 1
    const-string v0, "{custom_val if custom_val else 'HADI-ROOT'}"
    return v0
.end method
"""
        with open(os.path.join(foundation_path, "LoginSystem.smali"), "w") as f:
            f.write(smali_code)
        return "Lcom/hadi/foundation/LoginSystem;"

    def get_logic(self, mid, custom_val=None):
        logic_db = {
            1: "var A=Java.use('android.app.Activity');A.startActivity.implementation=function(i){console.log('[INTENT] '+i.toUri(0));return A.startActivity.call(this,i);};",
            2: "var U=Java.use('java.net.URL');U.openConnection.implementation=function(){console.log('[NET] '+this.toString());return this.openConnection();};",
            3: "var ssl=['libssl.so','libcrypto.so','libconscrypt_jni.so'];ssl.forEach(function(l){var addr=Module.findExportByName(l,'SSL_CTX_set_custom_verify');if(addr)Interceptor.attach(addr,{onEnter:function(args){args[1]=ptr(0);}});});Java.perform(function(){try{Java.use('okhttp3.CertificatePinner').check.implementation=function(){return;};}catch(e){}});",
            4: "var RB=Java.use('com.scottyab.rootbeer.RootBeer');RB.isRooted.implementation=function(){return false;};",
            5: "Java.use('android.os.Debug').isDebuggerConnected.implementation=function(){return false;};",
            6: "Java.use('java.lang.StringBuilder').toString.implementation=function(){var s=this.toString();if(s.length>10)console.log('[STR] '+s);return s;};",
            7: "var dl=Module.findExportByName(null,'dlopen');Interceptor.attach(dl,{onEnter:function(a){console.log('[NATIVE-LOAD] '+a[0].readUtf8String());}});",
            8: "Java.use('java.net.ProxySelector').setDefault.implementation=function(p){return;};",
            9: "Java.use('android.database.sqlite.SQLiteDatabase').rawQuery.overload('java.lang.String','[Ljava.lang.String;').implementation=function(q,a){console.log('[SQL] '+q);return this.rawQuery(q,a);};",
            10: "Java.use('java.net.HttpURLConnection').setRequestProperty.implementation=function(k,v){console.log('[HDR] '+k+': '+v);this.setRequestProperty(k,v);};",
            11: "Java.use('android.content.ContentValues').put.overload('java.lang.String','java.lang.String').implementation=function(k,v){console.log('[DATA] '+k+'='+v);return this.put(k,v);};",
            12: "Java.use('android.os.Build').SERIAL.value='HADI-'+Math.random().toString(36).substring(5);",
            13: "Java.use('java.net.NetworkInterface').getHardwareAddress.implementation=function(){return Java.array('byte',[0x00,0x08,0x22,0x11,0x44,0x55]);};",
            14: "Java.use('android.telephony.TelephonyManager').getDeviceId.overload().implementation=function(){return '35'+Math.floor(Math.random()*10**13);};",
            15: "Java.use('com.google.android.gms.common.GoogleApiAvailability').isGooglePlayServicesAvailable.implementation=function(){return 0;};",
            16: "try{Java.use('com.google.firebase.remoteconfig.FirebaseRemoteConfig').activate.implementation=function(){return true;};}catch(e){}",
            17: "Java.use('com.google.android.gms.analytics.Tracker').send.implementation=function(){return;};",
            18: "Java.use('android.content.Intent').getAction.implementation=function(){return 'android.intent.action.MAIN';};",
            19: "var B=Java.use('android.os.Build');B.MODEL.value='Pixel 8 Pro';B.MANUFACTURER.value='Google';",
            20: "Java.use('android.os.Build').FINGERPRINT.value='google/husky/husky:14/UD1A.230803.041/10808577:user/release-keys';",
            21: "var F=Java.use('java.io.File');F.exists.implementation=function(){var n=this.getName();if(n.match(/su|magisk|frida/i))return false;return F.exists.call(this);};",
            22: "try{Java.use('com.google.android.gms.integrity.IntegrityTokenResponse').token.implementation=function(){return 'eyJhbGciOiJIUzI1NiJ9.U09L';};}catch(e){}",
            23: "Java.use('android.app.ApplicationPackageManager').getPackageInfo.overload('java.lang.String','int').implementation=function(p,f){return this.getPackageInfo.call(this,p,f);};",
            24: "try{Java.use('com.google.android.gms.ads.AdRequest$Builder').build.implementation=function(){return null;};}catch(e){}",
            25: "var PR=Java.use('com.android.billingclient.api.Purchase');PR.getPurchaseState.implementation=function(){return 1;};",
            26: "Java.use('com.android.billingclient.api.BillingResult').getResponseCode.implementation=function(){return 0;};",
            27: "var AM=Java.use('android.app.ActivityManager');AM.getMemoryInfo.implementation=function(m){this.getMemoryInfo(m);m.lowMemory.value=false;};",
            28: "Java.use('android.app.SharedPreferencesImpl$EditorImpl').putString.implementation=function(k,v){console.log('[PREF] '+k+'='+v);return this.putString(k,v);};",
            29: "Java.use('android.os.SystemClock').elapsedRealtime.implementation=function(){return 1000000;};",
            30: "Java.use('android.view.Display').getRefreshRate.implementation=function(){return 120.0;};",
            31: "Java.use('android.view.View').setVisibility.implementation=function(v){return this.setVisibility.call(this,v);};",
            32: "Java.use('android.app.Activity').finish.implementation=function(){console.log('[BLOCK] App tried to close');};",
            33: "var lw=Module.findExportByName('liblog.so','__android_log_write');if(lw)Interceptor.attach(lw,{onEnter:function(a){a[2].writeUtf8String('[CLEAN]');}});",
            34: "Java.use('java.lang.reflect.Method').setAccessible.implementation=function(b){return this.setAccessible.call(this,true);};",
            35: "var op=Module.findExportByName(null,'open');Interceptor.attach(op,{onEnter:function(a){var p=a[0].readUtf8String();if(p.includes('.so'))console.log('[NATIVE-OPEN] '+p);}});",
            36: "Java.perform(function(){ try { Java.use('com.pairip.LicenseChecker').checkLicense.implementation = function(){ return true; }; } catch(e){} var clss = Java.enumerateLoadedClassesSync(); clss.forEach(function(n){ if(n.toLowerCase().includes('password')){ var target = Java.use(n); var mthds = target.class.getDeclaredMethods(); mthds.forEach(function(m){ var name = m.getName(); target[name].implementation = function(){ var arg = arguments[0]; console.log('\\n💎 [FOUND PASSWORD] 💎\\nMethod: ' + name + '\\nData: ' + arg + '\\n'); return this[name].apply(this, arguments); }; }); } }); });",
            37: """ // UNIVERSAL PASS SNIFFER
                var targetWords = ["password", "login", "auth", "credential", "pass"];
                Java.enumerateLoadedClasses({
                    onMatch: function (className) {
                        targetWords.forEach(function (word) {
                            if (className.toLowerCase().includes(word)) {
                                try {
                                    var clazz = Java.use(className);
                                    var methods = clazz.class.getDeclaredMethods();
                                    methods.forEach(function (method) {
                                        var methodName = method.getName();
                                        clazz[methodName].overloads.forEach(function (overload) {
                                            overload.implementation = function () {
                                                var args = arguments;
                                                console.log("\\n[💎 DETECTED ACTIVITY]\\nClass  : " + className + "\\nMethod : " + methodName);
                                                for (var i = 0; i < args.length; i++) {
                                                    console.log("Arg[" + i + "]: " + (args[i] ? args[i].toString() : "null"));
                                                }
                                                return this[methodName].apply(this, args);
                                            };
                                        });
                                    });
                                } catch (e) {}
                            }
                        });
                    },
                    onComplete: function () {}
                });
                Java.use("android.widget.TextView").setText.overload("java.lang.CharSequence").implementation = function (text) {
                    if (text && text.toString().length > 0) console.log("[⌨️ TYPING DETECTED]: " + text);
                    return this.setText(text);
                };
            """,
            38: f""" // ULTIMATE PASS OVERRIDER (FOUNDATION MODE)
                console.log("[!] FOUNDATION ACTIVE: OVERRIDING VIA com.hadi.foundation.LoginSystem");
                Java.perform(function() {{
                    var F = Java.use("com.hadi.foundation.LoginSystem");
                    var targetWords = ["password", "getpass", "checkpassword"];
                    Java.enumerateLoadedClasses({{
                        onMatch: function(className) {{
                            targetWords.forEach(function(word) {{
                                if (className.toLowerCase().includes(word)) {{
                                    try {{
                                        var clazz = Java.use(className);
                                        clazz.class.getDeclaredMethods().forEach(function(m) {{
                                            var mName = m.getName();
                                            var rType = m.getReturnType().getName();
                                            if (rType.includes("java.lang.String")) {{
                                                clazz[mName].implementation = function() {{ return F.getIdentity(); }};
                                            }}
                                            if (rType.includes("boolean")) {{
                                                clazz[mName].implementation = function() {{ return F.checkAccess(); }};
                                            }}
                                        }});
                                    }} catch(e) {{}}
                                }}
                            }});
                        }},
                        onComplete: function() {{}}
                    }});
                }});
            """
        }
        active = logic_db.get(int(mid), f"console.log('Module {mid} active');")
        return f"Java.perform(function(){{ try{{ {active} }}catch(e){{}} }});"

    def start_patch(self, mid):
        custom_val = None
        if mid == "38":
            print(f"\n{ICON_INPUT} {C_GRAY}Foundation Identity (Pass):")
            custom_val = input(f"{C_GRAY}└─{C_RESET}$ ").strip()

        apks = [f for f in os.listdir('.') if f.endswith('.apk') and "HADI_" not in f]
        w = get_terminal_width()
        if not apks: print(f"{ICON_ERR} {C_RED}No APK found!{C_RESET}"); return

        print(f"{C_CYAN}╔{'═' * (w-2)}╗{C_RESET}")
        print_center(f"{C_GRAY}            SELECT TARGET APK{C_RESET}")
        print(f"{C_CYAN}╠{'═' * (w-2)}╣{C_RESET}")
        for i, a in enumerate(apks, 1):
            item = f"[{i:02}] {a}"
            print(f"{C_CYAN}║ {C_GRAY}{item}{' ' * (w-4-len(item))} {C_CYAN}║{C_RESET}")
        print(f"{C_CYAN}╚{'═' * (w-2)}╝{C_RESET}")

        try:
            choice_idx = input(f"\n{ICON_INPUT} {C_GRAY}Select Number: {C_YELLOW}")
            target = apks[int(choice_idx) - 1]
        except: return

        shutil.rmtree(self.work_dir, ignore_errors=True)
        
        # --- DECOMPILE MODE -r (PASTI BERHASIL) ---
        print(f"\n{ICON_INFO} {C_GRAY}Decompiling {target}...{C_RESET}")
        env = os.environ.copy()
        env["JAVA_OPTS"] = f"-Djava.io.tmpdir={self.tmp_dir}"
        cmd_dec = f"java -Djava.io.tmpdir={self.tmp_dir} -jar apktool.jar d -r -f \"{target}\" -o \"{self.work_dir}\""
        stream_output(cmd_dec, env=env)

        # Injeksi Foundation Classes jika mid == 38
        foundation_class = None
        if mid == "38":
            print(f"{ICON_INFO} {C_GREEN}Building Foundation Classes...{C_RESET}")
            foundation_class = self.build_foundation_dex(custom_val)

        for root, _, files in os.walk(self.work_dir):
            for file in files:
                if file.endswith(".smali") and not any(x in file for x in ["R$", "BuildConfig"]):
                    path = os.path.join(root, file)
                    with open(path, "r", errors="ignore") as f: lines = f.readlines()
                    if any("onCreate(" in l for l in lines):
                        if any("frida-gadget" in l for l in lines): continue
                        new_lines = []
                        skip_old_locals = False
                        for line in lines:
                            if (".locals" in line or ".registers" in line) and not skip_old_locals:
                                new_lines.append("    .locals 10\n")
                                new_lines.append("    const-string v0, \"frida-gadget\"\n")
                                new_lines.append("    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n")
                                if mid == "38": # Panggil pondasi agar dimuat ke memory
                                    new_lines.append(f"    invoke-static {{}}, {foundation_class}->checkAccess()Z\n")
                                skip_old_locals = True
                                continue
                            new_lines.append(line)
                        if skip_old_locals:
                            with open(path, "w") as f: f.writelines(new_lines)
                            print(f"{ICON_OK}{C_GREEN}Injected SMALI: {C_CYAN}{file}{C_RESET}")

        js_payload = self.get_logic(mid, custom_val)
        for arch in ["arm64-v8a", "armeabi-v7a"]:
            lib_path = os.path.join(self.work_dir, "lib", arch); os.makedirs(lib_path, exist_ok=True)
            gadget_src = "frida-64.so" if "64" in arch else "frida-32.so"
            if os.path.exists(gadget_src):
                shutil.copy(gadget_src, os.path.join(lib_path, "libfrida-gadget.so"))
                with open(os.path.join(lib_path, "libfrida-gadget.config"), "w") as f:
                    f.write('{"interaction":{"type":"script","path":"logic.js","on_load":"run"}}')
                with open(os.path.join(lib_path, "logic.js"), "w") as f: f.write(js_payload)

        # --- REBUILD MODE AMAN ---
        print(f"{ICON_INFO} {C_GRAY}Rebuilding APK...{C_RESET}")
        cmd_build = f'java -Djava.io.tmpdir={self.tmp_dir} -jar apktool.jar b "{self.work_dir}" -o uns.apk'
        stream_output(cmd_build, env=env)

        # SIGN APK
        print(f"{ICON_INFO} {C_GRAY}Signing APK...{C_RESET}")
        cmd_sign = f"java -Djava.io.tmpdir={self.tmp_dir} -jar uber-apk-signer.jar -a uns.apk --overwrite"
        stream_output(cmd_sign, env=env)

        out = f"HADI_ULTIMATUM_{mid}_{target}"
        final_file = "uns-aligned-debugSigned.apk" if os.path.exists("uns-aligned-debugSigned.apk") else "uns.apk"
        if os.path.exists(final_file):
            shutil.move(final_file, out)
            print(f"\n{C_GREEN}╔{'═' * (w-2)}╗")
            print_center(f"{C_GRAY}PATCH SUCCESSFUL")
            print_center(f"{C_YELLOW}{out}")
            print(f"{C_GREEN}╚{'═' * (w-2)}╝{C_RESET}")
        else:
            print(f"\n{ICON_ERR} {C_RED}FAILED TO GENERATE APK!{C_RESET}")
        input(f"\n{C_GRAY}Press Enter to continue...{C_RESET}")

def main():
    engine = GodEngineV100()
    while True:
        clear()
        banner()
        w = get_terminal_width()

        print(f"{C_CYAN}╔{'═' * (w-2)}╗{C_RESET}")
        for i, menu in enumerate(engine.menus):
            str_menu = f"{C_GRAY}[{C_GREEN}{i+1:02}{C_GRAY}]{C_GREEN} {menu}"
            label_clean = f"[{i+1:02}] {menu}"
            padding = w - 4 - len(label_clean)
            print(f"{C_CYAN}║ {str_menu}{' ' * padding} {C_CYAN}║{C_RESET}")
        print(f"{C_CYAN}╚{'═' * (w-2)}╝{C_RESET}")

        print(f"\n{C_GRAY}  Target   : {C_GRAY}Android API 21+{C_RESET}")
        print(f"{C_GRAY}  Engine   : {C_GRAY}V100.5 (Ultimatum){C_RESET}")

        print(f"\n{C_GRAY}┌──({C_GRAY}HADI@V100{C_GRAY})-[{C_GRAY}~/menu{C_GRAY}]")
  
        try:
            choice = input(f"{C_GRAY}└─{C_RESET}$ ").strip()
            if choice.lower() in [str(len(engine.menus)), "exit", "keluar"]: break
            if choice.isdigit(): engine.start_patch(choice)
        except KeyboardInterrupt: break

if __name__ == "__main__":
    main()