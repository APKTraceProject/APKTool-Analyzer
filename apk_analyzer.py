import json
import re
import shutil
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ANDROID_NS = "http://schemas.android.com/apk/res/android"

SUSPICIOUS_APIS = {
    "reflection": [
        "Ljava/lang/Class;->forName",
        "Ljava/lang/reflect/Method;->invoke",
        "Ljava/lang/reflect/Constructor;->newInstance",
        "Ljava/lang/reflect/Field;->get",
        "Ljava/lang/reflect/Field;->set",
        "Ljava/lang/ClassLoader;->loadClass",
    ],
    "dynamic_code_loading": [
        "Ldalvik/system/DexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>",
        "Ldalvik/system/InMemoryDexClassLoader;-><init>",
        "Ldalvik/system/DexFile;->loadDex",
    ],
    "native_code": [
        "Ljava/lang/System;->loadLibrary",
        "Ljava/lang/System;->load",
        "Ljava/lang/Runtime;->loadLibrary",
        "Ljava/lang/Runtime;->load",
    ],
    "process_execution": [
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/ProcessBuilder;-><init>",
    ],
    "webview": [
        "Landroid/webkit/WebView;->addJavascriptInterface",
        "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
        "Landroid/webkit/WebView;->loadUrl",
        "Landroid/webkit/WebView;->loadDataWithBaseURL",
    ],
    "crypto": [
        "Ljavax/crypto/Cipher;->getInstance",
        "Ljava/security/MessageDigest;->getInstance",
        "Ljavax/crypto/Mac;->getInstance",
    ],
    "network": [
        "Ljava/net/URL;-><init>",
        "Ljava/net/HttpURLConnection;->connect",
        "Lokhttp3/Call;->execute",
        "Lokhttp3/Call;->enqueue",
        "Landroid/net/Uri;->parse",
    ],
    "telephony": [
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/telephony/TelephonyManager;->getImei",
        "Landroid/telephony/TelephonyManager;->getSubscriberId",
        "Landroid/telephony/SmsManager;->sendTextMessage",
    ],
    "settings": [
        "Landroid/provider/Settings$Secure;->getString",
        "Landroid/provider/Settings$Global;->getString",
    ],
    "package_management": [
        "Landroid/content/pm/PackageManager;->getInstalledPackages",
        "Landroid/content/pm/PackageManager;->getPackageInfo",
        "Landroid/content/Intent;->setComponent",
    ],
}

SMALI_CLASS_RE = re.compile(r"^\.class\b.*?\s(L[^;]+;)\s*$")
SMALI_SUPER_RE = re.compile(r"^\.super\s+(L[^;]+;)\s*$")
SMALI_SOURCE_RE = re.compile(r'^\.source\s+"(.*)"\s*$')
SMALI_METHOD_RE = re.compile(r"^\.method\b(.*?)\s+([^\s(]+)\(([^)]*)\)(\S+)\s*$")
SMALI_END_METHOD_RE = re.compile(r"^\.end\s+method\b")
SMALI_NATIVE_METHOD_RE = re.compile(r"^\.method\b.*\bnative\b")
SMALI_STRING_RE = re.compile(r'const-string(?:/jumbo)?\s+\S+,\s+"(.*)"')
SMALI_INVOKE_RE = re.compile(r"(L[^;]+;->[^(]+\([^)]*\)\S+)")
SMALI_FIELD_RE = re.compile(r"(L[^;]+;->[^:\s]+:[^\s]+)")
SMALI_TYPE_RE = re.compile(r"\bL[a-zA-Z0-9_/$-]+;")
OBFUSCATED_SEGMENT_RE = re.compile(r"^[a-zA-Z]{1,2}$")


def load_config(config_path: Path) -> Dict[str, Any]:
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as file:
        config = json.load(file)

    required_keys = ["apktool_path", "apk_path", "output_dir"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

    return config


def validate_paths(config: Dict[str, Any]) -> Tuple[Path, Path, Path]:
    apktool_path = Path(config["apktool_path"]).expanduser().resolve()
    apk_path = Path(config["apk_path"]).expanduser().resolve()
    output_dir = Path(config["output_dir"]).expanduser().resolve()

    if not apktool_path.exists():
        raise FileNotFoundError(f"Apktool was not found: {apktool_path}")
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file was not found: {apk_path}")
    if not apk_path.is_file():
        raise ValueError(f"APK path is not a file: {apk_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    return apktool_path, apk_path, output_dir


def build_apktool_command(apktool_path: Path, apk_path: Path, output_path: Path) -> List[str]:
    if apktool_path.suffix.lower() == ".jar":
        return ["java", "-jar", str(apktool_path), "d", "-f", str(apk_path), "-o", str(output_path)]
    return [str(apktool_path), "d", "-f", str(apk_path), "-o", str(output_path)]


def run_apktool(apktool_path: Path, apk_path: Path, output_path: Path) -> None:
    command = build_apktool_command(apktool_path, apk_path, output_path)
    print("[+] Running Apktool...")
    print("[+] Command:", " ".join(command))

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        if apktool_path.suffix.lower() == ".jar":
            raise RuntimeError("Java was not found. Make sure Java is installed and available in PATH.") from exc
        raise RuntimeError(f"Could not execute Apktool: {apktool_path}") from exc

    print(result.stdout)
    if result.returncode != 0:
        raise RuntimeError(f"Apktool failed with exit code {result.returncode}")


def get_android_attribute(element: ET.Element, name: str) -> Optional[str]:
    return element.attrib.get(f"{{{ANDROID_NS}}}{name}")


def parse_bool(value: Optional[str], default: Optional[bool] = None) -> Optional[bool]:
    if value is None:
        return default
    value = value.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return default


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def normalize_component_name(package_name: str, component_name: str) -> str:
    if not component_name:
        return ""
    if component_name.startswith("."):
        return f"{package_name}{component_name}"
    if "." not in component_name:
        return f"{package_name}.{component_name}"
    return component_name


def infer_exported(element: ET.Element) -> Optional[bool]:
    explicit = parse_bool(get_android_attribute(element, "exported"))
    if explicit is not None:
        return explicit
    return len(element.findall("intent-filter")) > 0


def extract_intent_filters(element: ET.Element) -> List[Dict[str, Any]]:
    result = []
    for intent_filter in element.findall("intent-filter"):
        data_items = []
        for data in intent_filter.findall("data"):
            data_items.append({
                "scheme": get_android_attribute(data, "scheme"),
                "host": get_android_attribute(data, "host"),
                "port": get_android_attribute(data, "port"),
                "path": get_android_attribute(data, "path"),
                "path_prefix": get_android_attribute(data, "pathPrefix"),
                "path_pattern": get_android_attribute(data, "pathPattern"),
                "path_advanced_pattern": get_android_attribute(data, "pathAdvancedPattern"),
                "mime_type": get_android_attribute(data, "mimeType"),
            })

        result.append({
            "priority": parse_int(get_android_attribute(intent_filter, "priority")),
            "auto_verify": parse_bool(get_android_attribute(intent_filter, "autoVerify")),
            "actions": [
                get_android_attribute(item, "name")
                for item in intent_filter.findall("action")
                if get_android_attribute(item, "name")
            ],
            "categories": [
                get_android_attribute(item, "name")
                for item in intent_filter.findall("category")
                if get_android_attribute(item, "name")
            ],
            "data": data_items,
        })
    return result


def extract_component(element: ET.Element, package_name: str, component_type: str) -> Dict[str, Any]:
    name = normalize_component_name(package_name, get_android_attribute(element, "name") or "")
    component = {
        "name": name,
        "type": component_type,
        "exported": infer_exported(element),
        "exported_explicitly_declared": get_android_attribute(element, "exported") is not None,
        "enabled": parse_bool(get_android_attribute(element, "enabled"), True),
        "permission": get_android_attribute(element, "permission"),
        "process": get_android_attribute(element, "process"),
        "direct_boot_aware": parse_bool(get_android_attribute(element, "directBootAware")),
        "intent_filters": extract_intent_filters(element),
    }

    if component_type == "provider":
        component.update({
            "authorities": get_android_attribute(element, "authorities"),
            "read_permission": get_android_attribute(element, "readPermission"),
            "write_permission": get_android_attribute(element, "writePermission"),
            "grant_uri_permissions": parse_bool(get_android_attribute(element, "grantUriPermissions")),
            "multiprocess": parse_bool(get_android_attribute(element, "multiprocess")),
            "syncable": parse_bool(get_android_attribute(element, "syncable")),
            "init_order": parse_int(get_android_attribute(element, "initOrder")),
        })

    return component


def parse_manifest(manifest_path: Path) -> Dict[str, Any]:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Decoded AndroidManifest.xml was not found: {manifest_path}")

    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError as exc:
        raise RuntimeError(f"Failed to parse AndroidManifest.xml: {exc}") from exc

    package_name = root.attrib.get("package", "")
    application = root.find("application")
    uses_sdk = root.find("uses-sdk")

    permissions = []
    for child in root:
        if child.tag.split("}")[-1].startswith("uses-permission"):
            name = get_android_attribute(child, "name")
            if name:
                permissions.append({
                    "name": name,
                    "max_sdk_version": parse_int(get_android_attribute(child, "maxSdkVersion")),
                    "declaration": child.tag.split("}")[-1],
                })

    custom_permissions = []
    for item in root.findall("permission"):
        custom_permissions.append({
            "name": get_android_attribute(item, "name"),
            "label": get_android_attribute(item, "label"),
            "description": get_android_attribute(item, "description"),
            "permission_group": get_android_attribute(item, "permissionGroup"),
            "protection_level": get_android_attribute(item, "protectionLevel"),
        })

    components = {
        "activities": [],
        "activity_aliases": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    app_data: Dict[str, Any] = {}
    if application is not None:
        app_data = {
            "name": normalize_component_name(package_name, get_android_attribute(application, "name") or ""),
            "label": get_android_attribute(application, "label"),
            "icon": get_android_attribute(application, "icon"),
            "theme": get_android_attribute(application, "theme"),
            "allow_backup": parse_bool(get_android_attribute(application, "allowBackup"), True),
            "full_backup_content": get_android_attribute(application, "fullBackupContent"),
            "data_extraction_rules": get_android_attribute(application, "dataExtractionRules"),
            "debuggable": parse_bool(get_android_attribute(application, "debuggable"), False),
            "test_only": parse_bool(get_android_attribute(application, "testOnly"), False),
            "uses_cleartext_traffic": parse_bool(get_android_attribute(application, "usesCleartextTraffic")),
            "network_security_config": get_android_attribute(application, "networkSecurityConfig"),
            "process": get_android_attribute(application, "process"),
            "task_affinity": get_android_attribute(application, "taskAffinity"),
            "extract_native_libs": parse_bool(get_android_attribute(application, "extractNativeLibs")),
        }

        for tag, key, kind in [
            ("activity", "activities", "activity"),
            ("service", "services", "service"),
            ("receiver", "receivers", "receiver"),
            ("provider", "providers", "provider"),
        ]:
            for element in application.findall(tag):
                components[key].append(extract_component(element, package_name, kind))

        for element in application.findall("activity-alias"):
            item = extract_component(element, package_name, "activity_alias")
            item["target_activity"] = normalize_component_name(
                package_name, get_android_attribute(element, "targetActivity") or ""
            )
            components["activity_aliases"].append(item)

    features = []
    for item in root.findall("uses-feature"):
        features.append({
            "name": get_android_attribute(item, "name"),
            "required": parse_bool(get_android_attribute(item, "required"), True),
            "gl_es_version": get_android_attribute(item, "glEsVersion"),
        })

    queries = []
    queries_node = root.find("queries")
    if queries_node is not None:
        for item in queries_node.findall("package"):
            queries.append({"type": "package", "name": get_android_attribute(item, "name")})
        for item in queries_node.findall("provider"):
            queries.append({"type": "provider", "authorities": get_android_attribute(item, "authorities")})
        for item in queries_node.findall("intent"):
            queries.append({
                "type": "intent",
                "actions": [
                    get_android_attribute(x, "name")
                    for x in item.findall("action")
                    if get_android_attribute(x, "name")
                ],
                "categories": [
                    get_android_attribute(x, "name")
                    for x in item.findall("category")
                    if get_android_attribute(x, "name")
                ],
            })

    exported = []
    for group in components.values():
        for component in group:
            if component.get("exported"):
                exported.append({
                    "name": component["name"],
                    "type": component["type"],
                    "permission": component.get("permission"),
                    "has_intent_filters": bool(component.get("intent_filters")),
                })

    return {
        "package_name": package_name,
        "version_name": get_android_attribute(root, "versionName"),
        "version_code": get_android_attribute(root, "versionCode"),
        "shared_user_id": get_android_attribute(root, "sharedUserId"),
        "sdk": {
            "min_sdk": parse_int(get_android_attribute(uses_sdk, "minSdkVersion")) if uses_sdk is not None else None,
            "target_sdk": parse_int(get_android_attribute(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None,
            "max_sdk": parse_int(get_android_attribute(uses_sdk, "maxSdkVersion")) if uses_sdk is not None else None,
        },
        "application": app_data,
        "permissions": permissions,
        "custom_permissions": custom_permissions,
        "uses_features": features,
        "components": components,
        "exported_components": exported,
        "queries": queries,
        "security_flags": {
            "debuggable": app_data.get("debuggable", False),
            "allow_backup": app_data.get("allow_backup", True),
            "uses_cleartext_traffic": app_data.get("uses_cleartext_traffic"),
            "network_security_config": app_data.get("network_security_config"),
            "test_only": app_data.get("test_only", False),
            "extract_native_libs": app_data.get("extract_native_libs"),
        },
    }


def find_smali_directories(decompiled_dir: Path) -> List[Path]:
    return sorted(
        [path for path in decompiled_dir.iterdir() if path.is_dir() and path.name.startswith("smali")],
        key=lambda path: (path.name != "smali", path.name),
    )


def descriptor_to_class_name(descriptor: Optional[str]) -> Optional[str]:
    if not descriptor:
        return None
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") and descriptor.endswith(";") else descriptor


def is_probably_obfuscated(class_descriptor: Optional[str]) -> bool:
    if not class_descriptor:
        return False
    parts = class_descriptor.strip("L;").split("/")
    if len(parts) < 2:
        return False
    short = sum(1 for part in parts if OBFUSCATED_SEGMENT_RE.fullmatch(part))
    return short >= max(2, len(parts) - 1)


def scan_smali_file(path: Path, root_dir: Path, max_strings_per_file: int = 100) -> Dict[str, Any]:
    result = {
        "relative_path": str(path.relative_to(root_dir)).replace("\\", "/"),
        "class_descriptor": None,
        "super_descriptor": None,
        "source_file": None,
        "method_count": 0,
        "native_method_count": 0,
        "instruction_count": 0,
        "string_literals": [],
        "api_hits": [],
        "invoked_methods": [],
        "referenced_fields": [],
    }

    in_method = False
    seen_hits = set()
    seen_invokes = set()
    seen_fields = set()

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if result["class_descriptor"] is None:
                match = SMALI_CLASS_RE.match(line)
                if match:
                    result["class_descriptor"] = match.group(1)
                    continue

            if result["super_descriptor"] is None:
                match = SMALI_SUPER_RE.match(line)
                if match:
                    result["super_descriptor"] = match.group(1)
                    continue

            if result["source_file"] is None:
                match = SMALI_SOURCE_RE.match(line)
                if match:
                    result["source_file"] = match.group(1)
                    continue

            if SMALI_METHOD_RE.match(line):
                result["method_count"] += 1
                in_method = True
                if SMALI_NATIVE_METHOD_RE.match(line):
                    result["native_method_count"] += 1
                continue

            if SMALI_END_METHOD_RE.match(line):
                in_method = False
                continue

            if in_method and not line.startswith(".") and not line.startswith(":"):
                result["instruction_count"] += 1

            match = SMALI_STRING_RE.search(line)
            if match and len(result["string_literals"]) < max_strings_per_file:
                result["string_literals"].append(match.group(1))

            for category, patterns in SUSPICIOUS_APIS.items():
                for pattern in patterns:
                    if pattern in line:
                        key = (category, pattern)
                        if key not in seen_hits:
                            seen_hits.add(key)
                            result["api_hits"].append({"category": category, "api": pattern})

            match = SMALI_INVOKE_RE.search(line)
            if match:
                value = match.group(1)
                if value not in seen_invokes and len(result["invoked_methods"]) < 300:
                    seen_invokes.add(value)
                    result["invoked_methods"].append(value)

            match = SMALI_FIELD_RE.search(line)
            if match:
                value = match.group(1)
                if value not in seen_fields and len(result["referenced_fields"]) < 200:
                    seen_fields.add(value)
                    result["referenced_fields"].append(value)

    return result


def analyze_smali(decompiled_dir: Path) -> Dict[str, Any]:
    smali_dirs = find_smali_directories(decompiled_dir)
    category_counter = Counter()
    api_counter = Counter()
    files_with_hits = []
    sample_strings = []
    class_samples = []
    total_files = 0
    total_methods = 0
    total_native_methods = 0
    total_instructions = 0
    obfuscated_classes = 0

    for smali_dir in smali_dirs:
        for path in smali_dir.rglob("*.smali"):
            total_files += 1
            item = scan_smali_file(path, decompiled_dir)
            total_methods += item["method_count"]
            total_native_methods += item["native_method_count"]
            total_instructions += item["instruction_count"]

            if is_probably_obfuscated(item["class_descriptor"]):
                obfuscated_classes += 1

            if len(class_samples) < 100:
                class_samples.append({
                    "name": descriptor_to_class_name(item["class_descriptor"]),
                    "super_class": descriptor_to_class_name(item["super_descriptor"]),
                    "source_file": item["source_file"],
                    "relative_path": item["relative_path"],
                })

            for text in item["string_literals"]:
                if len(sample_strings) < 300 and text not in sample_strings:
                    sample_strings.append(text)

            if item["api_hits"]:
                files_with_hits.append({
                    "file": item["relative_path"],
                    "class_name": descriptor_to_class_name(item["class_descriptor"]),
                    "hits": item["api_hits"],
                })
                for hit in item["api_hits"]:
                    category_counter[hit["category"]] += 1
                    api_counter[hit["api"]] += 1

    findings = {
        category: {
            "count": category_counter.get(category, 0),
            "detected": category_counter.get(category, 0) > 0,
        }
        for category in SUSPICIOUS_APIS
    }

    return {
        "summary": {
            "smali_directories": [path.name for path in smali_dirs],
            "smali_directory_count": len(smali_dirs),
            "smali_file_count": total_files,
            "class_count": total_files,
            "method_count": total_methods,
            "native_method_count": total_native_methods,
            "estimated_instruction_count": total_instructions,
            "obfuscated_class_count": obfuscated_classes,
            "obfuscation_ratio": round(obfuscated_classes / total_files, 4) if total_files else 0.0,
        },
        "findings": findings,
        "api_usage": {
            "by_api": dict(api_counter.most_common()),
            "files_with_hits": files_with_hits,
        },
        "class_samples": class_samples,
        "string_samples": sample_strings,
    }


def analyze_apk_structure(apk_path: Path, decompiled_dir: Path) -> Dict[str, Any]:
    with zipfile.ZipFile(apk_path, "r") as archive:
        names = archive.namelist()
        dex_files = sorted(name for name in names if re.fullmatch(r"classes\d*\.dex", Path(name).name))
        native_libraries = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
        assets = sorted(name for name in names if name.startswith("assets/") and not name.endswith("/"))
        certificates = sorted(name for name in names if name.upper().startswith("META-INF/"))

    resource_files = 0
    resource_dir = decompiled_dir / "res"
    if resource_dir.exists():
        resource_files = sum(1 for path in resource_dir.rglob("*") if path.is_file())

    return {
        "apk_file_name": apk_path.name,
        "apk_size_bytes": apk_path.stat().st_size,
        "dex_files": dex_files,
        "dex_count": len(dex_files),
        "native_libraries": native_libraries,
        "native_library_count": len(native_libraries),
        "assets": assets,
        "asset_count": len(assets),
        "certificate_entries": certificates,
        "resource_file_count": resource_files,
        "decoded_directory": str(decompiled_dir),
    }


def build_analysis_report(
    apk_path: Path,
    decompiled_dir: Path,
    manifest: Dict[str, Any],
    smali: Dict[str, Any],
    structure: Dict[str, Any],
) -> Dict[str, Any]:
    component_counts = {
        key: len(value)
        for key, value in manifest["components"].items()
    }

    return {
        "schema_version": "2.0",
        "analyzer": {
            "name": "APKTrace Apktool Analyzer",
            "engine": "apktool",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "apk": structure,
        "manifest": manifest,
        "component_summary": component_counts,
        "smali": smali,
    }


def save_json(data: Dict[str, Any], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def main() -> int:
    config_path = Path(__file__).resolve().parent / "config.json"

    try:
        print("[*] Loading configuration...")
        config = load_config(config_path)
        apktool_path, apk_path, output_dir = validate_paths(config)

        decompiled_dir = output_dir / "decoded"
        if decompiled_dir.exists():
            print(f"[*] Removing previous output: {decompiled_dir}")
            shutil.rmtree(decompiled_dir)

        print(f"[*] APK: {apk_path}")
        print(f"[*] Output: {decompiled_dir}")
        run_apktool(apktool_path, apk_path, decompiled_dir)

        manifest_path = decompiled_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            raise RuntimeError("Apktool completed, but AndroidManifest.xml was not generated.")

        print("[+] Parsing AndroidManifest.xml...")
        manifest = parse_manifest(manifest_path)

        print("[+] Analyzing APK structure...")
        structure = analyze_apk_structure(apk_path, decompiled_dir)

        print("[+] Analyzing Smali code...")
        smali = analyze_smali(decompiled_dir)

        report = build_analysis_report(
            apk_path=apk_path,
            decompiled_dir=decompiled_dir,
            manifest=manifest,
            smali=smali,
            structure=structure,
        )

        report_path = output_dir / "apktool_analysis.json"
        save_json(report, report_path)

        manifest_copy_path = output_dir / "AndroidManifest.xml"
        shutil.copy2(manifest_path, manifest_copy_path)

        print()
        print("[+] Analysis completed successfully.")
        print(f"[+] Decoded APK: {decompiled_dir}")
        print(f"[+] Manifest XML: {manifest_copy_path}")
        print(f"[+] Final JSON report: {report_path}")
        print(f"[+] Smali files: {smali['summary']['smali_file_count']}")
        print(f"[+] Smali methods: {smali['summary']['method_count']}")

        return 0

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
