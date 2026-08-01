import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def load_config(config_path: Path) -> Dict:
    """Load and validate the analysis configuration."""
    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as file:
        config = json.load(file)

    required_keys = [
        "apktool_path",
        "apk_path",
        "output_dir",
    ]

    for key in required_keys:
        if key not in config:
            raise ValueError(
                f"Missing required config key: {key}"
            )

    return config


def validate_paths(config: Dict) -> Tuple[Path, Path, Path]:
    """Validate input paths and prepare the output directory."""
    apktool_path = Path(
        config["apktool_path"]
    ).expanduser().resolve()

    apk_path = Path(
        config["apk_path"]
    ).expanduser().resolve()

    output_dir = Path(
        config["output_dir"]
    ).expanduser().resolve()

    if not apktool_path.exists():
        raise FileNotFoundError(
            f"Apktool was not found: {apktool_path}"
        )

    if not apk_path.exists():
        raise FileNotFoundError(
            f"APK file was not found: {apk_path}"
        )

    if not apk_path.is_file():
        raise ValueError(
            f"APK path is not a file: {apk_path}"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    return apktool_path, apk_path, output_dir


def build_apktool_command(
    apktool_path: Path,
    apk_path: Path,
    output_path: Path
) -> List[str]:
    """
    Build the Apktool command.

    JAR files are executed through Java, while executable
    scripts such as apktool.bat are executed directly.
    """
    suffix = apktool_path.suffix.lower()

    if suffix == ".jar":
        return [
            "java",
            "-jar",
            str(apktool_path),
            "d",
            "-f",
            str(apk_path),
            "-o",
            str(output_path),
        ]

    return [
        str(apktool_path),
        "d",
        "-f",
        str(apk_path),
        "-o",
        str(output_path),
    ]


def run_apktool(
    apktool_path: Path,
    apk_path: Path,
    output_path: Path
) -> None:
    """Run Apktool and decompile the APK."""
    command = build_apktool_command(
        apktool_path,
        apk_path,
        output_path
    )

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
            raise RuntimeError(
                "Java was not found. Make sure Java is installed "
                "and available in PATH."
            ) from exc

        raise RuntimeError(
            f"Could not execute Apktool: {apktool_path}"
        ) from exc

    print(result.stdout)

    if result.returncode != 0:
        raise RuntimeError(
            f"Apktool failed with exit code {result.returncode}"
        )


def get_android_attribute(
    element: ET.Element,
    name: str
):
    """Get an Android XML attribute using the Android namespace."""
    return element.attrib.get(
        f"{{{ANDROID_NS}}}{name}"
    )


def normalize_component_name(
    package_name: str,
    component_name: str
) -> str:
    """Convert relative Android component names to fully qualified names."""
    if not component_name:
        return component_name

    if component_name.startswith("."):
        return f"{package_name}{component_name}"

    if "." not in component_name:
        return f"{package_name}.{component_name}"

    return component_name


def extract_component(
    element: ET.Element,
    package_name: str,
    include_intent_filters: bool = True
) -> Dict:
    """Extract common Android component attributes."""
    component_name = normalize_component_name(
        package_name,
        get_android_attribute(
            element,
            "name"
        ) or ""
    )

    component = {
        "name": component_name,
        "exported": get_android_attribute(
            element,
            "exported"
        ),
        "enabled": get_android_attribute(
            element,
            "enabled"
        ),
        "permission": get_android_attribute(
            element,
            "permission"
        ),
        "process": get_android_attribute(
            element,
            "process"
        ),
        "direct_boot_aware": get_android_attribute(
            element,
            "directBootAware"
        ),
    }

    if include_intent_filters:
        intent_filters = []

        for intent_filter in element.findall(
            "intent-filter"
        ):
            filter_data = {
                "priority": get_android_attribute(
                    intent_filter,
                    "priority"
                ),
                "actions": [],
                "categories": [],
                "data": [],
            }

            for action in intent_filter.findall("action"):
                name = get_android_attribute(
                    action,
                    "name"
                )

                if name:
                    filter_data["actions"].append(name)

            for category in intent_filter.findall("category"):
                name = get_android_attribute(
                    category,
                    "name"
                )

                if name:
                    filter_data["categories"].append(name)

            for data in intent_filter.findall("data"):
                filter_data["data"].append({
                    "scheme": get_android_attribute(
                        data,
                        "scheme"
                    ),
                    "host": get_android_attribute(
                        data,
                        "host"
                    ),
                    "port": get_android_attribute(
                        data,
                        "port"
                    ),
                    "path": get_android_attribute(
                        data,
                        "path"
                    ),
                    "path_prefix": get_android_attribute(
                        data,
                        "pathPrefix"
                    ),
                    "path_pattern": get_android_attribute(
                        data,
                        "pathPattern"
                    ),
                    "mime_type": get_android_attribute(
                        data,
                        "mimeType"
                    ),
                })

            intent_filters.append(filter_data)

        component["intent_filters"] = intent_filters

    return component


def parse_manifest(
    manifest_path: Path
) -> Dict:
    """
    Parse AndroidManifest.xml and extract security-relevant data.

    The original decoded manifest remains available as XML.
    This function creates a structured representation for
    subsequent automated and LLM-based security analysis.
    """
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Decoded AndroidManifest.xml was not found: "
            f"{manifest_path}"
        )

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

    except ET.ParseError as exc:
        raise RuntimeError(
            f"Failed to parse AndroidManifest.xml: {exc}"
        ) from exc

    package_name = root.attrib.get(
        "package",
        ""
    )

    manifest_info = {
        "package": package_name,
        "version_code": get_android_attribute(
            root,
            "versionCode"
        ),
        "version_name": get_android_attribute(
            root,
            "versionName"
        ),
        "shared_user_id": get_android_attribute(
            root,
            "sharedUserId"
        ),
        "permissions": [],
        "uses_permissions": [],
        "permission_groups": [],
        "custom_permissions": [],
        "uses_features": [],
        "uses_libraries": [],
        "sdk": {},
        "application": {},
        "activities": [],
        "activity_aliases": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "instrumentation": [],
        "queries": [],
    }

    # Extract permissions requested by the application.
    for permission in root.findall("uses-permission"):
        name = get_android_attribute(
            permission,
            "name"
        )

        if name:
            manifest_info["permissions"].append(name)

    # Extract SDK-specific permission declarations.
    for element in root:
        if element.tag.endswith(
            "uses-permission-sdk-23"
        ):
            name = get_android_attribute(
                element,
                "name"
            )

            if name:
                manifest_info["uses_permissions"].append(name)

        elif element.tag.endswith(
            "uses-permission-sdk-m"
        ):
            name = get_android_attribute(
                element,
                "name"
            )

            if name:
                manifest_info["uses_permissions"].append(name)

    # Extract custom permissions declared by the application.
    for permission in root.findall("permission"):
        manifest_info["custom_permissions"].append({
            "name": get_android_attribute(
                permission,
                "name"
            ),
            "label": get_android_attribute(
                permission,
                "label"
            ),
            "description": get_android_attribute(
                permission,
                "description"
            ),
            "permission_group": get_android_attribute(
                permission,
                "permissionGroup"
            ),
            "protection_level": get_android_attribute(
                permission,
                "protectionLevel"
            ),
        })

    # Extract custom permission groups.
    for group in root.findall("permission-group"):
        manifest_info["permission_groups"].append({
            "name": get_android_attribute(
                group,
                "name"
            ),
            "label": get_android_attribute(
                group,
                "label"
            ),
            "description": get_android_attribute(
                group,
                "description"
            ),
        })

    # Extract SDK compatibility information.
    uses_sdk = root.find("uses-sdk")

    if uses_sdk is not None:
        manifest_info["sdk"] = {
            "min_sdk": get_android_attribute(
                uses_sdk,
                "minSdkVersion"
            ),
            "target_sdk": get_android_attribute(
                uses_sdk,
                "targetSdkVersion"
            ),
            "max_sdk": get_android_attribute(
                uses_sdk,
                "maxSdkVersion"
            ),
        }

    # Extract requested hardware and software features.
    for feature in root.findall("uses-feature"):
        manifest_info["uses_features"].append({
            "name": get_android_attribute(
                feature,
                "name"
            ),
            "required": get_android_attribute(
                feature,
                "required"
            ),
            "gl_es_version": get_android_attribute(
                feature,
                "glEsVersion"
            ),
        })

    # Extract external libraries.
    for library in root.findall("uses-library"):
        manifest_info["uses_libraries"].append({
            "name": get_android_attribute(
                library,
                "name"
            ),
            "required": get_android_attribute(
                library,
                "required"
            ),
        })

    application = root.find("application")

    if application is not None:
        manifest_info["application"] = {
            "name": normalize_component_name(
                package_name,
                get_android_attribute(
                    application,
                    "name"
                ) or ""
            ),
            "label": get_android_attribute(
                application,
                "label"
            ),
            "icon": get_android_attribute(
                application,
                "icon"
            ),
            "theme": get_android_attribute(
                application,
                "theme"
            ),
            "allow_backup": get_android_attribute(
                application,
                "allowBackup"
            ),
            "full_backup_content": get_android_attribute(
                application,
                "fullBackupContent"
            ),
            "data_extraction_rules": get_android_attribute(
                application,
                "dataExtractionRules"
            ),
            "debuggable": get_android_attribute(
                application,
                "debuggable"
            ),
            "test_only": get_android_attribute(
                application,
                "testOnly"
            ),
            "uses_cleartext_traffic": get_android_attribute(
                application,
                "usesCleartextTraffic"
            ),
            "network_security_config": get_android_attribute(
                application,
                "networkSecurityConfig"
            ),
            "process": get_android_attribute(
                application,
                "process"
            ),
            "task_affinity": get_android_attribute(
                application,
                "taskAffinity"
            ),
        }

        # Extract activities and their intent filters.
        for activity in application.findall("activity"):
            manifest_info["activities"].append(
                extract_component(
                    activity,
                    package_name,
                    True
                )
            )

        # Extract activity aliases and their target activities.
        for alias in application.findall(
            "activity-alias"
        ):
            alias_data = extract_component(
                alias,
                package_name,
                True
            )

            alias_data["target_activity"] = (
                normalize_component_name(
                    package_name,
                    get_android_attribute(
                        alias,
                        "targetActivity"
                    ) or ""
                )
            )

            manifest_info[
                "activity_aliases"
            ].append(alias_data)

        # Extract services and their intent filters.
        for service in application.findall("service"):
            manifest_info["services"].append(
                extract_component(
                    service,
                    package_name,
                    True
                )
            )

        # Extract broadcast receivers.
        for receiver in application.findall("receiver"):
            manifest_info["receivers"].append(
                extract_component(
                    receiver,
                    package_name,
                    True
                )
            )

        # Extract content providers and access control attributes.
        for provider in application.findall("provider"):
            provider_data = extract_component(
                provider,
                package_name,
                False
            )

            provider_data.update({
                "authorities": get_android_attribute(
                    provider,
                    "authorities"
                ),
                "read_permission": get_android_attribute(
                    provider,
                    "readPermission"
                ),
                "write_permission": get_android_attribute(
                    provider,
                    "writePermission"
                ),
                "grant_uri_permissions": get_android_attribute(
                    provider,
                    "grantUriPermissions"
                ),
                "multiprocess": get_android_attribute(
                    provider,
                    "multiprocess"
                ),
                "syncable": get_android_attribute(
                    provider,
                    "syncable"
                ),
                "init_order": get_android_attribute(
                    provider,
                    "initOrder"
                ),
            })

            manifest_info[
                "providers"
            ].append(provider_data)

        # Extract instrumentation declarations.
        for instrumentation in application.findall(
            "instrumentation"
        ):
            manifest_info[
                "instrumentation"
            ].append({
                "name": normalize_component_name(
                    package_name,
                    get_android_attribute(
                        instrumentation,
                        "name"
                    ) or ""
                ),
                "target_package": get_android_attribute(
                    instrumentation,
                    "targetPackage"
                ),
                "target_process": get_android_attribute(
                    instrumentation,
                    "targetProcesses"
                ),
                "functional_test": get_android_attribute(
                    instrumentation,
                    "functionalTest"
                ),
                "handle_profiling": get_android_attribute(
                    instrumentation,
                    "handleProfiling"
                ),
            })

    # Extract package visibility declarations.
    queries = root.find("queries")

    if queries is not None:
        for package in queries.findall("package"):
            manifest_info["queries"].append({
                "type": "package",
                "name": get_android_attribute(
                    package,
                    "name"
                ),
            })

        for intent in queries.findall("intent"):
            manifest_info["queries"].append({
                "type": "intent",
                "actions": [
                    get_android_attribute(
                        action,
                        "name"
                    )
                    for action in intent.findall("action")
                    if get_android_attribute(
                        action,
                        "name"
                    )
                ],
            })

    return manifest_info


def save_json(
    data: Dict,
    output_path: Path
) -> None:
    """Save structured analysis data as formatted JSON."""
    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )


def find_smali_directories(
    decompiled_dir: Path
) -> List[Path]:
    """Find all Smali directories generated by Apktool."""
    return sorted(
        [
            path
            for path in decompiled_dir.iterdir()
            if path.is_dir()
            and path.name.startswith("smali")
        ],
        key=lambda path: path.name
    )


def create_analysis_metadata(
    apk_path: Path,
    decompiled_dir: Path,
    manifest_info: Dict,
    metadata_path: Path
) -> None:
    """Create metadata describing the generated analysis output."""
    smali_directories = find_smali_directories(
        decompiled_dir
    )

    metadata = {
        "apk": {
            "path": str(apk_path),
            "filename": apk_path.name,
            "size_bytes": apk_path.stat().st_size,
        },
        "decompiled_directory": str(
            decompiled_dir
        ),
        "smali_directories": [
            str(path)
            for path in smali_directories
        ],
        "smali_directory_count": len(
            smali_directories
        ),
        "manifest": {
            "package": manifest_info.get(
                "package"
            ),
            "activity_count": len(
                manifest_info.get(
                    "activities",
                    []
                )
            ),
            "service_count": len(
                manifest_info.get(
                    "services",
                    []
                )
            ),
            "receiver_count": len(
                manifest_info.get(
                    "receivers",
                    []
                )
            ),
            "provider_count": len(
                manifest_info.get(
                    "providers",
                    []
                )
            ),
            "permission_count": len(
                manifest_info.get(
                    "permissions",
                    []
                )
            ),
        },
    }

    save_json(
        metadata,
        metadata_path
    )


def main() -> int:
    """Execute the complete APK analysis workflow."""
    config_path = (
        Path(__file__).resolve().parent
        / "config.json"
    )

    try:
        print("[*] Loading configuration...")

        config = load_config(
            config_path
        )

        (
            apktool_path,
            apk_path,
            output_dir
        ) = validate_paths(config)

        decompiled_dir = (
            output_dir / "decoded"
        )

        # Remove previous output to guarantee a clean analysis.
        if decompiled_dir.exists():
            print(
                f"[*] Removing previous output: "
                f"{decompiled_dir}"
            )
            shutil.rmtree(
                decompiled_dir
            )

        print(f"[*] APK: {apk_path}")
        print(
            f"[*] Output: "
            f"{decompiled_dir}"
        )

        # Apktool performs resource decoding and DEX-to-Smali conversion.
        run_apktool(
            apktool_path,
            apk_path,
            decompiled_dir
        )

        manifest_path = (
            decompiled_dir
            / "AndroidManifest.xml"
        )

        if not manifest_path.exists():
            raise RuntimeError(
                "Apktool completed, but AndroidManifest.xml "
                "was not generated."
            )

        print(
            "[+] Apktool decompilation completed."
        )

        print(
            "[+] Extracting manifest information..."
        )

        manifest_info = parse_manifest(
            manifest_path
        )

        manifest_json_path = (
            output_dir
            / "manifest_info.json"
        )

        save_json(
            manifest_info,
            manifest_json_path
        )

        # Keep the decoded manifest at a stable analysis path.
        manifest_copy_path = (
            output_dir
            / "AndroidManifest.xml"
        )

        shutil.copy2(
            manifest_path,
            manifest_copy_path
        )

        smali_directories = find_smali_directories(
            decompiled_dir
        )

        if not smali_directories:
            print(
                "[!] Warning: No Smali directory was generated."
            )
        else:
            print("[+] Smali directories:")

            for smali_dir in smali_directories:
                print(
                    f"    - {smali_dir}"
                )

        metadata_path = (
            output_dir
            / "analysis_metadata.json"
        )

        create_analysis_metadata(
            apk_path,
            decompiled_dir,
            manifest_info,
            metadata_path
        )

        print()
        print(
            "[+] Analysis completed successfully."
        )
        print(
            f"[+] Decoded APK:       {decompiled_dir}"
        )
        print(
            f"[+] Manifest XML:      {manifest_copy_path}"
        )
        print(
            f"[+] Manifest JSON:     {manifest_json_path}"
        )
        print(
            f"[+] Analysis metadata: {metadata_path}"
        )

        return 0

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError
    ) as exc:
        print(
            f"[ERROR] {exc}",
            file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())