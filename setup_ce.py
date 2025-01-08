#!/usr/bin/env python3
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import requests
import typer
import yaml

try:
    import colorama
except ImportError:
    colorama = None

app = typer.Typer(help="Manage MLRun CE installation & Telepresence intercept.")

REPO_URL = "git@github.com:mlrun/ce.git"

COMPONENT_IPS = {
    "192.168.56.200": ["mlrun.k8s.internal"],
    "192.168.56.201": ["mlrun-api.k8s.internal"],
    "192.168.56.202": ["mlrun-api-chief.k8s.internal"],
    "192.168.56.203": ["nuclio.k8s.internal", "nuclio-dashboard.k8s.internal"],
    "192.168.56.204": ["jupyter.k8s.internal"],
    "192.168.56.205": ["minio.k8s.internal"],
    "192.168.56.206": ["grafana.k8s.internal"],
    "192.168.56.207": ["kfp.k8s.internal"],
    "192.168.56.208": ["metadata-envoy.k8s.internal"],
    "192.168.56.209": ["workflow-metrics.k8s.internal"],
    "192.168.56.210": ["workflow-controller.k8s.internal"],
}

HELM_REPOS = {
    "mlrun": "https://mlrun.github.io/ce",
    "nuclio": "https://nuclio.github.io/nuclio/charts",
    "v3io-stable": "https://v3io.github.io/helm-charts/stable",
    "minio": "https://charts.min.io/",
    "spark-operator": "https://kubeflow.github.io/spark-operator",
    "prometheus-community": "https://prometheus-community.github.io/helm-charts",
}

METALLB_CONFIG_YAML = """apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 192.168.56.200-192.168.56.250
"""

WINDOWS_SCHEDULED_TASK_NAME = "LoopbackAliases"
WINDOWS_LOOPBACK_SCRIPT = Path(r"C:\persist_loopbacks.bat")

REQUIRED_COMMANDS = ["git", "helm", "kubectl"]


def echo_color(text: str, color: Optional[str] = "auto", err: bool = False) -> None:
    """
    Print text with an optional color using Typer.
    If color='auto', it chooses red if err=True, else green.
    If color=None, it prints without color.

    :param text: The text to print.
    :param color: "auto", None, or a Typer color constant (e.g., typer.colors.BLUE).
    :param err: Whether to print to stderr instead of stdout.
    """
    if color == "auto":
        color = typer.colors.RED if err else typer.colors.GREEN

    if color is None:
        typer.echo(text, err=err)
    else:
        typer.echo(typer.style(text, fg=color), err=err)


def run_command(
    cmd: list[str],
    raise_on_error: bool = True,
    cwd: Optional[Path] = None,
    input_data: Optional[str] = None,
    debug: bool = False,
):
    if debug:
        echo_color(f"[DEBUG] Running: {' '.join(cmd)}", color=typer.colors.MAGENTA)
    try:
        subprocess.run(
            cmd,
            check=raise_on_error,
            cwd=str(cwd) if cwd else None,
            input=input_data,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
        )
    except subprocess.SubprocessError:
        echo_color(f"[ERROR] Command failed: {' '.join(cmd)}", err=True)
        raise


@app.callback()
def main(ctx: typer.Context):
    if colorama is not None:
        colorama.init()
    ctx.ensure_object(dict)


def is_process_running(process_name: str) -> bool:
    """Check if a process is running."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", process_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_command_exists(cmd: str) -> bool:
    if shutil.which(cmd) is None:
        echo_color(f"[WARNING] Command '{cmd}' not on PATH.", color=typer.colors.YELLOW)
        return False
    else:
        return True


def clear_namespaces(debug: bool):
    echo_color("Clearing Kubernetes namespaces.")
    run_command(
        ["kubectl", "delete", "namespace", "mlrun"], debug=debug, raise_on_error=False
    )
    run_command(
        ["kubectl", "delete", "namespace", "ambassador"],
        debug=debug,
        raise_on_error=False,
    )


def windows_loopback_script(ips: list[str]):
    lines = ["@echo off"]
    for ip in ips:
        lines.append(
            f'netsh interface ip add address "Loopback Pseudo-Interface 1" {ip} 255.255.255.0 1>nul 2>nul'
        )
    lines.append("exit /b 0")
    WINDOWS_LOOPBACK_SCRIPT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def windows_scheduled_task(debug: bool):
    run_command(
        ["schtasks", "/delete", "/f", "/tn", WINDOWS_SCHEDULED_TASK_NAME], debug=debug
    )
    run_command(
        [
            "schtasks",
            "/create",
            "/tn",
            WINDOWS_SCHEDULED_TASK_NAME,
            "/sc",
            "onstart",
            "/ru",
            "SYSTEM",
            "/rl",
            "HIGHEST",
            "/tr",
            str(WINDOWS_LOOPBACK_SCRIPT),
        ],
        debug=debug,
    )
    echo_color(f"Scheduled task '{WINDOWS_SCHEDULED_TASK_NAME}' created or updated.")


def create_virtual_interface(debug: bool):
    sys_str = platform.system().lower()
    ips = list(COMPONENT_IPS.keys())
    if sys_str == "windows":
        for ip in ips:
            run_command(
                [
                    "netsh",
                    "interface",
                    "ip",
                    "add",
                    "address",
                    "MLRun Loopback",
                    ip,
                    "255.255.255.0",
                ],
                debug=debug,
            )
    elif sys_str == "darwin":
        for ip in ips:
            res = subprocess.run(["ifconfig", "lo0"], capture_output=True, text=True)
            if ip not in res.stdout:
                run_command(["sudo", "-S", "ifconfig", "lo0", "alias", ip], debug=debug)
    elif sys_str == "linux":
        for ip in ips:
            res = subprocess.run(
                ["ip", "addr", "show", "lo"], capture_output=True, text=True
            )
            if ip not in res.stdout:
                run_command(
                    ["sudo", "-S", "ip", "address", "add", f"{ip}/32", "dev", "lo"],
                    debug=debug,
                )


def persist_loopbacks_on_windows(debug: bool):
    if platform.system().lower() == "windows":
        ips = list(COMPONENT_IPS.keys())
        windows_loopback_script(ips)
        windows_scheduled_task(debug)


def write_hosts(debug: bool):
    echo_color("Checking if hosts file update is needed.")
    sys_str = platform.system().lower()
    hosts_file = (
        Path(r"C:\Windows\System32\drivers\etc\hosts")
        if sys_str == "windows"
        else Path("/etc/hosts")
    )

    old_lines = []
    if hosts_file.is_file():
        try:
            old_lines = hosts_file.read_text(encoding="utf-8").splitlines(keepends=True)
        except Exception:
            pass

    new_lines = []
    for line in old_lines:
        if not any(h in line for ips in COMPONENT_IPS.values() for h in ips):
            new_lines.append(line)
    for ip, hosts in COMPONENT_IPS.items():
        for h in hosts:
            new_lines.append(f"{ip}\t{h}\n")

    old_str = "".join(old_lines)
    new_str = "".join(new_lines)

    if old_str == new_str:
        echo_color("No changes detected in hosts file. Skipping write.")
        return

    echo_color("Updating hosts file with new content.")
    if sys_str in ("linux", "darwin"):
        tmp_file = Path(tempfile.gettempdir()) / "hosts.tmp"
        tmp_file.write_text(new_str, encoding="utf-8")
        run_command(["sudo", "-S", "mv", str(tmp_file), str(hosts_file)], debug=debug)
    else:
        hosts_file.write_text(new_str, encoding="utf-8")


def install_telepresence_all_os(debug: bool):
    echo_color("Installing Telepresence binary.")

    if check_command_exists("telepresence"):
        echo_color("Telepresence is already installed. Skipping.")
        return

    sys_str = platform.system().lower()
    if sys_str == "darwin":
        if not check_command_exists("brew"):
            echo_color(
                "Homebrew not found, cannot install Telepresence automatically.",
                color=typer.colors.YELLOW,
            )
            return

        formula_url = "https://raw.githubusercontent.com/datawire/homebrew-blackbird/97e0a28d02adb42221ae4160c35a35f3a00f9eed/Formula/telepresence-arm64.rb"
        local_formula = "/tmp/telepresence-arm64.rb"

        # Download the formula using wget
        if not check_command_exists("wget"):
            echo_color("wget not found, cannot download the formula.", err=True)
            return

        run_command(["wget", "-O", local_formula, formula_url], debug=debug)

        # Install the formula using brew
        run_command(
            ["brew", "install", local_formula], debug=debug, raise_on_error=False
        )
    elif sys_str == "linux":
        tmp_path = Path(tempfile.gettempdir()) / "telepresence"
        run_command(
            [
                "curl",
                "-fL",
                "https://app.getambassador.io/download/tel2oss/releases/download/v2.14.4/telepresence-linux-amd64",
                "-o",
                str(tmp_path),
            ],
            debug=debug,
        )
        run_command(["chmod", "+x", str(tmp_path)], debug=debug)
        run_command(
            ["sudo", "-S", "mv", str(tmp_path), "/usr/local/bin/telepresence"],
            debug=debug,
        )
    elif sys_str == "windows":
        # If Telepresence is not installed, try installing via choco
        if not check_command_exists("choco"):
            run_command(
                [
                    "powershell.exe",
                    "Set-ExecutionPolicy",
                    "Bypass",
                    "-Scope",
                    "Process",
                    "-Force;",
                    "[System.Net.ServicePointManager]::SecurityProtocol="
                    "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072;",
                    "iex",
                    "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')",
                ],
                debug=debug,
            )
        if check_command_exists("choco"):
            run_command(
                ["choco", "install", "telepresence", "--version=2.14.4", "-y"],
                debug=debug,
            )
        else:
            echo_color(
                "Chocolatey not available; cannot install Telepresence.", err=True
            )


def setup_telepresence(intercept: bool, install: bool, debug: bool):
    if install:
        install_telepresence_all_os(debug)
    echo_color("Installing Telepresence in Helm.")

    run_command(
        ["sudo", "-S", "pkill", "-f", "telepresence"], debug=debug, raise_on_error=False
    )
    run_command(
        ["sudo", "-S", "telepresence", "quit", "-s"], debug=debug, raise_on_error=False
    )
    run_command(["telepresence", "helm", "install"], debug=debug, raise_on_error=False)
    run_command(
        ["telepresence", "helm", "upgrade", "--set", "timeouts.agentArrival=120s"],
        debug=debug,
    )
    run_command(["telepresence", "connect"], debug=debug)
    if intercept:
        run_command(
            [
                "kubectl",
                "wait",
                "--for=condition=available",
                "--timeout=300s",
                "deployment/mlrun-api-chief",
                "-n",
                "mlrun",
            ],
            debug=debug,
        )
        run_command(
            [
                "telepresence",
                "--namespace",
                "mlrun",
                "intercept",
                "mlrun-api-chief",
                "--service",
                "mlrun-api-chief",
                "--port",
                "8080:8080",
                "--env-file",
                "mlrun-ce-docker.env",
            ],
            debug=debug,
        )


def configure_metallb(debug: bool):
    echo_color("Configuring MetalLB.")
    run_command(
        [
            "kubectl",
            "apply",
            "-f",
            "https://raw.githubusercontent.com/metallb/metallb/main/config/manifests/metallb-native.yaml",
        ],
        debug=debug,
    )
    run_command(
        [
            "kubectl",
            "wait",
            "--namespace",
            "metallb-system",
            "--for=condition=ready",
            "pod",
            "--selector=app=metallb",
            "--timeout=90s",
        ],
        debug=debug,
    )
    res = subprocess.run(
        ["kubectl", "get", "configmap", "config", "-n", "metallb-system"],
        capture_output=True,
        text=True,
    )
    if "NotFound" in res.stderr:
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".yaml", mode="w", encoding="utf-8"
        ) as tmpf:
            tmpf.write(METALLB_CONFIG_YAML)
            tmpf.flush()
            run_command(["kubectl", "apply", "-f", tmpf.name], debug=debug)


def is_traefik_installed(debug: bool = False) -> bool:
    """
    Checks if Traefik is installed on the cluster by looking for Traefik pods in all namespaces.
    You can customize this logic to best suit your environment.
    """
    cmd = ["kubectl", "get", "pods", "-A"]
    if debug:
        typer.echo(f"[DEBUG] Checking for Traefik: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # If we failed to run kubectl, fallback to saying no
        if debug:
            typer.echo(
                "[DEBUG] kubectl get pods -A failed, assuming Traefik is not installed."
            )
        return False

    # Simple detection if 'traefik' is found in any pod name
    return "traefik" in res.stdout.lower()


def setup_nginx(debug: bool):
    """
    Installs ingress-nginx only if Traefik is not detected.
    Otherwise, we assume the user wants to rely on Traefik for ingress.
    """
    traefik_found = is_traefik_installed(debug=debug)
    if traefik_found:
        typer.echo(
            "Traefik is already installed on this cluster. Skipping ingress-nginx installation."
        )
        return

    typer.echo("Setting up NGINX Ingress Controller.")
    run_command(
        [
            "helm",
            "repo",
            "add",
            "ingress-nginx",
            "https://kubernetes.github.io/ingress-nginx",
        ],
        debug=debug,
    )
    run_command(["helm", "repo", "update"], debug=debug)
    res = subprocess.run(
        ["helm", "status", "ingress-nginx", "-n", "ingress-nginx"],
        capture_output=True,
        text=True,
    )
    if "not found" in (res.stdout + res.stderr).lower():
        run_command(
            [
                "helm",
                "install",
                "--namespace",
                "ingress-nginx",
                "--create-namespace",
                "--set",
                "controller.ingressClassResource.default=true",
                "ingress-nginx",
                "ingress-nginx/ingress-nginx",
                "--debug",
            ],
            debug=debug,
        )


def add_helm_repositories(debug: bool):
    echo_color("Setting up Helm repositories.")
    for name, url in HELM_REPOS.items():
        run_command(["helm", "repo", "add", name, url], debug=debug)
    run_command(["helm", "repo", "update"], debug=debug)


def setup_registry_secret(
    docker_user: str, docker_pass: str, docker_server: str, debug: bool
):
    echo_color("Setting up Docker registry secret.")
    ns_cmd = subprocess.run(
        ["kubectl", "create", "namespace", "mlrun", "--dry-run=client", "-o", "yaml"],
        capture_output=True,
        text=True,
    )
    run_command(["kubectl", "apply", "-f", "-"], input_data=ns_cmd.stdout, debug=debug)

    res = subprocess.run(
        ["kubectl", "-n", "mlrun", "get", "secret", "registry-credentials"],
        capture_output=True,
        text=True,
    )
    if "NotFound" in res.stderr:
        run_command(
            [
                "kubectl",
                "-n",
                "mlrun",
                "create",
                "secret",
                "docker-registry",
                "registry-credentials",
                "--docker-username",
                docker_user,
                "--docker-password",
                docker_pass,
                "--docker-server",
                docker_server,
                "--docker-email",
                f"{docker_user}@iguazio.com",
            ],
            debug=debug,
        )


SEMVER_RC_REGEX = re.compile(r"^\d+\.\d+\.\d+(?:-rc\d+)?$")


def clean_version(version_str):
    match = re.search(r"\d+\.\d+\.\d+(?:-rc\d+)?", version_str)
    return match.group(0) if match else version_str.strip()


def is_valid_version(version):
    return bool(SEMVER_RC_REGEX.match(version))


def get_all_tags(url):
    tags = []
    page = 1
    per_page = 100
    while True:
        params = {"page": page, "per_page": per_page}
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            page_tags = response.json()
            if not page_tags:
                break
            tags.extend(page_tags)
            page += 1
        except requests.RequestException as e:
            print(f"HTTP error occurred while fetching tags: {e}")
            break
    return tags


def get_latest_valid_version(tags_url):
    latest_version = None
    tags = get_all_tags(tags_url)
    for tag in tags:
        tag_name = tag.get("name", "")
        cleaned_version = clean_version(tag_name)
        if is_valid_version(cleaned_version):
            latest_version = cleaned_version
            print(f"Valid version found: {latest_version}")
            break
        else:
            print(f"Ignoring invalid version: {cleaned_version}")
    if not latest_version:
        raise ValueError("No valid version found with the required criteria.")
    return latest_version


def setup_ce(use_kfp_v2: bool, user: str, server: str, ce_version: str, debug: bool):
    if not ce_version:
        ce_version = get_latest_valid_version(
            "https://api.github.com/repos/mlrun/ce/tags"
        )
        ce_version = ce_version.replace("mlrun-ce-", "")

    add_helm_repositories(debug=debug)

    res = subprocess.run(
        ["helm", "status", "mlrun-admin", "-n", "mlrun"],
        capture_output=True,
        text=True,
    )
    if "not found" in (res.stdout + res.stderr).lower():
        run_command(
            [
                "helm",
                "--namespace",
                "mlrun",
                "upgrade",
                "--install",
                "mlrun-admin",
                "--create-namespace",
                "mlrun/mlrun-ce",
                "--devel",
                "--version",
                ce_version,
                "--values",
                "charts/mlrun-ce/admin_installation_values.yaml",
            ],
            debug=debug,
        )

    registry_url = f"{server.rstrip('/')}/{user}"
    install_args = [
        "--namespace",
        "mlrun",
        "--create-namespace",
        "--set",
        f"global.registry.url={registry_url}",
        "--set",
        "global.registry.secretName=registry-credentials",
        "--set",
        "global.externalHostAddress=k8s.internal",
        "--set",
        "mlrun.api.securityContext.readOnlyRootFilesystem=false",
        "--set",
        "mlrun.api.chief.tolerations[0].key=node.kubernetes.io/disk-pressure",
        "--set",
        "mlrun.api.chief.tolerations[0].operator=Exists",
        "--set",
        "mlrun.api.chief.tolerations[0].effect=NoSchedule",
        "--set",
        "global.localEnvironment=true",
        "--set",
        "global.persistence.storageClass=hostpath",
        "--set",
        f"global.persistence.hostPath={Path.home() / 'mlrun-data'}",
        "mlrun/mlrun-ce",
        "--devel",
        "--version",
        ce_version,
        "--values",
        "charts/mlrun-ce/non_admin_cluster_ip_installation_values.yaml",
        "--set",
        "argoWorkflows.controller.metricsConfig.enabled=true",
        "--set",
        "argoWorkflows.controller.metricsConfig.port=9090",
    ]
    if use_kfp_v2:
        install_args += ["--values", "charts/mlrun-ce/kfp2.yaml"]

    run_command(
        ["helm", "upgrade", "--install", "mlrun"] + install_args + ["--debug"],
        debug=debug,
    )


def upgrade_images(
    mlrun_ver: str, ce_dir: Path, user: str, server: str, branch: str, debug: bool
):
    if not ce_dir.is_dir():
        run_command(["git", "clone", REPO_URL, str(ce_dir)], debug=debug)
    else:
        if branch:
            run_command(["git", "checkout", branch], cwd=ce_dir, debug=debug)
            run_command(["git", "pull"], cwd=ce_dir, debug=debug)

    charts = ce_dir / "charts" / "mlrun-ce"
    if not charts.is_dir():
        echo_color(
            f"{charts} not found. Skipping local image upgrade.",
            color=typer.colors.YELLOW,
        )
        return

    if not mlrun_ver:
        mlrun_ver = get_latest_valid_version(
            "https://api.github.com/repos/mlrun/mlrun/tags"
        )
        mlrun_ver = mlrun_ver.replace("v", "")

    registry_url = f"{server.rstrip('/')}/{user}"
    run_command(["helm", "dependency", "build"], cwd=charts, debug=debug)
    run_command(
        [
            "helm",
            "upgrade",
            "mlrun",
            ".",
            "--namespace",
            "mlrun",
            "--reuse-values",
            "--set",
            f"global.registry.url={registry_url}",
            "--set",
            f"mlrun.api.image.tag={mlrun_ver}",
            "--set",
            f"mlrun.ui.image.tag={mlrun_ver}",
            "--set",
            f"mlrun.api.sidecars.logCollector.image.tag={mlrun_ver}",
            "--set",
            f"jupyterNotebook.image.tag={mlrun_ver}",
            "--set",
            "nuclio.controller.image.tag=unstable-arm64",
            "--set",
            "nuclio.dashboard.image.tag=unstable-arm64",
            "--debug",
        ],
        cwd=charts,
        debug=debug,
    )


def patch_workflow_controller_to_9091(debug: bool):
    echo_color("Ensuring workflow-controller uses port 9091.")

    # Patch Service
    svc_data = subprocess.run(
        [
            "kubectl",
            "get",
            "service",
            "workflow-controller-metrics",
            "-n",
            "mlrun",
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    if svc_data.returncode != 0:
        echo_color("Cannot get workflow-controller-metrics service.", err=True)
        return

    svc_json = json.loads(svc_data.stdout)
    svc_patches = []
    for idx, port in enumerate(svc_json["spec"]["ports"]):
        if port.get("name") == "metrics":
            # Replace port and targetPort
            svc_patches.append(
                {"op": "replace", "path": f"/spec/ports/{idx}/port", "value": 9091}
            )
            svc_patches.append(
                {
                    "op": "replace",
                    "path": f"/spec/ports/{idx}/targetPort",
                    "value": 9091,
                }
            )
            # Optionally rename to ensure uniqueness
            svc_patches.append(
                {
                    "op": "replace",
                    "path": f"/spec/ports/{idx}/name",
                    "value": f"metrics-{idx}",
                }
            )

    if svc_patches:
        patch_payload = json.dumps(svc_patches)
        run_command(
            [
                "kubectl",
                "patch",
                "service",
                "workflow-controller-metrics",
                "-n",
                "mlrun",
                "--type",
                "json",
                "-p",
                patch_payload,
            ],
            debug=debug,
        )
    else:
        echo_color("No 'metrics' ports found in the service to patch.", err=True)

    # Patch Deployment
    dep_data = subprocess.run(
        [
            "kubectl",
            "get",
            "deployment",
            "workflow-controller",
            "-n",
            "mlrun",
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    if dep_data.returncode != 0:
        echo_color("Cannot get workflow-controller deployment.", err=True)
        return

    dep_json = json.loads(dep_data.stdout)
    dep_patches = []
    containers = dep_json["spec"]["template"]["spec"].get("containers", [])
    if not containers:
        echo_color("No containers found in the deployment.", err=True)
        return

    container = containers[0]  # Assuming single container
    for idx, port in enumerate(container.get("ports", [])):
        if port.get("name") == "metrics":
            # Replace containerPort
            dep_patches.append(
                {
                    "op": "replace",
                    "path": f"/spec/template/spec/containers/0/ports/{idx}/containerPort",
                    "value": 9091,
                }
            )
            # Optionally rename to ensure uniqueness
            dep_patches.append(
                {
                    "op": "replace",
                    "path": f"/spec/template/spec/containers/0/ports/{idx}/name",
                    "value": f"metrics-{idx}",
                }
            )

    if dep_patches:
        dep_patch_payload = json.dumps(dep_patches)
        run_command(
            [
                "kubectl",
                "patch",
                "deployment",
                "workflow-controller",
                "-n",
                "mlrun",
                "--type",
                "json",
                "-p",
                dep_patch_payload,
            ],
            debug=debug,
        )
    else:
        echo_color("No 'metrics' ports found in the deployment to patch.", err=True)

    echo_color("Patching completed.")


def expose_workflow_controller(debug: bool):
    echo_color("Patching workflow-controller with hostNetwork, metrics-port=9091.")
    run_command(
        [
            "kubectl",
            "patch",
            "deployment",
            "workflow-controller",
            "-n",
            "mlrun",
            "--type",
            "json",
            "-p",
            '[{"op":"add","path":"/spec/template/spec/hostNetwork","value":true},'
            '{"op":"replace","path":"/spec/template/spec/containers/0/args","value":'
            '["--configmap","workflow-controller-configmap","--executor-image","argoproj/argoexec:v3.4.6","--metrics-port=9091"]}]',
        ],
        debug=debug,
    )


INGRESS_HOSTS = [
    {
        "host": "mlrun.k8s.internal",
        "paths": [{"path": "/", "serviceName": "mlrun-ui", "servicePort": 80}],
    },
    {
        "host": "mlrun-api.k8s.internal",
        "paths": [{"path": "/", "serviceName": "mlrun-api", "servicePort": 8080}],
    },
    {
        "host": "mlrun-api-chief.k8s.internal",
        "paths": [{"path": "/", "serviceName": "mlrun-api-chief", "servicePort": 8080}],
    },
    {
        "host": "nuclio.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "nuclio-dashboard", "servicePort": 8070}
        ],
    },
    {
        "host": "nuclio-dashboard.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "nuclio-dashboard", "servicePort": 8070}
        ],
    },
    {
        "host": "jupyter.k8s.internal",
        "paths": [{"path": "/", "serviceName": "mlrun-jupyter", "servicePort": 8888}],
    },
    {
        "host": "minio.k8s.internal",
        "paths": [{"path": "/", "serviceName": "minio-console", "servicePort": 9001}],
    },
    {
        "host": "grafana.k8s.internal",
        "paths": [{"path": "/", "serviceName": "grafana", "servicePort": 80}],
    },
    {
        "host": "kfp.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "ml-pipeline-ui", "servicePort": 80},
            {"path": "/apis/", "serviceName": "ml-pipeline", "servicePort": 8888},
        ],
    },
    {
        "host": "metadata-envoy.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "metadata-envoy-service", "servicePort": 9090}
        ],
    },
    {
        "host": "workflow-metrics.k8s.internal",
        "paths": [
            {
                "path": "/",
                "serviceName": "workflow-controller-metrics",
                "servicePort": 9091,
            }
        ],
    },
]


def create_ingress(debug: bool):
    typer.echo("Ensuring Ingress resources are created...")

    traefik_found = is_traefik_installed(debug=debug)

    ingress_class = "traefik" if traefik_found else "nginx"
    ingress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": "mlrun-ce-ingress",
            "namespace": "mlrun",
            "annotations": {},
        },
        "spec": {"ingressClassName": ingress_class, "rules": []},
    }

    for item in INGRESS_HOSTS:
        host_item = {"host": item["host"], "http": {"paths": []}}
        for p in item["paths"]:
            host_item["http"]["paths"].append(
                {
                    "path": p["path"],
                    "pathType": "Prefix",
                    "backend": {
                        "service": {
                            "name": p["serviceName"],
                            "port": {"number": p["servicePort"]},
                        }
                    },
                }
            )
        ingress["spec"]["rules"].append(host_item)

    proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=yaml.dump(ingress, sort_keys=False),
        text=True,
    )
    if proc.returncode == 0:
        typer.echo("Ingress ensured.")
    else:
        echo_color("Failed to create/update Ingress.", err=True)


def patch_mlrun_env():
    env_file = Path("mlrun-ce-docker.env")
    home_dir = str(Path.home())
    new_line = f"MLRUN_HTTPDB__DIRPATH={home_dir}/mlrun/db"
    if env_file.is_file():
        lines = env_file.read_text(encoding="utf-8").splitlines()
        found = False
        for i, line in enumerate(lines):
            if line.startswith("MLRUN_HTTPDB__DIRPATH="):
                lines[i] = new_line
                found = True
        if not found:
            lines.append(new_line)
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        env_file.write_text(new_line + "\n", encoding="utf-8")


def install_ce_on_docker(
    user: str,
    passwd: str,
    server: str,
    ce_dir: Path,
    use_kfp_v2: bool,
    clear_ns: bool,
    intercept: bool,
    install_tel: bool,
    ce_ver: str,
    mlrun_ver: str,
    branch: str,
    debug: bool,
):
    for c in REQUIRED_COMMANDS:
        check_command_exists(c)
    if clear_ns:
        clear_namespaces(debug)
    (Path.home() / "mlrun-data").mkdir(exist_ok=True)

    create_virtual_interface(debug)
    persist_loopbacks_on_windows(debug)
    configure_metallb(debug)
    setup_nginx(debug)
    setup_registry_secret(user, passwd, server, debug)
    write_hosts(debug)
    setup_ce(use_kfp_v2, user, server, ce_ver, debug)
    upgrade_images(mlrun_ver, ce_dir, user, server, branch, debug)
    patch_workflow_controller_to_9091(debug)
    expose_workflow_controller(debug)
    create_ingress(debug)
    setup_telepresence(intercept, install_tel, debug)
    patch_mlrun_env()
    echo_color("MLRun CE installation complete!")


@app.command()
def install(
    ctx: typer.Context,
    docker_user: str = typer.Option(
        ...,
        help="Docker username for pulling/pushing images."
    ),
    docker_password: str = typer.Option(
        ...,
        help="Password or token for the specified Docker user."
    ),
    docker_server: str = typer.Option(
        ...,
        help="Docker registry server (e.g., 'docker.io' or a private registry)."
    ),
    ce_folder: Path = typer.Option(
        Path.home() / "mlrun-ce",
        "--ce-folder",
        help="Folder in which to clone and store the MLRun CE source."
    ),
    use_kfp_v2: bool = typer.Option(
        False,
        "--use-kfp-v2",
        help="Enable Kubeflow Pipelines V2 integration."
    ),
    clear_k8s_namespaces: bool = typer.Option(
        False,
        "--clear-namespaces",
        help="Remove existing MLRun-related Kubernetes namespaces before install."
    ),
    intercept: bool = typer.Option(
        False,
        "--intercept",
        help="Intercept the MLRun API Chief deployment using Telepresence."
    ),
    install_tel: bool = typer.Option(
        False,
        "--install-telepresence",
        help="Install Telepresence if not found on the system."
    ),
    ce_version: str = typer.Option(
        "",
        "--ce-version",
        help="MLRun CE chart version to install. If empty, fetches the latest valid version."
    ),
    mlrun_version: str = typer.Option(
        "",
        "--mlrun-version",
        help="MLRun version (image tag) to use. If empty, fetches the latest valid version."
    ),
    branch: str = typer.Option(
        "",
        "--branch",
        help="Git branch name to check out when upgrading images from the CE repo."
    ),
    debug: bool = typer.Option(
        "",
        "--debug",
        help="Enable debug mode for more verbose log output."
    ),
):
    install_ce_on_docker(
        docker_user,
        docker_password,
        docker_server,
        ce_folder,
        use_kfp_v2,
        clear_k8s_namespaces,
        intercept,
        install_tel,
        ce_version,
        mlrun_version,
        branch,
        debug,
    )

@app.command()
def intercept_only(
    ctx: typer.Context,
    install_tel: bool = typer.Option(
        False,
        "--install-telepresence",
        help="Install Telepresence if not installed."
    ),
    debug: bool = typer.Option(
        "",
        "--debug",
        help="Enable debug mode for more verbose log output."
    ),
):
    """
    Only intercept the MLRun API Chief deployment (without re-installing everything).
    """
    setup_telepresence(intercept=True, install=install_tel, debug=debug)

@app.command()
def unintercept(
    ctx: typer.Context,
    debug: bool = typer.Option(
        "",
        "--debug",
        help="Enable debug mode for more verbose log output."
    ),
):
    """
    Disconnect Telepresence and leave the MLRun API Chief intercept.
    """
    run_command(["telepresence", "leave", "mlrun-api-chief"], debug=debug)
    run_command(["telepresence", "disconnect"], debug=debug)
    echo_color("Telepresence intercept removed and disconnected.")


if __name__ == "__main__":
    app()
