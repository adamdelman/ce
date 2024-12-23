#!/usr/bin/env python3

import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Any

import requests
import typer
import yaml

app = typer.Typer(help="Manage MLRun CE installation & Telepresence intercept.")

REPO_URL: str = "git@github.com:mlrun/ce.git"

COMPONENT_IPS: dict[str, list[str]] = {
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

HELM_REPOS: dict[str, str] = {
    "mlrun": "https://mlrun.github.io/ce",
    "nuclio": "https://nuclio.github.io/nuclio/charts",
    "v3io-stable": "https://v3io.github.io/helm-charts/stable",
    "minio": "https://charts.min.io/",
    "spark-operator": "https://kubeflow.github.io/spark-operator",
    "prometheus-community": "https://prometheus-community.github.io/helm-charts",
}

METALLB_CONFIG_YAML: str = """apiVersion: v1
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

WINDOWS_SCHEDULED_TASK_NAME: str = "LoopbackAliases"
WINDOWS_LOOPBACK_SCRIPT: Path = Path(r"C:\persist_loopbacks.bat")

REQUIRED_COMMANDS: list[str] = ["git", "helm", "kubectl"]


def run_command(
        cmd: list[str],
        check: bool = True,
        cwd: Optional[Path] = None,
        input_data: Optional[str] = None
) -> None:
    cmd_str = " ".join(cmd)
    typer.echo(f"Running: {cmd_str}")
    cwd_str = str(cwd) if cwd else None
    try:
        subprocess.run(cmd, check=check, cwd=cwd_str, input=input_data, text=True)
    except subprocess.CalledProcessError as e:
        typer.secho(f"Command failed: {e}", fg=typer.colors.RED)
        if check:
            sys.exit(e.returncode)


def check_command_exists(cmd: str) -> None:
    if shutil.which(cmd) is None:
        typer.secho(f"[WARNING] Command '{cmd}' not installed or not on PATH.", fg=typer.colors.YELLOW)


def clear_docker_images() -> None:
    typer.echo("Clearing Docker images/containers via docker system prune -a -f.")
    run_command(["docker", "system", "prune", "-a", "-f"])
    run_command(["kubectl", "delete", "namespace", "mlrun"])
    run_command(["kubectl", "delete", "namespace", "ambassador"])


def windows_create_loopback_script(ips: list[str], interface_name: str = "Loopback Pseudo-Interface 1") -> None:
    lines: list[str] = []
    lines.append("@echo off")
    for ip in ips:
        lines.append(f'netsh interface ip add address "{interface_name}" {ip} 255.255.255.0 1>nul 2>nul')
    lines.append("exit /b 0")
    WINDOWS_LOOPBACK_SCRIPT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def windows_create_scheduled_task() -> None:
    run_command(["schtasks", "/delete", "/f", "/tn", WINDOWS_SCHEDULED_TASK_NAME], check=False)
    run_command([
        "schtasks", "/create",
        "/tn", WINDOWS_SCHEDULED_TASK_NAME,
        "/sc", "onstart",
        "/ru", "SYSTEM",
        "/rl", "HIGHEST",
        "/tr", str(WINDOWS_LOOPBACK_SCRIPT),
    ])
    typer.echo(f"Scheduled task '{WINDOWS_SCHEDULED_TASK_NAME}' created or updated.")


def create_virtual_interface() -> None:
    system_str = platform.system().lower()
    ips = list(COMPONENT_IPS.keys())

    if system_str == "windows":
        interface_name = "Loopback Pseudo-Interface 1"
        for ip in ips:
            run_command(["netsh", "interface", "ip", "add", "address", interface_name, ip, "255.255.255.0"],
                        check=False)
    elif system_str == "darwin":
        interface_name = "lo0"
        for ip in ips:
            result = subprocess.run(["ifconfig", interface_name], stdout=subprocess.PIPE, text=True)
            if ip not in result.stdout:
                run_command(["sudo", "ifconfig", interface_name, "alias", ip], check=False)
    elif system_str == "linux":
        interface_name = "lo"
        for ip in ips:
            result = subprocess.run(["ip", "addr", "show", interface_name], stdout=subprocess.PIPE, text=True)
            if ip not in result.stdout:
                run_command(["sudo", "ip", "address", "add", f"{ip}/32", "dev", interface_name], check=False)


def persist_loopback_aliases_on_boot() -> None:
    system_str = platform.system().lower()
    if system_str == "windows":
        ips = list(COMPONENT_IPS.keys())
        windows_create_loopback_script(ips)
        windows_create_scheduled_task()


def write_hosts() -> None:
    system_str = platform.system().lower()
    if system_str == "windows":
        hosts_file = Path(r"C:\Windows\System32\drivers\etc\hosts")
    else:
        hosts_file = Path("/etc/hosts")

    old_content: list[str] = []
    if hosts_file.is_file():
        try:
            old_content = hosts_file.read_text(encoding="utf-8").splitlines(keepends=True)
        except Exception:
            old_content = []

    new_lines: list[str] = []
    for line in old_content:
        skip_line = False
        for ip, hosts in COMPONENT_IPS.items():
            for h in hosts:
                if h in line:
                    skip_line = True
                    break
            if skip_line:
                break
        if not skip_line:
            new_lines.append(line)

    for ip, hosts in COMPONENT_IPS.items():
        for h in hosts:
            new_lines.append(f"{ip}\t{h}\n")

    if system_str in ["linux", "darwin"]:
        try:
            tmp_hosts = Path(tempfile.gettempdir()) / "hosts.tmp"
            tmp_hosts.write_text("".join(new_lines), encoding="utf-8")
            run_command(["sudo", "mv", str(tmp_hosts), str(hosts_file)], check=False)
            typer.echo("Hosts file updated via sudo mv.")
        except Exception as e:
            typer.secho(f"Error writing hosts file: {e}", fg=typer.colors.RED)
    else:
        try:
            hosts_file.write_text("".join(new_lines), encoding="utf-8")
            typer.echo("Hosts file updated.")
        except Exception as e:
            typer.secho(f"Error writing hosts file: {e}", fg=typer.colors.RED)


def install_telepresence_all_os() -> None:
    """
    If telepresence is not found, install it according to OS.
    On macOS, use the arm64 formula from the custom raw URL.
    """
    if shutil.which("telepresence") is not None:
        typer.echo("Telepresence is already installed. Skipping installation.")
        return

    system_str = platform.system().lower()
    if system_str == "darwin":
        if shutil.which("brew") is None:
            typer.secho("Homebrew not found, cannot install Telepresence automatically.", fg=typer.colors.YELLOW)
            return
        # Install from the custom Telepresence arm64 formula
        run_command([
            "brew", "install",
            "https://raw.githubusercontent.com/datawire/homebrew-blackbird/97e0a28d02adb42221ae4160c35a35f3a00f9eed/Formula/telepresence-arm64.rb"
        ], check=False)
    elif system_str == "linux":
        tmp_path = Path(tempfile.gettempdir()) / "telepresence"
        run_command([
            "curl", "-fL",
            "https://app.getambassador.io/download/tel2oss/releases/download/v2.14.4/telepresence-linux-amd64",
            "-o", str(tmp_path)
        ], check=False)
        run_command(["chmod", "+x", str(tmp_path)], check=False)
        run_command(["sudo", "mv", str(tmp_path), "/usr/local/bin/telepresence"], check=False)
    elif system_str == "windows":
        if shutil.which("choco") is None:
            run_command([
                "powershell.exe",
                "Set-ExecutionPolicy", "Bypass", "-Scope", "Process", "-Force;",
                "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;",
                "iex",
                "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')"
            ], check=False)
        if shutil.which("choco") is not None:
            run_command(["choco", "install", "telepresence", "--version=2.14.4", "-y"], check=False)


def setup_telepresence(intercept: bool, install: bool) -> None:
    if install:
        install_telepresence_all_os()
    run_command(["telepresence", "helm", "install"], check=False)
    run_command(["telepresence", "helm", "upgrade", "--set", "timeouts.agentArrival=120s"], check=False)
    run_command(["telepresence", "connect"], check=False)
    run_command(["kubectl", "rollout", "restart", "deployment/mlrun-api-chief", "-n", "mlrun"], check=False)
    run_command([
        "kubectl", "wait", "--for=condition=available", "--timeout=120s",
        "deployment/mlrun-api-chief", "-n", "mlrun"
    ], check=False)
    if intercept:
        env_file = "mlrun-ce-docker.env"
        run_command([
            "telepresence", "--namespace", "mlrun", "intercept", "mlrun-api-chief",
            "--service", "mlrun-api-chief", "--port", "8080:8080",
            "--env-file", env_file
        ], check=False)


def configure_metallb() -> None:
    run_command([
        "kubectl", "apply", "-f",
        "https://raw.githubusercontent.com/metallb/metallb/main/config/manifests/metallb-native.yaml"
    ], check=False)
    run_command([
        "kubectl", "wait", "--namespace", "metallb-system",
        "--for=condition=ready", "pod", "--selector=app=metallb",
        "--timeout=90s"
    ], check=False)
    result = subprocess.run(
        ["kubectl", "get", "configmap", "config", "-n", "metallb-system"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "NotFound" in result.stderr:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="w", encoding="utf-8") as tmpf:
            tmpf.write(METALLB_CONFIG_YAML)
            tmpf.flush()
            run_command(["kubectl", "apply", "-f", tmpf.name], check=False)


def setup_nginx() -> None:
    run_command(["helm", "repo", "add", "ingress-nginx", "https://kubernetes.github.io/ingress-nginx"], check=False)
    run_command(["helm", "repo", "update"], check=False)
    result = subprocess.run(
        ["helm", "status", "ingress-nginx", "-n", "ingress-nginx"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "not found" in (result.stdout + result.stderr).lower():
        run_command([
            "helm", "install",
            "--namespace", "ingress-nginx",
            "--create-namespace",
            "--set", "controller.ingressClassResource.default=true",
            "ingress-nginx", "ingress-nginx/ingress-nginx",
            "--debug"
        ])


def add_helm_repositories() -> None:
    for name, url in HELM_REPOS.items():
        run_command(["helm", "repo", "add", name, url], check=False)
    run_command(["helm", "repo", "update"], check=False)


def setup_registry_secret(docker_user: str, docker_password: str, docker_server: str) -> None:
    ns_result = subprocess.run(
        ["kubectl", "create", "namespace", "mlrun", "--dry-run=client", "-o", "yaml"],
        stdout=subprocess.PIPE,
        text=True
    )
    run_command(["kubectl", "apply", "-f", "-"], check=False, input_data=ns_result.stdout)

    result = subprocess.run(
        ["kubectl", "--namespace", "mlrun", "get", "secret", "registry-credentials"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "NotFound" in result.stderr:
        run_command([
            "kubectl", "--namespace", "mlrun",
            "create", "secret", "docker-registry", "registry-credentials",
            "--docker-username", docker_user,
            "--docker-password", docker_password,
            "--docker-server", docker_server,
            "--docker-email", f"{docker_user}@iguazio.com"
        ])


def setup_ce(use_kfp_v2: bool, docker_user: str, docker_server: str, ce_version: str) -> None:
    if not ce_version:
        r = requests.get("https://api.github.com/repos/mlrun/ce/tags", timeout=30)
        r.raise_for_status()
        tags = r.json()
        ce_version = tags[0]["name"].replace("mlrun-ce-", "")

    add_helm_repositories()

    result = subprocess.run(
        ["helm", "status", "mlrun-admin", "-n", "mlrun"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "not found" in (result.stdout + result.stderr).lower():
        run_command([
            "helm", "--namespace", "mlrun",
            "upgrade", "--install", "mlrun-admin",
            "--create-namespace",
            "mlrun/mlrun-ce",
            "--devel",
            "--version", ce_version,
            "--values", "charts/mlrun-ce/admin_installation_values.yaml"
        ], check=False)

    registry_url = f"{docker_server.rstrip('/')}/{docker_user}"
    install_args: list[str] = [
        "--namespace", "mlrun",
        "--create-namespace",
        "--set", f"global.registry.url={registry_url}",
        "--set", "global.registry.secretName=registry-credentials",
        "--set", "global.externalHostAddress=k8s.internal",
        "--set", "mlrun.api.securityContext.readOnlyRootFilesystem=false",
        "--set", "mlrun.api.chief.tolerations[0].key=node.kubernetes.io/disk-pressure",
        "--set", "mlrun.api.chief.tolerations[0].operator=Exists",
        "--set", "mlrun.api.chief.tolerations[0].effect=NoSchedule",
        "--set", "global.localEnvironment=true",
        "--set", "global.persistence.storageClass=hostpath",
        "--set", f"global.persistence.hostPath={Path.home() / 'mlrun-data'}",
        "mlrun/mlrun-ce",
        "--devel",
        "--version", ce_version,
        "--values", "charts/mlrun-ce/non_admin_cluster_ip_installation_values.yaml",
        "--set", "argoWorkflows.controller.metricsConfig.enabled=true",
        "--set", "argoWorkflows.controller.metricsConfig.port=9090"
    ]
    if use_kfp_v2:
        install_args.extend(["--values", "charts/mlrun-ce/kfp2.yaml"])

    run_command(["helm", "upgrade", "--install", "mlrun"] + install_args + ["--debug"], check=False)


def upgrade_images(mlrun_version: str, ce_folder: Path, docker_user: str, docker_server: str) -> None:
    if not ce_folder.is_dir():
        run_command(["git", "clone", REPO_URL, str(ce_folder)])
    else:
        run_command(["git", "checkout", "development"], check=False, cwd=ce_folder)
        run_command(["git", "pull"], check=False, cwd=ce_folder)

    charts_dir = ce_folder / "charts" / "mlrun-ce"
    if not charts_dir.is_dir():
        typer.secho(f"Directory {charts_dir} not found. Skipping local image upgrade.", fg=typer.colors.YELLOW)
        return

    if not mlrun_version:
        r = requests.get("https://api.github.com/repos/mlrun/mlrun/tags", timeout=30)
        r.raise_for_status()
        tags = r.json()
        mlrun_version = tags[0]["name"].replace("v", "")

    registry_url = f"{docker_server.rstrip('/')}/{docker_user}"
    run_command(["helm", "dependency", "build"], check=False, cwd=charts_dir)
    run_command([
        "helm", "upgrade", "mlrun", ".",
        "--namespace", "mlrun",
        "--reuse-values",
        "--set", f"global.registry.url={registry_url}",
        "--set", f"mlrun.api.image.tag={mlrun_version}",
        "--set", f"mlrun.ui.image.tag={mlrun_version}",
        "--set", f"mlrun.api.sidecars.logCollector.image.tag={mlrun_version}",
        "--set", f"jupyterNotebook.image.tag={mlrun_version}",
        "--set", "nuclio.controller.image.tag=unstable-arm64",
        "--set", "nuclio.dashboard.image.tag=unstable-arm64",
        "--debug"
    ], check=False, cwd=charts_dir)


def patch_workflow_controller_to_9091() -> None:
    typer.echo("Patching workflow-controller to use 9091.")
    svc_patch = (
        '[{"op": "replace","path": "/spec/ports/0/port","value": 9091},'
        '{"op": "replace","path": "/spec/ports/0/targetPort","value": 9091}]'
    )
    run_command([
        "kubectl", "patch", "service", "workflow-controller-metrics",
        "-n", "mlrun", "--type", "json", "-p", svc_patch
    ], check=False)

    dep_patch = '[{"op":"replace","path":"/spec/template/spec/containers/0/ports/0/containerPort","value":9091}]'
    run_command([
        "kubectl", "patch", "deployment", "workflow-controller",
        "-n", "mlrun", "--type", "json", "-p", dep_patch
    ], check=False)


def expose_workflow_controller() -> None:
    typer.echo("Patching workflow-controller to hostNetwork, --metrics-port=9091.")
    patch_payload = (
        '[{"op":"add","path":"/spec/template/spec/hostNetwork","value":true},'
        '{"op":"replace","path":"/spec/template/spec/containers/0/args","value":'
        '["--configmap","workflow-controller-configmap","--executor-image","argoproj/argoexec:v3.4.6","--metrics-port=9091"]}]'
    )
    run_command([
        "kubectl", "patch", "deployment", "workflow-controller",
        "-n", "mlrun", "--type", "json", "-p", patch_payload
    ], check=False)


INGRESS_HOSTS: list[dict[str, Any]] = [
    {
        "host": "mlrun.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "mlrun-ui", "servicePort": 80},
        ],
    },
    {
        "host": "mlrun-api.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "mlrun-api", "servicePort": 8080},
        ],
    },
    {
        "host": "mlrun-api-chief.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "mlrun-api-chief", "servicePort": 8080},
        ],
    },
    {
        "host": "nuclio.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "nuclio-dashboard", "servicePort": 8070},
        ],
    },
    {
        "host": "nuclio-dashboard.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "nuclio-dashboard", "servicePort": 8070},
        ],
    },
    {
        "host": "jupyter.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "mlrun-jupyter", "servicePort": 8888},
        ],
    },
    {
        "host": "minio.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "minio-console", "servicePort": 9001},
        ],
    },
    {
        "host": "grafana.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "grafana", "servicePort": 80},
        ],
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
            {"path": "/", "serviceName": "metadata-envoy-service", "servicePort": 9090},
        ],
    },
    {
        "host": "workflow-metrics.k8s.internal",
        "paths": [
            {"path": "/", "serviceName": "workflow-controller-metrics", "servicePort": 9091},
        ],
    },
]


def create_ingress() -> None:
    typer.echo("Ensuring Ingress resources are created...")

    ingress_dict: dict[str, Any] = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": "mlrun-ce-ingress",
            "namespace": "mlrun",
        },
        "spec": {
            "ingressClassName": "nginx",
            "rules": [],
        },
    }

    for entry in INGRESS_HOSTS:
        host_item: dict[str, Any] = {
            "host": entry["host"],
            "http": {
                "paths": [],
            },
        }
        for path_data in entry["paths"]:
            host_item["http"]["paths"].append({
                "path": path_data["path"],
                "pathType": "Prefix",
                "backend": {
                    "service": {
                        "name": path_data["serviceName"],
                        "port": {
                            "number": path_data["servicePort"],
                        },
                    }
                },
            })
        ingress_dict["spec"]["rules"].append(host_item)

    yaml_str = yaml.dump(ingress_dict, sort_keys=False)

    proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=yaml_str,
        text=True
    )
    if proc.returncode == 0:
        typer.echo("Ingress ensured.")
    else:
        typer.echo("Failed to create or update Ingress.")


def patch_mlrun_env() -> None:
    env_file = Path("mlrun-ce-docker.env")
    home_dir = str(Path.home())
    patched_line = f"MLRUN_HTTPDB__DIRPATH={home_dir}/mlrun/db"
    if env_file.is_file():
        lines = env_file.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        replaced = False
        for line in lines:
            if line.startswith("MLRUN_HTTPDB__DIRPATH="):
                new_lines.append(patched_line)
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            new_lines.append(patched_line)
        env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    else:
        env_file.write_text(patched_line + "\n", encoding="utf-8")


def install_ce_on_docker(
        docker_user: str,
        docker_password: str,
        docker_server: str,
        ce_folder: Path,
        use_kfp_v2: bool,
        clear_docker: bool,
        intercept: bool,
        install_tel: bool,
        ce_version: str,
        mlrun_version: str
) -> None:
    for c in REQUIRED_COMMANDS:
        check_command_exists(c)

    if clear_docker:
        clear_docker_images()

    (Path.home() / "mlrun-data").mkdir(exist_ok=True)

    create_virtual_interface()
    persist_loopback_aliases_on_boot()
    configure_metallb()
    setup_nginx()
    setup_registry_secret(docker_user, docker_password, docker_server)
    write_hosts()
    setup_ce(use_kfp_v2, docker_user, docker_server, ce_version)
    upgrade_images(mlrun_version, ce_folder, docker_user, docker_server)
    patch_workflow_controller_to_9091()
    expose_workflow_controller()
    create_ingress()
    setup_telepresence(intercept=intercept, install=install_tel)
    patch_mlrun_env()

    typer.echo("MLRun CE installation complete!")


@app.command()
def install(
        docker_user: str = typer.Option(...),
        docker_password: str = typer.Option(...),
        docker_server: str = typer.Option("https://artifactory.iguazeng.com:10557", "--docker-server"),
        ce_folder: Path = typer.Option(Path.home() / "mlrun-ce", "--ce-folder"),
        use_kfp_v2: bool = typer.Option(False, "--use-kfp-v2"),
        clear_docker: bool = typer.Option(False, "--clear-docker"),
        intercept: bool = typer.Option(False, "--intercept"),
        install_tel: bool = typer.Option(False, "--install-telepresence"),
        ce_version: str = typer.Option("", "--ce-version"),
        mlrun_version: str = typer.Option("", "--mlrun-version")
) -> None:
    install_ce_on_docker(
        docker_user,
        docker_password,
        docker_server,
        ce_folder,
        use_kfp_v2,
        clear_docker,
        intercept,
        install_tel,
        ce_version,
        mlrun_version
    )


@app.command()
def intercept_only(
        install_tel: bool = typer.Option(False, "--install-telepresence")
) -> None:
    setup_telepresence(intercept=True, install=install_tel)


if __name__ == "__main__":
    app()
