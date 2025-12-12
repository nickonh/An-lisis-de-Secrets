import requests
import subprocess
import os
from datetime import datetime
from shutil import which

DOCKER = "docker"
TRIVY = "trivy"


# --------------------------- Helpers ---------------------------

def check_dependencies():
    if which(DOCKER) is None:
        print("[ERROR] Docker no está instalado o no está en PATH.")
        exit(1)
    if which(TRIVY) is None:
        print("[ERROR] Trivy no está instalado o no está en PATH.")
        exit(1)


def normalize_image_name(image_name):
    if image_name.startswith("library/"):
        return image_name.replace("library/", "", 1)
    return image_name


def search_images(keyword, max_pages=3):
    images = []
    for page in range(1, max_pages + 1):
        url = f"https://hub.docker.com/v2/search/repositories/?query={keyword}&page={page}"
        try:
            r = requests.get(url, timeout=10).json()
        except Exception as e:
            print(f"[!] Error consultando Docker Hub: {e}")
            break

        for item in r.get("results", []):
            images.append(item["repo_name"])

    return images


# --------------------------- NEW: Obtener tags ---------------------------

def get_tags(repo, limit=3):
    """Obtiene los tags reales de un repositorio."""
    url = f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100"

    try:
        r = requests.get(url, timeout=10).json()
    except Exception as e:
        print(f"[!] Error obteniendo tags de {repo}: {e}")
        return []

    tags = [t["name"] for t in r.get("results", [])]

    if not tags:
        return []

    # Si existe "latest", lo usamos como prioridad
    if "latest" in tags:
        return ["latest"]

    # De lo contrario, tomamos los primeros N
    return tags[:limit]


# -------------------------------------------------------------------------

def run_trivy(image, tag):
    """Descarga, analiza con Trivy y elimina la imagen."""

    report_dir = os.path.join(os.path.expanduser("~"), "docker_reports")
    os.makedirs(report_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{image.replace('/', '_')}_{tag}"
    output = os.path.join(report_dir, f"{safe_name}_{timestamp}.json")

    full_image = f"{image}:{tag}"

    print(f"\n[*] Descargando imagen: {full_image}")
    pull = subprocess.run(
        [DOCKER, "pull", full_image],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if pull.returncode != 0:
        print(f"[!] No se pudo descargar '{full_image}'. Saltando.")
        return

    cmd = [TRIVY, "image", "--format", "json", "-o", output, full_image]

    print(f"[*] Analizando con Trivy: {full_image}")
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Reporte guardado en: {output}")
    except subprocess.CalledProcessError:
        print(f"[!] Error analizando {full_image}")

    finally:
        subprocess.run([DOCKER, "rmi", full_image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    check_dependencies()

    keyword = input("Keyword para buscar imágenes en Docker Hub: ").strip()

    print(f"[*] Buscando imágenes relacionadas con: {keyword}")
    repos = search_images(keyword)

    if not repos:
        print("[!] No se encontraron repositorios.")
        return

    print(f"[+] {len(repos)} repos encontrados:")
    for repo in repos:
        print(" -", repo)

    for repo in repos:
        repo = normalize_image_name(repo)

        # Obtener tags reales
        tags = get_tags(repo)

        if not tags:
            print(f"[!] {repo} no tiene tags. Saltando.")
            continue

        for tag in tags:
            run_trivy(repo, tag)

    print("\n[✔] Finalizado. Todas las imágenes y tags fueron analizados.\n")


if __name__ == "__main__":
    main()
