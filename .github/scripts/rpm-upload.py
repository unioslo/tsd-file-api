import argparse
import base64
import os
import re
import urllib
import urllib.parse
import urllib.request


def get_package_info(filename: str):
    pattern = r"^(?P<name>.+)-(?P<version>[\d\.]+(\.(dev|a|b|rc|post)\d+(\+[0-9a-z]+)?)?)-(?P<release>[\d\.]+)\.(?P<os>[a-z0-9]+)\.(?P<arch>.+)\.rpm$"
    match = re.match(pattern, filename)
    if match:
        return match.groupdict()
    else:
        raise ValueError(f"Filename '{filename}' does not match expected pattern.")


def upload_path(name: str, version: str, release: str, os: str, arch: str) -> str:
    os_match = re.match(r"^(?P<os_name>[a-z]+)(?P<os_ver>[0-9]+)$", os)
    if not os_match:
        raise ValueError(f"OS string '{os}' does not match expected pattern.")
    os_name = os_match.group("os_name")
    os_ver = os_match.group("os_ver")
    if arch == "noarch":
        arch = "x86_64"
    return f"{os_name}/{os_ver}/Everything/{arch}/Packages/{name[0]}"


def generate_upload_url(base_url: str, repo_name: str, filename: str) -> str:
    package_info = get_package_info(filename)
    path = upload_path(
        name=package_info["name"],
        version=package_info["version"],
        release=package_info["release"],
        os=package_info["os"],
        arch=package_info["arch"],
    )
    full_url = urllib.parse.urljoin(
        base_url + "/" + repo_name + "/", path + "/" + filename
    )
    return full_url


def upload_file(upload_url: str, file_path: str, credentials: tuple):
    with open(file_path, "rb") as file_data:
        data = file_data.read()
    request = urllib.request.Request(upload_url, data=data, method="PUT")
    request.add_header("Content-Type", "application/x-rpm")

    # authentication
    encoded_auth = base64.b64encode(
        f"{credentials[0]}:{credentials[1]}".encode()
    ).decode()
    request.add_header("Authorization", f"Basic {encoded_auth}")

    with urllib.request.urlopen(request) as response:
        if response.status == 200 or response.status == 201:
            print(f"Successfully uploaded to {upload_url}")
        else:
            print(f"Failed to upload. Status code: {response.status}")


# CLI interface
def main():
    parser = argparse.ArgumentParser(description="Upload RPM files to a repository.")
    parser.add_argument("file_path", help="Path to the RPM file to upload", nargs="+")
    parser.add_argument(
        "--base_url",
        help="Base URL of the repository",
        default="https://artifacts.tsd.usit.no/repository/",
    )
    parser.add_argument(
        "--repo-name", help="Repository name", default="tsd-yum", required=False
    )
    parser.add_argument(
        "--username", help="Username for authentication", required=False
    )
    parser.add_argument(
        "--password", help="Password for authentication", required=False
    )
    args = parser.parse_args()

    for path in args.file_path:
        filename = path.split("/")[-1]
        upload_url = generate_upload_url(args.base_url, args.repo_name, filename)
        if not args.username:
            if os.environ.get("RPM_USERNAME"):
                args.username = os.environ.get("RPM_USERNAME")
            else:
                args.username = input("Username: ")
        if not args.password:
            if os.environ.get("RPM_PASSWORD"):
                args.password = os.environ.get("RPM_PASSWORD")
            else:
                import getpass

                args.password = getpass.getpass("Password: ")
        credentials = (args.username, args.password)
        print(f"Uploading to: {upload_url}")
        upload_file(upload_url, path, credentials)


if __name__ == "__main__":
    main()
