%{!?pkg_version:%global pkg_version 0.0.0}
%{!?python_pkg:%global python_pkg python3.12}
%{!?src_dir:%global src_dir /src}
%{!?app_root:%global app_root /opt/tsd-file-api}

# The package is a self-contained virtualenv with absolute paths.
%global __brp_check_rpaths %{nil}
%undefine __brp_mangle_shebangs
%global __requires_exclude ^%{app_root}/
%global __brp_python_bytecompile %{nil}
%global __provides_exclude_from ^%{app_root}/.*$
%global debug_package %{nil}

Name:           tsd-file-api
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        TSD File API
License:        BSD-3-Clause
URL:            https://github.com/unioslo/tsd-file-api

Requires:       %{python_pkg}
Requires:       file-libs
Requires:       libpq
Requires:       libsodium
Requires:       sudo
Requires(posttrans): findutils

%description
REST API for upload and download of files and JSON data, packaged with a
self-contained Python virtualenv.

%prep
mkdir -p %{_builddir}/%{name}-%{version}
cp -a %{src_dir}/. %{_builddir}/%{name}-%{version}/

%build
cd %{_builddir}/%{name}-%{version}
export POETRY_DYNAMIC_VERSIONING_BYPASS=%{pkg_version}
poetry env use %{python_pkg}
poetry export --without-hashes --format requirements.txt --output requirements.txt
poetry build -f wheel

%install
cd %{_builddir}/%{name}-%{version}
app_root=%{buildroot}%{app_root}
virtualenv -p %{python_pkg} "$app_root"
"$app_root/bin/pip" install --upgrade pip
"$app_root/bin/pip" install -r requirements.txt
"$app_root/bin/pip" install --no-index --find-links dist tsdfileapi

find "$app_root" -type f -name '*.pyc' -delete
find "$app_root" -type d -name '__pycache__' -empty -delete

# Rewrite the temporary buildroot paths captured by the venv.
grep -rlI '%{buildroot}' "$app_root" | while IFS= read -r f; do
    sed -i "s|%{buildroot}||g" "$f"
done

%posttrans
# Safety net for upgrades from fpm-built RPMs, which owned files but not
# directories. Remove only empty directories at or below Python metadata dirs.
find %{app_root} -depth -type d -path '*.dist-info/*' -empty -delete || :
find %{app_root} -depth -type d -path '*.egg-info/*' -empty -delete || :
find %{app_root} -type d \( -name '*.dist-info' -o -name '*.egg-info' \) -empty -delete || :

%files
%{app_root}/

%changelog
* %(date "+%a %b %d %Y") TSD <tsd-drift@usit.uio.no> - %{pkg_version}-1
- Automated build of %{pkg_version}
