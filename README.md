# War Room

war_room is a simple CLI that provides insights into the Rancher Image Scanning CVE database. 

The user interface is a CLI flow using `librattler` which was inspired by `spf13/cobra`.

## Build and Install

Pre-Requisite

```sh
git clone --depth 1 https://github.com/briandowns/librattler && \
cd librattler && \
make && make install && \
sudo ldconfig
```

```sh
make && sudo make install
```

## Examples

List reports

```sh
war_room list reports
+--------------------------+
| Name                     |
+--------------------------+
| top-images-by-vuln-count |
| images-vulns-by-severity |
| vulns-by-team            |
| vulns-by-all-teams       |
| images-by-cve            |
| release-debt             |
| release-health           |
+--------------------------+
```

Run a report

```sh
war_room report images-by-cve -c CVE-2026-9999
+--------------------------------------------------------+------------------+--------------------------+
| Image                                                  | Package Name     | Package Version          |
+--------------------------------------------------------+------------------+--------------------------+
| rancher/mirrored-grafana-grafana-image-renderer:v5.1.0 | chromium         | 143.0.7499.109-1~deb13u1 |
| rancher/mirrored-grafana-grafana-image-renderer:v5.1.0 | chromium-common  | 143.0.7499.109-1~deb13u1 |
| rancher/mirrored-grafana-grafana-image-renderer:v5.1.0 | chromium-driver  | 143.0.7499.109-1~deb13u1 |
| rancher/mirrored-grafana-grafana-image-renderer:v5.1.0 | chromium-sandbox | 143.0.7499.109-1~deb13u1 |
| rancher/mirrored-grafana-grafana-image-renderer:v5.1.0 | chromium-shell   | 143.0.7499.109-1~deb13u1 |
+--------------------------------------------------------+------------------+--------------------------+
```

## Docker

```sh
make image
```

Run

```sh
docker run --rm -it -v "${GOPATH}/src/github.com/briandowns/image-scanning/artifacts/cvedb":/data -w /data -e CVE_DB_PATH="/data/cves.db" briandowns/war_room:latest list teams
```

## Contributing

Please feel free to open a PR!

## License

BSD 2 Clause [License](/LICENSE).
