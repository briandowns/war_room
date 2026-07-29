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
sudo make install
```

## Examples

List reports

```sh
war_room list reports
+--------------------------+----------------------------------------------+
| Name                     | Description                                  |
+--------------------------+----------------------------------------------+
| top-images-by-vuln-count | Top images by vulnerability count            |
| images-vulns-by-severity | Images and their vulnerabilities by severity |
| vulns-by-team            | Vulnerabilities by team                      |
| vulns-by-all-teams       | Vulnerabilities by all teams                 |
| images-by-cve            | Images affected by a specific CVE            |
| release-debt             | Release debt report                          |
| release-health           | Release health report                        |
| release-stats-by-release | Release stats by release report              |
| worst-packages           | Worst packages report                        |
| packages-with-upgrades   | Packages with upgrades report                |
| vex-effectiveness        | VEX effectiveness report                     |
+--------------------------+----------------------------------------------+
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

### Style

Please match existing code style.

File includes are grouped into 3 sections. The first are standard library includes, the second is for 3rd party libraries, and the third is for local project specific libraries.

### Add a New Report

Adding a new report or fairly starightforward.

1. Add the new report name and description to the `struct report reports` array at the top fo main.c
2. Add a new query macro to report.c
3. Add new function call prototype for the query in report.h 
4. Implement new function in report.c
5. Extend `else if` block in the `reports_cmd` function to match the report name in step 1 and add a call to the function defined in reports.h
6. Build and run `war_room list reports` and update the README.md with the new output.

There are already a number of useful flags defined for the `release` command and can be easily integrated into new report calls.

Please feel free to open a PR!

## License

BSD 2 Clause [License](/LICENSE).
