#ifndef __DB_H
#define __DB_H

#include <sqlite3.h>

int
db_init();

void
list_teams();

void
list_images_all();

void
list_images_by_team(const char *team);

void
top_images_by_vuln_count_report();

void
images_vulns_by_severity_report(const char *severity);

void
vulns_by_team_report(const char *team);

void
vulns_by_all_teams_report();

void
images_by_cve_report(const char *cve);

void
release_debt_report(const char *release);

void
release_health_report(const char *release);

void
db_shutdown();

#endif /** end __DB_H */
