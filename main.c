/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Brian J. Downs
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdbool.h>

#include <rattler.h>

#include "db.h"
#include "fort.h"

#define STR1(x) #x
#define STR(x) STR1(x)

static const char *list_items[] = {
    "images",
    "teams",
    "reports",
    "severities",
    NULL
};

static const char *reports[] = {
    "top-images-by-vuln-count",
    "images-vulns-by-severity",
    "vulns-by-team",
    "vulns-by-all-teams",
    "images-by-cve",
    "release-debt",
    "release-health",
    NULL
};

static const char *severities[] = {
    "critical",
    "high",
    "medium",
    "low",
    NULL
};

static bool
valid_list_item(const char *item)
{
    for (const char **p = list_items; *p != NULL; p++) {
        if (strcmp(*p, item) == 0) {
            return true;
        }
    }

    return false;
}

static bool
valid_report_item(const char *item)
{
    for (const char **p = reports; *p != NULL; p++) {
        if (strcmp(*p, item) == 0) {
            return true;
        }
    }

    return false;
}

static bool
valid_severity(const char *severity)
{
    for (const char **p = severities; *p != NULL; p++) {
        if (strcmp(*p, severity) == 0) {
            return true;
        }
    }

    return false;
}

static void
list_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    RATTLER_UNUSED(cmd);

    if (argc < 1) {
        fprintf(stderr, "error: missing subcommand\n");
        return;
    }

    if (!valid_list_item(argv[0])) {
        fprintf(stderr, "error: invalid item \"%s\"\n", argv[0]);
        return;
    }

    const char *list_item = argv[0];

    if (strcmp(list_item, "images") == 0) {
        const char *team = rattler_flag_string(cmd, "team");

        if (team != NULL && team[0] != '\0') {
            list_images_by_team(team);
        } else {
            list_images_all();
        }
    } else if (strcmp(list_item, "teams") == 0) {
        list_teams();
    } else if (strcmp(list_item, "severities") == 0) {
        ft_table_t *table = ft_create_table();
        ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
        ft_write_ln(table, "Name");
        for (const char **p = severities; *p != NULL; p++) {
            ft_write_ln(table, *p);
        }

        printf("%s\n", ft_to_string(table));
        ft_destroy_table(table);
    } else if (strcmp(list_item, "reports") == 0) {
        ft_table_t *table = ft_create_table();
        ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
        ft_write_ln(table, "Name");

        for (const char **p = reports; *p != NULL; p++) {
            ft_write_ln(table, *p);
        }

        printf("%s\n", ft_to_string(table));
        ft_destroy_table(table);
    }

    return;
}

static void
reports_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "error: missing subcommand\n");
        return;
    }

    if (!valid_report_item(argv[0])) {
        fprintf(stderr, "error: invalid report \"%s\"\n", argv[0]);
        return;
    }

    const char *report_name = argv[0];

    if (strcmp(report_name, "top-images-by-vuln-count") == 0) {
        top_images_by_vuln_count_report();
    } else if (strcmp(report_name, "images-vulns-by-severity") == 0) {
        const char *severity = rattler_flag_string(cmd, "severity");

        if (!valid_severity(severity)) {
            fprintf(stderr, "error: invalid severity \"%s\"\n", severity);
            return;
        }

        images_vulns_by_severity_report(severity);
    } else if (strcmp(report_name, "vulns-by-team") == 0) {
        const char *team = rattler_flag_string(cmd, "team");

        if (team == NULL || team[0] == '\0') {
            fprintf(stderr, "error: missing required flag -t or --team\n");
            return;
        }

        vulns_by_team_report(team);
    } else if (strcmp(report_name, "vulns-by-all-teams") == 0) {
        vulns_by_all_teams_report();
    } else if (strcmp(report_name, "images-by-cve") == 0) {
        const char *cve = rattler_flag_string(cmd, "cve");

        if (cve == NULL || cve[0] == '\0') {
            fprintf(stderr, "error: missing required flag -c or --cve\n");
            return;
        }

        images_by_cve_report(cve);
    } else if (strcmp(report_name, "release-debt") == 0) {
        const char *release = rattler_flag_string(cmd, "release");
        if (release == NULL || release[0] == '\0') {
            printf("Note: lower debt values are better\n\n");
        }

        release_debt_report(release);
    } else if (strcmp(report_name, "release-health") == 0) {
        const char *release = rattler_flag_string(cmd, "release");
        
        release_health_report(release);

        if (release == NULL || release[0] == '\0') {
            printf("Note: higher health values are better\n\n");
        }
    }

    return;
}

int
main(int argc, char **argv)
{
    rattler_cmd *root = rattler_new_command(
        "war-room [command]",
        "Rancher image-scanning reports CLI",
        "war-room uses the SQLite DB produced by rancher/image-scanning\n"
        "to generate reports and visualizations.\n\n"
        "Required:\n"
        "    export CVE_DB_PATH=/path/to/cve.db\n");
    rattler_set_version(root, "0.1.0");

    rattler_cmd *list = rattler_new_command(
        "list [command]",
        "List available resources",
        "list shows available resources:\n"
        "    images: list all images\n"
        "    teams: list all teams\n"
        "    reports: list all available reports\n"
        "    severities: list all vuln severity levels\n");
    list->cmd = list_cmd;
    rattler_set_args(list, 1, 1);
    rattler_flags_string(list, "team", 't', "", "team name");
    rattler_add_command(root, list);

    rattler_cmd *report = rattler_new_command(
        "report [command]",
        "Run pre-built reports",
        "report runs pre-built reports.\n"
        "Some reports require additional arguments, such as severity level or\n"
        "image name.\n");
    report->cmd = reports_cmd;
    rattler_flags_string(report, "severity", 's', "",
        "severity (critical, high, medium, low)");
    rattler_flags_string(report, "cve", 'c', "", "CVE identifier");
    rattler_flags_string(report, "release", 'r', "", "release tag");
    rattler_flags_string(report, "team", 't', "", "team name");
    rattler_add_command(root, report);

    if (db_init() != 0) {
        fprintf(stderr, "error: failed to initialize database\n");
        return 1;
    }

    rattler_execute(root, argc, argv);
    rattler_free(root);

    db_shutdown();

    return 0;
}
