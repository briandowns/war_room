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

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>

#include "report.h"
#include "fort.h"

#define TEAMS_QUERY "WITH RECURSIVE split(team_name, remainder) AS (" \
    "SELECT " \
        "TRIM(substr(team, 1, instr(team || ',', ',') - 1)) AS team_name, " \
        "substr(team, instr(team || ',', ',') + 1) AS remainder " \
    "FROM images " \
    "WHERE team IS NOT NULL AND team != '' " \
    "UNION ALL " \
    "SELECT " \
        "TRIM(substr(remainder, 1, instr(remainder || ',', ',') - 1)) AS team_name, " \
        "substr(remainder, instr(remainder || ',', ',') + 1) AS remainder " \
    "FROM split " \
    "WHERE remainder != '' " \
    ")" \
    "SELECT DISTINCT team_name " \
    "FROM split " \
    "WHERE team_name != '' " \
    "ORDER BY team_name;"
#define TOP_IMAGES_BY_VULN_COUNT_QUERY "SELECT " \
    "image, " \
    "CAST(SUM(severity='CRITICAL') AS TEXT) AS critical, " \
    "CAST(SUM(severity='HIGH') AS TEXT) AS high, " \
    "CAST(SUM(severity='MEDIUM') AS TEXT) AS medium, " \
    "CAST(SUM(severity='LOW') AS TEXT) AS low, " \
    "CAST(COUNT(*) AS TEXT) AS total " \
    "FROM findings " \
    "WHERE status != 'fixed' " \
    "GROUP BY image " \
    "ORDER BY total DESC;"
#define IMAGE_VULNS_BY_SEVERITY_QUERY "SELECT " \
    "DISTINCT(image), vulnerability_id FROM findings " \
    "WHERE severity = :severity " \
    "ORDER BY image;"
#define IMAGES_ALL_QUERY "SELECT DISTINCT(image) FROM images;"
#define IMAGES_BY_TEAM_QUERY "SELECT DISTINCT(image) FROM images WHERE team = :team;"
#define VULNS_BY_ALL_TEAMS_QUERY "SELECT " \
    "i.team, " \
    "CAST(SUM(f.severity='CRITICAL') AS TEXT) AS critical, " \
    "CAST(SUM(f.severity='HIGH') AS TEXT) AS high, " \
    "CAST(SUM(f.severity='MEDIUM') AS TEXT) AS medium, " \
    "CAST(SUM(f.severity='LOW') AS TEXT) AS low, " \
    "CAST(COUNT(*) AS TEXT) AS total " \
    "FROM findings f " \
    "JOIN images i " \
    "ON f.image=i.image " \
    "WHERE f.status != 'fixed' " \
    "GROUP BY i.team " \
    "ORDER BY total DESC;"
#define VULNS_BY_TEAM_QUERY "SELECT " \
    "i.team, " \
    "CAST(SUM(f.severity='CRITICAL') AS TEXT) AS critical, " \
    "CAST(SUM(f.severity='HIGH') AS TEXT) AS high, " \
    "CAST(SUM(f.severity='MEDIUM') AS TEXT) AS medium, " \
    "CAST(SUM(f.severity='LOW') AS TEXT) AS low, " \
    "CAST(COUNT(*) AS TEXT) AS total " \
    "FROM findings f " \
    "JOIN images i " \
    "ON f.image=i.image " \
    "WHERE f.status != 'fixed' " \
    "AND i.team = :team " \
    "GROUP BY i.team " \
    "ORDER BY total DESC;"
#define IMAGES_BY_CVE_QUERY "SELECT " \
    "image, " \
    "package_name, " \
    "package_version " \
    "FROM findings " \
    "WHERE vulnerability_id = :cve " \
    "ORDER BY image;"
#define RELEASE_DEBT_QUERY "SELECT " \
    "release, " \
    "CAST((critical * 25) + " \
    "(high * 10) + " \
    "(medium * 3) + " \
    "low AS TEXT) AS debt " \
    "FROM release_stats " \
    "ORDER BY debt DESC;"
#define RELEASE_DEBT_BY_RELEASE_QUERY "SELECT " \
    "release, " \
    "CAST((critical * 25) + " \
    "(high * 10) + " \
    "(medium * 3) + " \
    "low AS TEXT) AS debt " \
    "FROM release_stats " \
    "WHERE release = :release ;"
#define RELEASE_HEALTH_QUERY "WITH debt AS ( " \
    "SELECT " \
        "release, " \
        "(critical * 25) + " \
        "(high * 10) + " \
        "(medium * 3) + " \
        "low AS debt " \
    "FROM release_stats " \
    "), " \
    "max_debt AS ( " \
        "SELECT MAX(debt) AS value " \
        "FROM debt " \
    ") " \
    "SELECT " \
        "d.release, " \
        "CAST(d.debt AS TEXT), " \
        "ROUND( " \
            "CASE " \
                "WHEN m.value = 0 THEN 100 " \
                "ELSE (1.0 - (CAST(d.debt AS REAL) / m.value)) * 100 " \
            "END, " \
            "1 " \
        ") AS health " \
    "FROM debt d " \
    "CROSS JOIN max_debt m " \
    "ORDER BY health DESC;"
#define RELEASE_HEALTH_BY_RELEASE_QUERY "WITH debt AS ( " \
    "SELECT " \
        "release, " \
        "(critical * 25) + " \
        "(high * 10) + " \
        "(medium * 3) + " \
        "low AS debt " \
    "FROM release_stats " \
    "), " \
    "max_debt AS ( " \
        "SELECT MAX(debt) AS value " \
        "FROM debt " \
    ") " \
    "SELECT " \
        "d.release, " \
        "CAST(d.debt AS TEXT), " \
        "ROUND( " \
            "CASE " \
                "WHEN m.value = 0 THEN 100 " \
                "ELSE (1.0 - (CAST(d.debt AS REAL) / m.value)) * 100 " \
            "END, " \
            "1 " \
        ") AS health " \
    "FROM debt d " \
    "CROSS JOIN max_debt m " \
    "WHERE d.release = :release " \
    "ORDER BY health DESC;"
#define WORST_PACKAGES_QUERY "SELECT " \
    "package_name, " \
    "COUNT(*) AS occurrences, " \
    "COUNT(DISTINCT vulnerability_id) AS unique_cves " \
    "FROM findings " \
    "WHERE status != 'fixed' " \
    "GROUP BY package_name " \
    "ORDER BY occurrences DESC;"
#define PACKAGES_WITH_UPGRADE_QUERY "SELECT " \
    "package_name, " \
    "package_version, " \
    "patched_version, " \
    "COUNT(*) AS affected " \
    "FROM findings " \
    "WHERE " \
    "patched_version != '' " \
    "AND status != 'fixed' " \
    "GROUP BY " \
    "package_name, " \
    "package_version, " \
    "patched_version " \
    "ORDER BY affected DESC;"
#define PACKAGE_WITH_UPGRADE_QUERY "SELECT " \
    "package_name, " \
    "package_version, " \
    "patched_version, " \
    "COUNT(*) AS affected " \
    "FROM findings " \
    "WHERE " \
    "package_name = :package_name " \
    "AND patched_version != '' " \
    "AND status != 'fixed' " \
    "GROUP BY " \
    "package_name, " \
    "package_version, " \
    "patched_version " \
    "ORDER BY affected DESC;"

static sqlite3 *db = NULL;

static void
to_upper(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        str[i] = (char)toupper((unsigned char)str[i]);
    }
}

int
report_init()
{
    char *path_value = getenv("CVE_DB_PATH");

    if (path_value == NULL) {
        fprintf(stderr, "error: CVE_DB_PATH environment variable not set.\n");
        return 1;
    }

    if (sqlite3_open(path_value, &db) != SQLITE_OK) {
        fprintf(stderr, "error: failed to open db: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        db = NULL;

        return 1;
    }
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);

    return 0;
}

void
report_shutdown()
{
    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
    }
}

void
report_list_images_all()
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, IMAGES_ALL_QUERY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Name");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 0);
        ft_write_ln(table, (const char *)name);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_list_images_by_team(const char *team)
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, IMAGES_BY_TEAM_QUERY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    int param_index = sqlite3_bind_parameter_index(stmt, ":team");
    if (param_index == 0) {
        fprintf(stderr, "parameter ':team' not found in statement\n");
        sqlite3_finalize(stmt);
        return;
    }
    sqlite3_bind_text(stmt, param_index, team, -1, SQLITE_STATIC);

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Name");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 0);
        ft_write_ln(table, (const char *)name);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_list_teams()
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, TEAMS_QUERY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Name");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 0);
        ft_write_ln(table, (const char *)name);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_top_images_by_vuln_count()
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, TOP_IMAGES_BY_VULN_COUNT_QUERY, -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Image", "Critical", "High", "Medium", "Low", "Total");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *image = sqlite3_column_text(stmt, 0);
        const unsigned char *critical = sqlite3_column_text(stmt, 1);
        const unsigned char *high = sqlite3_column_text(stmt, 2);
        const unsigned char *medium = sqlite3_column_text(stmt, 3);
        const unsigned char *low = sqlite3_column_text(stmt, 4);
        const unsigned char *total = sqlite3_column_text(stmt, 5);

        ft_write_ln(table, (const char *)image, (const char *)critical,
            (const char *)high, (const char *)medium, (const char *)low,
            (const char *)total);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_images_vulns_by_severity(const char *severity)
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, IMAGE_VULNS_BY_SEVERITY_QUERY, -1, &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    int param_index = sqlite3_bind_parameter_index(stmt, ":severity");
    if (param_index == 0) {
        fprintf(stderr, "parameter ':severity' not found in statement\n");
        sqlite3_finalize(stmt);
        return;
    } 

    to_upper((char*)severity);
    sqlite3_bind_text(stmt, param_index, severity, -1, SQLITE_STATIC);

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, "Name", "Severity");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *image = sqlite3_column_text(stmt, 0);
        const unsigned char *vuln_id = sqlite3_column_text(stmt, 1);

        ft_write_ln(table, (const char *)image, (const char *)vuln_id);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_vulns_by_team(const char *team)
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, VULNS_BY_TEAM_QUERY, -1, &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    int param_index = sqlite3_bind_parameter_index(stmt, ":team");
    if (param_index == 0) {
        fprintf(stderr, "parameter ':team' not found in statement\n");
        sqlite3_finalize(stmt);
        return;
    } 

    sqlite3_bind_text(stmt, param_index, team, -1, SQLITE_STATIC);

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, "Team", "Critical", "High", "Medium", "Low", "Total");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *team_name = sqlite3_column_text(stmt, 0);
        const unsigned char *critical = sqlite3_column_text(stmt, 1);
        const unsigned char *high = sqlite3_column_text(stmt, 2);
        const unsigned char *medium = sqlite3_column_text(stmt, 3);
        const unsigned char *low = sqlite3_column_text(stmt, 4);
        const unsigned char *total = sqlite3_column_text(stmt, 5);

        ft_write_ln(table, (const char *)team_name, (const char *)critical,
            (const char *)high, (const char *)medium, (const char *)low,
            (const char *)total);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_vulns_by_all_teams()
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, VULNS_BY_ALL_TEAMS_QUERY, -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Team", "Critical", "High", "Medium", "Low", "Total");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *team_name = sqlite3_column_text(stmt, 0);
        const unsigned char *critical = sqlite3_column_text(stmt, 1);
        const unsigned char *high = sqlite3_column_text(stmt, 2);
        const unsigned char *medium = sqlite3_column_text(stmt, 3);
        const unsigned char *low = sqlite3_column_text(stmt, 4);
        const unsigned char *total = sqlite3_column_text(stmt, 5);

        ft_write_ln(table, (const char *)team_name, (const char *)critical,
            (const char *)high, (const char *)medium, (const char *)low,
            (const char *)total);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_images_by_cve(const char *cve)
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, IMAGES_BY_CVE_QUERY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    int param_index = sqlite3_bind_parameter_index(stmt, ":cve");
    if (param_index == 0) {
        fprintf(stderr, "parameter ':cve' not found in statement\n");
        sqlite3_finalize(stmt);
        return;
    } 

    sqlite3_bind_text(stmt, param_index, cve, -1, SQLITE_STATIC);

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Image", "Package Name", "Package Version");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *image = sqlite3_column_text(stmt, 0);
        const unsigned char *package_name = sqlite3_column_text(stmt, 1);
        const unsigned char *package_version = sqlite3_column_text(stmt, 2);

        ft_write_ln(table, (const char *)image, (const char *)package_name,
            (const char *)package_version);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_release_debt(const char *release)
{
    sqlite3_stmt *stmt;
    int rc = 0;
    
    if (release != NULL && release[0] != '\0') {
        rc = sqlite3_prepare_v2(db, RELEASE_DEBT_BY_RELEASE_QUERY, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s\n", sqlite3_errmsg(db));
            return;
        }

        int param_index = sqlite3_bind_parameter_index(stmt, ":release");
        if (param_index == 0) {
            fprintf(stderr, "parameter ':release' not found in statement\n");
            sqlite3_finalize(stmt);
            return;
        } 

        sqlite3_bind_text(stmt, param_index, release, -1, SQLITE_STATIC);
    } else {
        rc = sqlite3_prepare_v2(db, RELEASE_DEBT_QUERY, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s\n", sqlite3_errmsg(db));
            return;
        }
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Release", "Debt");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *release = sqlite3_column_text(stmt, 0);
        const unsigned char *debt = sqlite3_column_text(stmt, 1);

        ft_write_ln(table, (const char *)release, (const char *)debt);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_release_health(const char *release)
{
    sqlite3_stmt *stmt;
    int rc = 0;
    
    if (release != NULL && release[0] != '\0') {
        rc = sqlite3_prepare_v2(db, RELEASE_HEALTH_BY_RELEASE_QUERY, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s\n", sqlite3_errmsg(db));
            return;
        }

        int param_index = sqlite3_bind_parameter_index(stmt, ":release");
        if (param_index == 0) {
            fprintf(stderr, "parameter ':release' not found in statement\n");
            sqlite3_finalize(stmt);
            return;
        } 

        sqlite3_bind_text(stmt, param_index, release, -1, SQLITE_STATIC);
    } else {
        rc = sqlite3_prepare_v2(db, RELEASE_HEALTH_QUERY, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s\n", sqlite3_errmsg(db));
            return;
        }
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Release", "Debt", "Health");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *release = sqlite3_column_text(stmt, 0);
        const unsigned char *debt = sqlite3_column_text(stmt, 1);
        const unsigned char *health = sqlite3_column_text(stmt, 2);

        ft_write_ln(table, (const char *)release, (const char *)debt, (const char *)health);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_worst_packages()
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, WORST_PACKAGES_QUERY, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        return;
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Package", "Occurances");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *package_name = sqlite3_column_text(stmt, 0);
        const unsigned char *occurances = sqlite3_column_text(stmt, 1);

        ft_write_ln(table, (const char *)package_name, (const char *)occurances);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void
report_packages_with_upgrades(const char *package_name)
{
    sqlite3_stmt *stmt;
int rc = 0;
    
    if (package_name != NULL && package_name[0] != '\0') {
        rc = sqlite3_prepare_v2(db, PACKAGE_WITH_UPGRADE_QUERY, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s\n", sqlite3_errmsg(db));
            return;
        }

        int param_index = sqlite3_bind_parameter_index(stmt, ":package_name");
        if (param_index == 0) {
            fprintf(stderr, "parameter ':package_name' not found in statement\n");
            sqlite3_finalize(stmt);
            return;
        } 

        sqlite3_bind_text(stmt, param_index, package_name, -1, SQLITE_STATIC);
    } else {
        rc = sqlite3_prepare_v2(db, PACKAGES_WITH_UPGRADE_QUERY, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s\n", sqlite3_errmsg(db));
            return;
        }
    }

    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE,
        FT_ROW_HEADER);
    ft_write_ln(table, "Package", "Version", "Patched Version", "Affected");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *package_name = sqlite3_column_text(stmt, 0);
        const unsigned char *version = sqlite3_column_text(stmt, 1);
        const unsigned char *patched_version = sqlite3_column_text(stmt, 2);
        const unsigned char *affected = sqlite3_column_text(stmt, 3);

        ft_write_ln(table, (const char *)package_name, (const char *)version,
            (const char *)patched_version, (const char *)affected);
    }
    sqlite3_finalize(stmt);

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}
