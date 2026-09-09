# Trino 480 → 483 upgrade: feasibility and CVE impact

Branch: `trino-483-upgrade` (from `cve-remediation-480` @ `aa4e4fbbfd0`)
Date: 2026-09-09. Merge performed (`59105047b81`, `fdc9289fafb`), built, image built,
started, and scanned. See "Build results" and "Scan results" below.

## Verdict

**Feasible, and it retires a meaningful share of the fork's CVE patch set.** The
lineage is clean and the conflict surface is small. Two items need deliberate
handling: the Jetty pin **inverts**, and the HDFS filesystem deletions must be
checked against the HopsFS integration.

## Feasibility

Apache's 480 release commit (`0ace945c7bb`) is an ancestor of tag `483`, so the
merge is well-defined. `apache` remote added (`trinodb/trino`), tags 481-483 fetched.

| Measure | Value |
|---|---|
| Fork commits since 480 | 41 |
| Fork-touched files | 66 (2601 +, 1736 −) |
| Upstream 480→483 | 1630 commits, 5240 files (246469 +, 93232 −) |
| Files touched by both | 47 |
| **Actual merge conflicts** | **22 files, 30 hunks** |

Conflict concentration (trial `git merge 483`, then aborted):

- `.github/workflows/ci.yml` — 4 hunks. Fork replaced upstream CI with `Jenkinsfile`;
  resolve as "keep ours", low risk.
- `pom.xml` — 3 hunks. The substantive one; see CVE table below.
- `plugin/trino-iceberg/pom.xml` — 2 hunks. Iceberg 1.10.1 (ours) vs 1.11.0 (483).
- 16 files at 1 hunk each — mostly `hive-apache` dependency swaps in module poms.
- 3 modify/delete conflicts (see risk 2).

Build environment is unchanged: `air.java.version` is 25.0.1 in both 480 and 483,
so the existing JDK 25 Docker build still applies.

### Risk 1 — Jetty pin inverts (must not be carried over blindly)

`CVE_ANALYSIS.md` records "do NOT raise `dep.jetty.version` above 12.1.10" because
airlift 419 calls `setRateControlFactory(org.eclipse.jetty.http2.RateControl$Factory)`.
**483 moves airbase 364 → 395 and airlift 419 → 439.** Verified by decompiling
`io/airlift/http-server/439`: it now calls
`setRateControlFactory(org.eclipse.jetty.io.RateControl$Factory)` — the *new*
location. airbase 395 ships `dep.jetty.version` 12.1.11 to match.

So on 483 the constraint reverses: **carrying our 12.1.10 pin forward reproduces the
same `NoSuchMethodError` it was written to prevent.** Drop the pin, inherit 12.1.11.
CVE-2026-10050 stays fixed (12.1.11 > 12.1.10). This must be started, not just built,
to confirm — it is the same failure mode a compile-only check missed before.

### Risk 2 — trino-hdfs deletions vs HopsFS

Upstream deleted 66 files from `lib/trino-hdfs` (−10394 lines): the legacy Hadoop
`gcs/`, `azure/`, `cos/` filesystem support. Two fork-modified files are among them,
producing modify/delete conflicts:

- `hdfs/azure/TrinoAzureConfigurationInitializer.java` (deleted upstream)
- `hdfs/s3/TestS3HadoopPaths.java` (deleted upstream)

Both fork edits there are small and incidental. The load-bearing HopsFS files all
survive in 483 and merged cleanly: `HdfsConfigurationInitializer.java`,
`CachingKerberosHadoopAuthentication.java`, `KerberosHadoopAuthentication.java`.
Confirm nothing in the Hops integration imports the deleted `azure`/`gcs`/`cos`
packages before resolving these as "take upstream's deletion".

### Risk 3 — Hive 4 / Hudi 1.2 semantics

The fork's largest investment (HWORKS-2879: Hive 4, Hudi 1.2, Spark 4.1) touches
`plugin/trino-hive`, `plugin/trino-hudi`, `lib/trino-metastore`,
`lib/trino-hive-formats`. None of those Java files conflicted, but upstream churn
behind them is heavy — `plugin/trino-hive` alone is 242 files / 4574 insertions.
A clean merge here is not evidence of semantic compatibility; this is where the
real integration testing effort goes, not in conflict resolution.

### Bonus — the Redshift patch disappears

483 carries `LegacyRedshiftConnectionImpl`, `LegacyRedshiftDatabaseMetaData` and
`LegacyRedshiftDriver` itself, **byte-identical to the fork's copies**;
`RedshiftClientModule` differs by one blank line. That fork patch is fully subsumed
upstream — resolve as "take theirs" and delete the fork delta.

## CVE evaluation on 483

Baseline for `cve_report.txt` is the `hopsworks/trino:480-v8` image (81 rows).
What 483 provides natively versus what the fork must keep:

| Package | Report | Our fix | 483 provides | Action on 483 |
|---|---|---|---|---|
| `jackson-databind` (2.x) | 2.21.2 | 2.21.6 | **2.22.1** (airbase 395) | **Drop override** — ours is now a downgrade |
| `tools.jackson` (3.x) | 3.1.0 | 3.1.6 | **3.2.1** (airbase 395) | **Drop override** |
| `jetty-security` | 12.1.7 | 12.1.10 | **12.1.11** (airbase 395) | **Drop pin** — see Risk 1 |
| `postgresql` | 42.7.10 | 42.7.13 | **42.7.13** | Drop override (no-op) |
| `ignite-core` | 2.17.0 | 2.18.0 | **2.18.0** | Drop override (no-op) |
| `redshift-jdbc42` | 2.1.0.30 | 2.2.8 | 2.2.7 | **Keep** ours (2.2.8 > 2.2.7) |
| `netty` | 4.2.10 | 4.2.17 | 4.2.16 | **Keep** ours — 39 rows depend on it |
| `httpclient5` | 5.6 | 5.6.4 | 5.6.2 | **Keep** ours |
| `libthrift` | 0.22.0 | 0.24.0 | 0.23.0 | **Keep** ours |
| `wire-runtime-jvm` | 6.0.0 | 6.4.7 | 6.4.0 | **Keep** ours |
| `micrometer-core` | 1.16.2 | 1.16.7 (bom) | not managed | **Keep** our bom import |
| `jetty-http` (Ranger) | 11.0.26 | dependency removed | **still 11.0.26** | **Re-apply removal** |
| Go `stdlib` / `x/text` | v1.26.1 | launcher 321 | launcher **318** | **Keep** ours (321 > 318) |

### Headline numbers

- **5 of 13 override groups retire** (jackson 2.x, jackson 3.x, jetty 12, postgresql,
  ignite) plus the entire Redshift source patch. That is the strongest argument for
  the upgrade beyond feature currency.
- **8 groups must be carried forward** — 483 is *behind* the fork on netty,
  httpclient5, libthrift, wire, redshift and the Go launcher, and does not manage
  micrometer at all. Upgrading without re-applying these **regresses** those rows.
- **CVE-2026-2332 is not fixed by 483.** `plugin/trino-ranger/pom.xml` at 483 still
  pins `dep.jetty11.version` 11.0.26 and still declares `ranger-audit-dest-solr`, on
  Ranger 2.8.0 — unchanged from 480. The Solr removal (`5a2d8062e91`) and its docs
  (`aa4e4fbbfd0`) must be re-applied; the pom conflicts, so this will not slip through
  silently. Dropping the whole Ranger plugin remains the better long-term answer.
- The 20 accepted Go stdlib rows are unaffected — still gated on a launcher built
  with go1.26.6+, which 483 does not provide.

## Recommended sequence

1. Merge `483`, resolving CI/Jenkins and hive-apache pom conflicts as "keep ours".
2. Take upstream for all of `plugin/trino-redshift` except the 2.2.8 version bump.
3. Rewrite the root-pom override block to the "keep" column above — **delete the
   jetty pin** and both jackson overrides.
4. Re-apply the Ranger Solr/Jetty 11 removal.
5. Audit the HopsFS integration against the deleted `trino-hdfs` filesystem packages.
6. Build **and start** the image; re-scan to confirm the row count does not regress.

## Build results (2026-09-09)

`mvn -T1C -DskipTests -Dair.check.skip-all=true clean install -pl '!docs'` in the
`maven:3.9-eclipse-temurin-25` container: **BUILD SUCCESS, 111 modules, 0 failures**
(2:45). Two problems were hit and resolved on the way:

### One real fork/upstream API gap

`trino-hdfs` testCompile failed. 483 adds `TestCachingKerberosHadoopAuthentication`
(absent in 480) which calls `UserGroupInformation.createUserGroupInformationForSubject`.
`javap` on `io.hops.hadoop:hadoop-apache:3.4.3.2-EE-RC3` confirms that method does not
exist there; the Hops UGI exposes `getUGIFromSubject(Subject)` instead, which throws a
checked `IOException`. Adapted in `fdc9289fafb`. This is the predicted Risk 3 class of
problem, and note it surfaced in the *HopsFS* integration rather than in Hive/Hudi —
a clean merge is genuinely not evidence of semantic compatibility.

### One environment failure, not a code problem

`trino-docs` fails `run-sphinx` with exit 127 — sphinx is not installed in the Maven
container. Pre-existing, unrelated to 483, excluded with `-pl '!docs'`.

### Stale-target contamination (process lesson)

The first passing build was run without `clean`, and `lib/trino-hdfs/target/` still
held output from the Sep 8 build of 480. The assembly globbed both generations into
`trino-hdfs-483.zip`, so `plugin/*/hdfs/` shipped **Jetty 12.1.10 and 12.1.11 side by
side** with current timestamps. `dependency:tree` resolved uniformly to 12.1.11 — only
the packaging was wrong. Scanning that tree would have produced duplicate Jetty rows
and an easily-misread CVE-2026-10050 signal. **Always `clean` before packaging or
scanning this repo.**

### Verified jar inventory (clean build)

Read out of `core/trino-server/target/trino-server-483`, confirming the override plan
landed as intended rather than trusting the poms:

| Expected | Found in distribution |
|---|---|
| Jetty uniformly 12.1.11 | 671 jars, all 12.1.11; **zero** Jetty 11 |
| Solr audit destination gone | **zero** solr jars |
| jackson from airbase 395 | 2.22.1 and 3.2.1 |
| netty override kept | 4.2.17 |
| launcher override kept | `golang.org/x/text@v0.40.0` (= launcher 321) |
| httpclient5 / libthrift / wire | 5.6.4 / 0.24.0 / 6.4.7 |
| micrometer / postgresql / ignite | 1.16.7 / 42.7.13 / 2.18.0 |
| redshift driver | 2.2.8 |

Every row of the CVE table above is now confirmed at the artifact level. This is not a
substitute for a scan: it verifies versions, not that the scanner agrees, and it says
nothing about runtime behaviour.

## Image build, startup and scan (2026-09-09)

Image `hopsworks/trino:483-test`, linux/amd64, JDK `jdk-25.0.3+9`. `core/docker/build.sh`
was bypassed — it calls `mvnw help:evaluate` to derive the version and JDK, which would
run under the host's JDK 8 — and `docker build` was invoked directly with the values the
script would have computed.

**The coordinator starts.** `container-test.sh` passed: the container reached its
`HEALTHCHECK` healthy state and answered `SELECT 'success'`. This is the check that
bytecode inspection could not give — the Jetty **12.1.11 + airlift 439** pairing works at
runtime, with no `NoSuchMethodError` on `setRateControlFactory`. Dropping the 12.1.10 pin
was correct; carrying it forward would have failed precisely here.

### Scan results

Trivy `--scanners vuln --severity HIGH,CRITICAL`, matching the baseline's severity range.
Full output in `cve_report_483.txt`.

| | Baseline `480-v8` | This build |
|---|---|---|
| HIGH+CRITICAL rows | 80 | **10** |
| Distinct (CVE, package) | 78 | 10 |
| Resolved | — | **68** |
| **Newly introduced** | — | **0** |

Zero OS-level HIGH/CRITICAL rows (ubi10-micro), and every Java row from the baseline is
gone except the ClickHouse pair below — netty, jackson (both trees), jetty 12, the Ranger
Jetty 11 row (CVE-2026-2332), redshift, postgresql, ignite, libthrift, wire, micrometer
and httpclient5 all clear.

The 10 remaining rows are exactly the two categories already accepted in
`CVE_ANALYSIS.md`, and nothing else:

1. **8 Go stdlib rows** in `bin/linux-amd64/launcher`, go1.26.5, all fixed in go1.26.6+.
   The baseline had 20; launcher 321 cleared 12. This matches the earlier prediction
   exactly — "the remaining 8 need a launcher built with go1.26.6+".
2. **2 ClickHouse rows** — CVE-2026-54399 / CVE-2026-54428, `httpcore5` and
   `httpcore5-h2` at 5.3.4, **shaded inside** `com.clickhouse_clickhouse-jdbc-0.9.8-all.jar`.
   Dependency management cannot reach them: every standalone `httpcore5` jar in the
   distribution is 5.4.3. 483 improves this (480 shaded 5.2.1/5.2 via clickhouse-jdbc
   0.7.1-patch1) but still lands short of the 5.4.3 fix. The `-all` classifier problem
   and its two rejected workarounds are unchanged from `CVE_ANALYSIS.md`.

### Still outstanding

1. Tests have never run (`-DskipTests` throughout), nor style/enforcer checks
   (`air.check.skip-all=true`). The startup test exercises one query, not the connectors —
   in particular nothing here tests Hive 4 / Hudi 1.2 behaviour, which is where the
   fork's real risk lives.
2. Only linux/amd64 was built; the release builds arm64 and ppc64le too.
3. `trino-iceberg` at 483 adds `bannedDependencies` excludes naming
   `io.trino.hadoop:hadoop-apache` and `io.trino.hive:hive-apache`. These were left
   pointing at the upstream coordinates rather than rewritten to `io.hops.*`, since
   rewriting risked banning the fork's own test dependencies. Worth a human decision.
4. `trino-docs` remains unbuilt in this environment.
