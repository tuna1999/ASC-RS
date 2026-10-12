/*
 * API-35 URI-relative-filter-group ORACLE — Robolectric (Android 15 / API 35).
 *
 * Read this only as the reference implementation: it MUST be run on a real
 * android-15 framework build before its output is treated as authoritative.
 * It did NOT run on this machine (no JDK / Android SDK / Gradle) — see
 * README.md. Every verdict this file could contribute is therefore
 * UNVERIFIED until a maintainer runs it (and the harness refuses to confirm
 * anything such an unverified build produced).
 *
 * It mirrors asc-rs `evaluate_filter_uri` over tests/fixtures/uri_match_cases.json
 * and writes a JSON report:
 *     { "verdicts": { case_id: "matches"|"cannot_match", ... },
 *       "provenance": { "framework": "android-15.0.0_r1", "api_level": 35,
 *                       "status": "RUN"|"UNVERIFIED_SKIPPED",
 *                       "flag_state_actual": bool|null,
 *                       "flag_skipped": [case_id, ...],
 *                       "flag_mechanism": "...", "robolectric": "...",
 *                       "fixtures": "...", "output": "..." } }
 *
 * The framework's `IntentFilter.matchData` is DETERMINISTIC: it returns >=0
 * match categories for a match and <0 for a rejection — it has no "unknown".
 * An ASC-RS `unknown` row (pattern/advanced glob, opaque URI, bound overflow)
 * therefore has no direct `matchData` answer; the harness records that
 * divergence as a real finding (ORACLE-OPEN) and never as "the oracle also
 * says unknown".
 *
 * v0.19.2 correctness audit (flag state is VERIFIED, not assumed):
 *  - scheme is derived from the INPUT URI (Uri.parse(uri).getScheme()), not
 *    from the filter's <data> — `matchData(type, scheme, data)`'s scheme
 *    argument is the incoming URI's scheme, not a filter property.
 *  - The group-aware branch of AOSP `matchData` is gated by the frozen
 *    build-time aconfig flag `android.content.pm.Flags.relativeReferenceIntentFilters()`,
 *    which a Robolectric test cannot toggle at runtime. This test therefore
 *    READS the build's ACTUAL flag state and only emits a verdict for a case
 *    whose required `flag_on` equals it. Every other case lands in
 *    `flag_skipped`. If the flag state cannot be read at all, the test FAILS
 *    (fail closed): no verdicts are written and `status` is UNVERIFIED_SKIPPED.
 *    A file that cannot prove its flag state is rejected by the runner.
 *  - output path and fixture path come from system properties so the Gradle
 *    task and the README recipe agree (no copy of the fixture).
 */

package us.ascrs.urioracle;

import android.content.IntentFilter;
import android.content.UriRelativeFilter;
import android.content.UriRelativeFilterGroup;
import android.content.pm.Flags;
import android.net.Uri;
import android.os.PatternMatcher;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public class UriOracle {
    static final String FRAMEWORK = "android-15.0.0_r1";
    static final int API_LEVEL = 35;

    static final int PATH = 0, QUERY = 1, FRAGMENT = 2; // UriRelativeFilter constants
    static final int[] KINDS = {PatternMatcher.PATTERN_LITERAL, PatternMatcher.PATTERN_PREFIX,
        PatternMatcher.PATTERN_SUFFIX, PatternMatcher.PATTERN_SIMPLE_GLOB, PatternMatcher.PATTERN_ADVANCED_GLOB};

    static int partId(String s) {
        return "query".equals(s) ? QUERY : "fragment".equals(s) ? FRAGMENT : PATH;
    }

    static int kindOf(int i) {
        return KINDS[i];
    }

    static void addPath(IntentFilter flt, String v, int k) {
        flt.addDataPath(v, k);
    }

    static IntentFilter buildFilter(JSONObject f) throws Exception {
        IntentFilter flt = new IntentFilter();
        JSONArray data = f.getJSONArray("data");
        for (int i = 0; i < data.length(); i++) {
            JSONObject d = data.getJSONObject(i);
            if (d.has("scheme")) flt.addDataScheme(d.getString("scheme"));
            if (d.has("host")) {
                flt.addDataAuthority(d.getString("host"),
                        d.has("port") ? d.getString("port") : null);
            }
            if (d.has("path")) addPath(flt, d.getString("path"), PatternMatcher.PATTERN_LITERAL);
            if (d.has("path_prefix")) addPath(flt, d.getString("path_prefix"), PatternMatcher.PATTERN_PREFIX);
            if (d.has("path_pattern")) addPath(flt, d.getString("path_pattern"), PatternMatcher.PATTERN_SIMPLE_GLOB);
            if (d.has("path_advanced_pattern")) addPath(flt, d.getString("path_advanced_pattern"), PatternMatcher.PATTERN_ADVANCED_GLOB);
            if (d.has("path_suffix")) addPath(flt, d.getString("path_suffix"), PatternMatcher.PATTERN_SUFFIX);
        }
        JSONArray groups = f.optJSONArray("groups");
        if (groups != null) {
            for (int g = 0; g < groups.length(); g++) {
                JSONObject grp = groups.getJSONObject(g);
                UriRelativeFilterGroup ufg =
                    new UriRelativeFilterGroup(grp.optBoolean("allow", true)
                        ? UriRelativeFilterGroup.ACTION_ALLOW : UriRelativeFilterGroup.ACTION_BLOCK);
                JSONArray gd = grp.getJSONArray("data");
                for (int d = 0; d < gd.length(); d++) {
                    JSONArray parts = gd.getJSONObject(d).getJSONArray("parts");
                    for (int p = 0; p < parts.length(); p++) {
                        JSONObject m = parts.getJSONObject(p);
                        int kind = m.optString("kind", "exact") switch {
                            "prefix" -> 1, "suffix" -> 2,
                            "pattern" -> 3, "advanced" -> 4, default -> 0
                        };
                        ufg.addUriRelativeFilter(new UriRelativeFilter(
                            partId(m.getString("part")), kindOf(kind), m.getString("value")));
                    }
                }
                flt.addUriRelativeFilterGroup(ufg);
            }
        }
        return flt;
    }

    /**
     * The build's ACTUAL frozen aconfig flag state that gates the group-aware
     * branch of `IntentFilter.matchData`. Returns null only if the generated
     * flags class cannot be read (build mismatch) — the caller must fail
     * closed then, never assume a value.
     */
    static Boolean actualFlagOn() {
        try {
            return Flags.relativeReferenceIntentFilters();
        } catch (Throwable t) {
            // LinkageError / missing generated method / any reflection failure.
            return null;
        }
    }

    /**
     * Deterministic framework verdict for one URI under this build's flag state.
     * The group-aware vs legacy branch is taken by the framework build's frozen
     * FLAG_RELATIVE_REFERENCE_INTENT_FILTERS, NOT by the caller — so this method
     * is only ever invoked for a case whose required `flag_on` equals
     * `flag_state_actual` (checked by the caller).
     */
    static String match(IntentFilter flt, String uri) {
        Uri u = Uri.parse(uri);
        // AOSP matchData(type, scheme, data): `scheme` is the INCOMING URI's
        // scheme, not a filter property (a filter can pool several schemes).
        String scheme = u.getScheme();
        int r = flt.matchData(null, scheme, u);
        return r >= 0 ? "matches" : "cannot_match";
    }

    @Test
    public void emitOracleVerdicts() throws Exception {
        String fixturePath = System.getProperty("uri.fixtures", "/uri_match_cases.json");
        String outPath = System.getProperty("uri.oracle.out", "oracle_verdicts.json");
        String flagMechanism = System.getProperty("uri.flag.mechanism", "UNKNOWN");

        String text;
        if (fixturePath.startsWith("/") || fixturePath.contains(":")) {
            text = new String(Files.readAllBytes(Paths.get(fixturePath)), StandardCharsets.UTF_8);
        } else {
            // Classpath fallback (resource on the test classpath).
            try (java.io.InputStream is = getClass().getResourceAsStream(fixturePath)) {
                if (is == null) throw new IllegalStateException("fixture not found: " + fixturePath);
                text = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        // FAIL CLOSED: read the actual framework flag state. If it cannot be
        // proven, write NOTHING (the test itself fails) and record the file as
        // UNVERIFIED_SKIPPED so the runner can never confirm from it.
        Boolean flagStateActual = actualFlagOn();
        if (flagStateActual == null) {
            throw new IllegalStateException(
                "cannot read android.content.pm.Flags.relativeReferenceIntentFilters(); "
                + "flag state unprovable — refusing to write verdicts (fail closed)");
        }
        boolean flagOnBuild = flagStateActual.booleanValue();

        JSONObject root = new JSONObject(text);
        JSONArray cases = root.getJSONArray("cases");
        Map<String, String> verdicts = new LinkedHashMap<>();
        List<String> flagSkipped = new ArrayList<>();
        int exercisedOn = 0, exercisedOff = 0, skipped = 0;
        for (int i = 0; i < cases.length(); i++) {
            JSONObject c = cases.getJSONObject(i);
            JSONObject f = c.getJSONObject("filter");
            String cid = c.getString("case_id");
            boolean requiredFlagOn = c.optBoolean("flag_on", true);
            if (requiredFlagOn != flagOnBuild) {
                // This build's frozen flag cannot exercise this case's required
                // state. Skip it deliberately; the runner will report
                // UNVERIFIED(FLAG|SKIP), never confirmed. A missing verdict that
                // is NOT in flag_skipped is a governed error on the runner side.
                flagSkipped.add(cid);
                skipped++;
                continue;
            }
            if (requiredFlagOn) exercisedOn++; else exercisedOff++;
            verdicts.put(cid, match(buildFilter(f), c.getString("uri")));
        }

        JSONObject provenance = new JSONObject();
        provenance.put("framework", FRAMEWORK);
        provenance.put("api_level", API_LEVEL);
        provenance.put("status", flagMechanism.equals("UNKNOWN")
            ? "UNVERIFIED_SKIPPED" : "RUN");
        // The build's ACTUAL flag state, read at runtime — not assumed.
        provenance.put("flag_state_actual", flagOnBuild);
        provenance.put("flag_skipped", new JSONArray(flagSkipped));
        provenance.put("flag_mechanism", flagMechanism);
        provenance.put("exercised_flag_on", exercisedOn);
        provenance.put("exercised_flag_off", exercisedOff);
        provenance.put("flag_skipped_count", skipped);
        provenance.put("robolectric", "4.14.1 (see build.gradle)");
        provenance.put("fixtures", fixturePath);
        provenance.put("output", outPath);

        JSONObject j = new JSONObject();
        j.put("verdicts", new JSONObject(verdicts));
        j.put("provenance", provenance);
        try (FileWriter w = new FileWriter(outPath)) {
            w.write(j.toString(2));
        }
    }
}
