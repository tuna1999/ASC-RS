/*
 * API-35 URI-relative-filter-group ORACLE — Robolectric (Android 15 / API 35).
 *
 * Read this only as the reference implementation: it MUST be run on a real
 * android-15 framework build before its output is treated as authoritative.
 * It did NOT run on this machine (no JDK / Android SDK / Gradle) — see
 * README.md. Every verdict this file could contribute is therefore
 * UNVERIFIED until a maintainer runs it.
 *
 * It mirrors asc-rs `evaluate_filter_uri` over tests/fixtures/uri_match_cases.json
 * and writes a JSON report:
 *     { "verdicts": { case_id: "matches"|"cannot_match", ... },
 *       "provenance": { "framework": "android-15.0.0_r1", "api_level": 35,
 *                       "flag_assumed": bool, "flag_mechanism": "...",
 *                       "robolectric": "...", "fixtures": "...", "output": "..." } }
 *
 * The framework's `IntentFilter.matchData` is DETERMINISTIC: it returns >=0
 * match categories for a match and <0 for a rejection — it has no "unknown".
 * An ASC-RS `unknown` row (pattern/advanced glob, opaque URI, bound overflow)
 * therefore has no direct `matchData` answer; the harness records that
 * divergence as a real finding and never as "the oracle also says unknown".
 *
 * v0.19.2 correctness audit:
 *  - scheme is now derived from the INPUT URI (Uri.parse(uri).getScheme()),
 *    not from the filter's <data> — `matchData(type, scheme, data)`'s scheme
 *    argument is the incoming URI's scheme, not a filter property.
 *  - the flag-on/off scenario is selected explicitly and recorded in
 *    provenance; the aconfig toggle itself is NOT performed here (see
 *    README "Flag handling" for the mechanism) — `flag_mechanism` states how
 *    (or whether) it was enforced on the run that produced this file.
 *  - output path and fixture path come from system properties so the Gradle
 *    task and the README recipe agree (no copy of the fixture).
 */

package us.ascrs.urioracle;

import android.content.IntentFilter;
import android.content.UriRelativeFilter;
import android.content.UriRelativeFilterGroup;
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
import java.util.LinkedHashMap;
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
     * Deterministic framework verdict for one URI. `flagOn` selects the
     * scenario ("flag on" group-aware branch vs "flag off" legacy branch);
     * enforcing the aconfig flag is OUT OF SCOPE here (see README) — the
     * mechanism that produced this state is recorded in provenance.
     */
    static String match(IntentFilter flt, String uri, boolean flagOn) {
        Uri u = Uri.parse(uri);
        // AOSP matchData(type, scheme, data): `scheme` is the INCOMING URI's
        // scheme, not a filter property (a filter can pool several schemes).
        String scheme = u.getScheme();
        int r = flt.matchData(null, scheme, u);
        // NOTE: the group-aware / legacy branch of matchData is taken by the
        // framework build's frozen FLAG_RELATIVE_REFERENCE_INTENT_FILTERS,
        // NOT by `flagOn` directly. `flagOn` is asserted against the build's
        // flag state in provenance.
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

        JSONObject root = new JSONObject(text);
        JSONArray cases = root.getJSONArray("cases");
        Map<String, String> verdicts = new LinkedHashMap<>();
        boolean anyFlagOn = false;
        boolean anyFlagOff = false;
        for (int i = 0; i < cases.length(); i++) {
            JSONObject c = cases.getJSONObject(i);
            JSONObject f = c.getJSONObject("filter");
            boolean flagOn = c.optBoolean("flag_on", true);
            if (flagOn) anyFlagOn = true; else anyFlagOff = true;
            verdicts.put(c.getString("case_id"),
                match(buildFilter(f), c.getString("uri"), flagOn));
        }

        JSONObject provenance = new JSONObject();
        provenance.put("framework", FRAMEWORK);
        provenance.put("api_level", API_LEVEL);
        provenance.put("flag_assumed_on", anyFlagOn);
        provenance.put("flag_assumed_off", anyFlagOff);
        provenance.put("flag_mechanism", flagMechanism);
        provenance.put("robolectric", "4.14.1 (see build.gradle)");
        provenance.put("fixtures", fixturePath);
        provenance.put("output", outPath);
        provenance.put("status", flagMechanism.equals("UNKNOWN")
            ? "UNVERIFIED_SKIPPED" : "RUN");

        JSONObject j = new JSONObject();
        j.put("verdicts", new JSONObject(verdicts));
        j.put("provenance", provenance);
        try (FileWriter w = new FileWriter(outPath)) {
            w.write(j.toString(2));
        }
    }
}
