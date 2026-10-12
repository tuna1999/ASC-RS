/*
 * API-35 URI-relative-filter-group ORACLE — Robolectric (Android 15 / API 35).
 *
 * Read this only as the reference implementation: it MUST be run on a real
 * android-15 framework build (Robolectric resolving android-all for API 35, or
 * an API-35 emulator with FLAG_RELATIVE_REFERENCE_INTENT_FILTERS enabled)
 * before its output is treated as authoritative. It was NOT executed here (no
 * JDK / Android SDK on this machine) — see README.md and the explicit gap in
 * docs/research/uri-relative-filter-groups.md §5.6.
 *
 * It mirrors asc-rs evaluate_filter_uri over tests/fixtures/uri_match_cases.json
 * and writes oracle_verdicts.json { case_id : matches|cannot_match|unknown }.
 *
 * Fixture -> IntentFilter mapping (must match asc-rs asc_manifest::IntentFilter):
 *   filter.data[*].scheme/host/port/path*  -> addDataScheme/addDataAuthority/addDataPath
 *   filter.groups[*].allow + parts[]       -> addUriRelativeFilterGroup(new UriRelativeFilterGroup(...))
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
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public class UriOracle {
    static final int PATH = 0, QUERY = 1, FRAGMENT = 2; // UriRelativeFilter constants

    static int partId(String s) {
        return "query".equals(s) ? QUERY : "fragment".equals(s) ? FRAGMENT : PATH;
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

    static void addPath(IntentFilter flt, String v, int k) { flt.addDataPath(v, k); }
    static final int[] KINDS = {PatternMatcher.PATTERN_LITERAL, PatternMatcher.PATTERN_PREFIX,
        PatternMatcher.PATTERN_SUFFIX, PatternMatcher.PATTERN_SIMPLE_GLOB, PatternMatcher.PATTERN_ADVANCED_GLOB};
    static int kindOf(int i) { return KINDS[i]; }

    static String match(IntentFilter flt, String scheme, String uri, boolean flagOn) {
        // Flag handling: a real run must toggle FLAG_RELATIVE_REFERENCE_INTENT_FILTERS
        // so that `matchData` takes the group-aware (on) or legacy (off) branch.
        int r = flt.matchData(null, scheme.isEmpty() ? null : scheme, Uri.parse(uri));
        return r >= 0 ? "matches" : "cannot_match";
    }

    @Test
    public void emitOracleVerdicts() throws Exception {
        InputStream is = getClass().getResourceAsStream("/uri_match_cases.json");
        JSONObject root = new JSONObject(new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        JSONArray cases = root.getJSONArray("cases");
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < cases.length(); i++) {
            JSONObject c = cases.getJSONObject(i);
            JSONObject f = c.getJSONObject("filter");
            String scheme = "https";
            if (f.getJSONArray("data").length() > 0
                    && f.getJSONArray("data").getJSONObject(0).has("scheme"))
                scheme = f.getJSONArray("data").getJSONObject(0).getString("scheme");
            // NOTE: the flag must be wired to c.optBoolean("flag_on", true);
            out.put(c.getString("case_id"), match(buildFilter(f), scheme,
                c.getString("uri"), c.optBoolean("flag_on", true)));
        }
        JSONObject j = new JSONObject(out);
        try (FileWriter w = new FileWriter("oracle_verdicts.json")) { w.write(j.toString(2)); }
    }
}
