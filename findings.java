import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.*;
import org.apache.commons.cli.*;
import org.apache.commons.csv.*;

import java.io.*;
import java.net.URLEncoder;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class NonameFindingsFetcher {

    // Config - replace these with your real values or read from env/config file
    private static final String CLIENT_ID = "your_client_id";
    private static final String CLIENT_SECRET = "your_client_secret";
    private static final String HOST = "https://wellsfargobank.nonamesec.com";
    private static final String AUTH_URL = HOST + "/auth/token";
    private static final String FINDINGS_API = HOST + "/api/v4/findings";
    private static final String API_METADATA_ENDPOINT = HOST + "/api/v3/apis/";

    private static final Path TOKEN_CACHE_FILE = Paths.get(System.getProperty("java.io.tmpdir"), "token_cache.json");
    private static final int TOKEN_EXPIRY_HOURS = 8;
    private static final int LIMIT = 50;

    private static final Path CSV_PATH = Paths.get(System.getProperty("java.io.tmpdir"), "findings_report.csv");
    private static final Path JSON_PATH = Paths.get(System.getProperty("java.io.tmpdir"), "findings_report.json");

    private static OkHttpClient client = new OkHttpClient.Builder()
            .callTimeout(30, TimeUnit.SECONDS)
            .build();

    private static ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static String bearerToken = null;

    // Fields to request from findings API
    private static final List<String> RETURN_FIELDS = Arrays.asList(
            "id", "title", "url", "typeId", "apiId", "module", "host", "path", "method",
            "resourceGroupName", "status", "severity", "owaspTags", "complianceFrameworkTags",
            "vulnerabilityFrameworkTags", "detectionTime", "lastUpdate", "triggeredOn",
            "description", "impact", "remediation", "investigate", "comments", "tickets",
            "externalTickets", "evidence", "source", "hasRelatedIncidents", "tagsIds",
            "relatedApiIds"
    );

    public static void main(String[] args) throws Exception {
        Options options = new Options();
        options.addOption("s", "start", true, "Start ISO timestamp (UTC)");
        options.addOption("e", "end", true, "End ISO timestamp (UTC)");
        options.addOption("h", "hours", true, "Hours back if no start/end");
        options.addOption(null, "include-api-metadata", false, "Include API metadata enrichment");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        String start = cmd.getOptionValue("start");
        String end = cmd.getOptionValue("end");
        int hoursBack = Integer.parseInt(cmd.getOptionValue("hours", "24"));
        boolean includeApiMetadata = cmd.hasOption("include-api-metadata");

        bearerToken = getCachedToken();
        if (bearerToken == null) {
            bearerToken = fetchBearerToken();
            if (bearerToken == null) {
                System.err.println("❌ Failed to authenticate.");
                System.exit(1);
            }
        }

        String[] timeWindow = getTimeWindow(start, end, hoursBack);
        start = timeWindow[0];
        end = timeWindow[1];

        System.out.printf("📅 Fetching findings from: %s to %s%n", start, end);

        List<Map<String, Object>> rawFindings = fetchFindings(start, end);

        List<Map<String, Object>> outputFindings;
        if (includeApiMetadata) {
            outputFindings = enrichFindingsWithApiMetadata(rawFindings);
        } else {
            outputFindings = rawFindings;
        }

        writeFindingsToJson(outputFindings, JSON_PATH);
        writeFindingsToCsv(outputFindings, CSV_PATH);

        System.out.printf("📊 Total findings: %d%n", outputFindings.size());
    }

    private static String getCachedToken() {
        if (Files.exists(TOKEN_CACHE_FILE)) {
            try {
                byte[] bytes = Files.readAllBytes(TOKEN_CACHE_FILE);
                JsonNode root = mapper.readTree(bytes);
                String token = root.path("accessToken").asText(null);
                String timestampStr = root.path("timestamp").asText(null);
                if (token != null && timestampStr != null) {
                    Instant tokenTime = Instant.parse(timestampStr);
                    Instant now = Instant.now();
                    if (Duration.between(tokenTime, now).toHours() < TOKEN_EXPIRY_HOURS) {
                        System.out.println("🔐 Using cached token.");
                        return token;
                    }
                }
            } catch (IOException e) {
                System.err.println("⚠️ Failed to read or parse cached token: " + e.getMessage());
            }
        }
        return null;
    }

    private static void cacheToken(String token) {
        ObjectNode root = mapper.createObjectNode();
        root.put("accessToken", token);
        root.put("timestamp", Instant.now().toString());
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(TOKEN_CACHE_FILE.toFile(), root);
        } catch (IOException e) {
            System.err.println("⚠️ Failed to write cached token: " + e.getMessage());
        }
    }

    private static String fetchBearerToken() {
        Map<String, String> payload = new HashMap<>();
        payload.put("client_id", CLIENT_ID);
        payload.put("client_secret", CLIENT_SECRET);
        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            System.err.println("❌ Failed to serialize auth payload: " + e.getMessage());
            return null;
        }

        RequestBody body = RequestBody.create(jsonPayload, MediaType.get("application/json"));

        Request request = new Request.Builder()
                .url(AUTH_URL)
                .post(body)
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                JsonNode json = mapper.readTree(response.body().string());
                String token = json.path("accessToken").asText(null);
                if (token != null) {
                    cacheToken(token);
                    return token;
                }
            } else {
                System.err.printf("❌ Token fetch failed: %d - %s%n", response.code(), response.message());
            }
        } catch (IOException e) {
            System.err.println("❌ Auth error: " + e.getMessage());
        }
        return null;
    }

    private static String[] getTimeWindow(String startArg, String endArg, int hoursBack) {
        Instant now = Instant.now();
        if (startArg != null && endArg != null) {
            return new String[]{startArg, endArg};
        }
        Instant start = now.minus(Duration.ofHours(hoursBack));
        Instant end = now;
        return new String[]{start.toString(), end.toString()};
    }

    private static List<Map<String, Object>> fetchFindings(String startTime, String endTime) {
        List<Map<String, Object>> findings = new ArrayList<>();
        int offset = 0;

        while (true) {
            HttpUrl.Builder urlBuilder = HttpUrl.parse(FINDINGS_API).newBuilder();
            urlBuilder.addQueryParameter("sortDesc", "true");
            urlBuilder.addQueryParameter("limit", String.valueOf(LIMIT));
            urlBuilder.addQueryParameter("offset", String.valueOf(offset));
            urlBuilder.addQueryParameter("detectionStartDate", startTime);
            urlBuilder.addQueryParameter("detectionEndDate", endTime);
            urlBuilder.addQueryParameter("lastUpdateStartDate", startTime);
            urlBuilder.addQueryParameter("lastUpdateEndDate", endTime);
            for (String field : RETURN_FIELDS) {
                urlBuilder.addQueryParameter("returnFields", field);
            }

            Request request = new Request.Builder()
                    .url(urlBuilder.build())
                    .header("Authorization", "Bearer " + bearerToken)
                    .header("Accept", "application/json")
                    .build();

            Response response = executeRequestWithRetry(request);

            if (response == null) break;

            try (ResponseBody body = response.body()) {
                if (body == null) break;
                JsonNode root = mapper.readTree(body.string());
                JsonNode entities = root.path("entities");
                if (entities.isArray()) {
                    for (JsonNode entity : entities) {
                        Map<String, Object> map = mapper.convertValue(entity, new TypeReference<Map<String, Object>>() {});
                        findings.add(map);
                    }
                    System.out.printf("📥 Retrieved %d findings (offset %d)%n", entities.size(), offset);
                }
                boolean more = root.path("moreEntities").asBoolean(false);
                if (!more) break;
            } catch (IOException e) {
                System.err.println("❌ Failed to parse findings response: " + e.getMessage());
                break;
            }

            offset += LIMIT;
        }
        return findings;
    }

    private static Response executeRequestWithRetry(Request request) {
        int retries = 5;
        for (int attempt = 0; attempt < retries; attempt++) {
            try {
                Response response = client.newCall(request).execute();
                if (response.code() == 401) {
                    // Token expired - refresh
                    System.out.println("🔁 Token expired. Refreshing.");
                    bearerToken = fetchBearerToken();
                    if (bearerToken == null) {
                        System.err.println("❌ Failed to refresh token.");
                        return null;
                    }
                    // Rebuild request with new token
                    request = request.newBuilder()
                            .header("Authorization", "Bearer " + bearerToken)
                            .build();
                    Thread.sleep(1500);
                    continue;
                }
                if (response.isSuccessful()) {
                    return response;
                } else {
                    System.err.printf("❗ Request failed (%d): %s%n", response.code(), response.message());
                }
                response.close();
            } catch (IOException | InterruptedException e) {
                System.err.println("❌ Network error: " + e.getMessage());
            }
            try {
                Thread.sleep((long) (Math.pow(2, attempt) * 1000 + Math.random() * 1000));
            } catch (InterruptedException ignored) {
            }
        }
        return null;
    }

    private static List<Map<String, Object>> enrichFindingsWithApiMetadata(List<Map<String, Object>> rawFindings) {
        List<Map<String, Object>> enriched = new ArrayList<>();
        Set<String> seenApiIds = new HashSet<>();

        for (Map<String, Object> finding : rawFindings) {
            Set<String> apiIds = new HashSet<>();
            if (finding.containsKey("apiId") && finding.get("apiId") != null) {
                apiIds.add(finding.get("apiId").toString());
            }
            if (finding.containsKey("relatedApiIds") && finding.get("relatedApiIds") instanceof List) {
                List<?> related = (List<?>) finding.get("relatedApiIds");
                for (Object o : related) {
                    if (o != null) apiIds.add(o.toString());
                }
            }

            List<Map<String, Object>> apiDetails = new ArrayList<>();
            for (String apiId : apiIds) {
                if (!seenApiIds.contains(apiId)) {
                    Map<String, Object> metadata = fetchApiMetadata(apiId);
                    if (metadata != null) {
                        apiDetails.add(metadata);
                    }
                    seenApiIds.add(apiId);
                }
            }
            finding.put("apiDetails", apiDetails);
            enriched.add(finding);
        }
        return enriched;
    }

    private static Map<String, Object> fetchApiMetadata(String apiId) {
        String url = API_METADATA_ENDPOINT + URLEncoder.encode(apiId, java.nio.charset.StandardCharsets.UTF_8);
        Request request = new Request.Builder()
                .url(url)
                .header("Authorization", "Bearer " + bearerToken)
                .header("Accept", "application/json")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                return mapper.readValue(response.body().string(), new TypeReference<Map<String, Object>>() {});
            } else {
                System.err.printf("⚠️ Failed to fetch API metadata %s: %d %s%n", apiId, response.code(), response.message());
            }
        } catch (IOException e) {
            System.err.println("❌ Error fetching API metadata for " + apiId + ": " + e.getMessage());
        }
        return null;
    }

    private static void writeFindingsToJson(List<Map<String, Object>> findings, Path path) {
        try (Writer writer = Files.newBufferedWriter(path)) {
            mapper.writerWithDefaultPrettyPrinter().writeValue(writer, findings);
            System.out.println("✅ JSON written to: " + path.toString());
        } catch (IOException e) {
            System.err.println("⚠️ Failed to write JSON: " + e.getMessage());
        }
    }

    private static void writeFindingsToCsv(List<Map<String, Object>> findings, Path path) {
        if (findings.isEmpty()) {
            System.out.println("⚠️ No findings to write to CSV.");
            return;
        }

        // Flatten each finding into a map of Strings for CSV
        List<Map<String, String>> flatFindings = new ArrayList<>();
        for (Map<String, Object> finding : findings) {
            Map<String, String> flat = new LinkedHashMap<>();
            for (String key : RETURN_FIELDS) {
                Object val = finding.get(key);
                if (val instanceof List) {
                    flat.put(key, String.join(", ", toStringList((List<?>) val)));
                } else if (val instanceof Map) {
                    try {
                        flat.put(key, mapper.writeValueAsString(val));
                    } catch (JsonProcessingException e) {
                        flat.put(key, val.toString());
                    }
                } else {
                    flat.put(key, val == null ? "" : val.toString());
                }
            }
            // Add apiDetails count
            Object apiDetails = finding.get("apiDetails");
            if (apiDetails instanceof List) {
                flat.put("apiDetailsCount", String.valueOf(((List<?>) apiDetails).size()));
            } else {
                flat.put("apiDetailsCount", "0");
            }
            flatFindings.add(flat);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(path);
             CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT
                     .withHeader(concatArrays(RETURN_FIELDS.toArray(new String[0]), new String[]{"apiDetailsCount"})))) {
            for (Map<String, String> record : flatFindings) {
                List<String> row = new ArrayList<>();
                for (String header : csvPrinter.getHeaderNames()) {
                    row.add(record.getOrDefault(header, ""));
                }
                csvPrinter.printRecord(row);
            }
            csvPrinter.flush();
            System.out.println("✅ CSV written to: " + path.toString());
        } catch (IOException e) {
            System.err.println("⚠️ Failed to write CSV: " + e.getMessage());
        }
    }

    private static List<String> toStringList(List<?> list) {
        List<String> out = new ArrayList<>();
        for (Object o : list) {
            out.add(o == null ? "" : o.toString());
        }
        return out;
    }

    @SafeVarargs
    private static <T> T[] concatArrays(T[] first, T[] second) {
        T[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
