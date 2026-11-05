import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ScamShield AI — a zero-dependency consumer fraud and phishing sentinel.
 *
 * <p>Run with Java 11+:
 * {@code javac --release 11 -d out src/Main.java && java --add-modules jdk.httpserver -cp out Main}
 *
 * <p>The HTTP server exposes the static experience at "/" and an explainable
 * heuristic scoring API at "POST /api/analyze".
 */
public final class Main {

    private static final String VERSION = "1.0.0";
    private static final String ENGINE = "ScamShield Explainable Heuristic Engine v1.0";
    private static final int DEFAULT_PORT = 8080;
    private static final int MAX_CONTENT_CHARS = 6000;
    private static final int MAX_BODY_BYTES = 128 * 1024;
    private static final Set<String> ALLOWED_TYPES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList("url", "review", "message")));
    private static final Instant STARTED_AT = Instant.now();

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        int port = DEFAULT_PORT;
        String host = "127.0.0.1";
        String publicDir = "public";

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--port".equals(arg) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--host".equals(arg) && i + 1 < args.length) {
                host = args[++i];
            } else if ("--public".equals(arg) && i + 1 < args.length) {
                publicDir = args[++i];
            } else if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage();
                return;
            }
        }

        String envPort = System.getenv("PORT");
        if (envPort != null && !envPort.isBlank()) {
            try {
                port = Integer.parseInt(envPort.trim());
            } catch (NumberFormatException ignored) {
                // Keep the CLI/default value when PORT is not a number.
            }
        }

        Path root = Paths.get(publicDir).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            System.err.println("[ScamShield] Warning: public directory not found: " + root);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/api/analyze", new AnalyzeHandler());
        server.createContext("/api/health", new HealthHandler());
        server.createContext("/", new StaticHandler(root));
        server.setExecutor(Executors.newFixedThreadPool(
                Math.max(4, Math.min(16, Runtime.getRuntime().availableProcessors() * 2))));

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[ScamShield] Shutting down safely. Stay scam-aware.");
            server.stop(0);
        }));

        server.start();
        System.out.println("============================================================");
        System.out.println("  ScamShield AI " + VERSION + "  |  Java " + System.getProperty("java.version"));
        System.out.println("  Engine : " + ENGINE);
        System.out.println("  Web    : http://localhost:" + port + "/");
        System.out.println("  API    : POST http://localhost:" + port + "/api/analyze");
        System.out.println("  Public : " + root);
        System.out.println("============================================================");
        System.out.println("  Press Ctrl+C to stop.");
    }

    private static void printUsage() {
        System.out.println("ScamShield AI " + VERSION);
        System.out.println("Usage: java --add-modules jdk.httpserver -cp out Main [options]");
        System.out.println("  --port <number>    HTTP port (default 8080, or PORT env var)");
        System.out.println("  --host <address>   Bind address (default 127.0.0.1)");
        System.out.println("  --public <dir>     Static asset directory (default public)");
        System.out.println("  --help             Show this help");
    }

    // ---------------------------------------------------------------------
    // HTTP handlers
    // ---------------------------------------------------------------------

    private static final class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendEmpty(exchange, 204);
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())
                    && !"HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, error("Use GET for the health endpoint."));
                return;
            }

            long uptime = Duration.between(STARTED_AT, Instant.now()).getSeconds();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", "ok");
            body.put("service", "ScamShield AI");
            body.put("version", VERSION);
            body.put("engine", ENGINE);
            body.put("uptimeSeconds", uptime);
            body.put("timestamp", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
            sendJson(exchange, 200, body, "HEAD".equalsIgnoreCase(exchange.getRequestMethod()));
        }
    }

    private static final class AnalyzeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addSecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "POST, OPTIONS");
                sendEmpty(exchange, 204);
                return;
            }
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "POST, OPTIONS");
                sendJson(exchange, 405, error("Use POST /api/analyze with a JSON body."));
                return;
            }

            try {
                byte[] raw = readLimited(exchange.getRequestBody(), MAX_BODY_BYTES);
                if (raw.length == 0) {
                    sendJson(exchange, 400, error("Request body is empty. Send JSON with content and type."));
                    return;
                }

                Object parsed;
                try {
                    parsed = Json.parse(new String(raw, StandardCharsets.UTF_8));
                } catch (IllegalArgumentException ex) {
                    sendJson(exchange, 400, error("Malformed JSON: " + ex.getMessage()));
                    return;
                }

                if (!(parsed instanceof Map)) {
                    sendJson(exchange, 400, error("The request body must be a JSON object."));
                    return;
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> body = (Map<String, Object>) parsed;
                String content = stringValue(body.get("content")).trim();
                String requestedType = stringValue(body.get("type")).trim().toLowerCase(Locale.ROOT);

                if (content.isEmpty()) {
                    sendJson(exchange, 400, error("'content' is required."));
                    return;
                }
                if (content.length() > MAX_CONTENT_CHARS) {
                    sendJson(exchange, 413,
                            error("Content is too long. Keep it under " + MAX_CONTENT_CHARS + " characters."));
                    return;
                }

                if (requestedType.isEmpty()) {
                    requestedType = inferType(content);
                }
                if (!ALLOWED_TYPES.contains(requestedType)) {
                    sendJson(exchange, 400,
                            error("'type' must be one of: url, review, message."));
                    return;
                }

                long started = System.nanoTime();
                Map<String, Object> analysis = Analyzer.analyze(content, requestedType);
                analysis.put("processingMs", Math.max(1,
                        Duration.ofNanos(System.nanoTime() - started).toMillis()));

                addSecurityHeaders(exchange);
                sendJson(exchange, 200, analysis);
            } catch (BodyTooLargeException ex) {
                sendJson(exchange, 413, error(ex.getMessage()));
            } catch (Exception ex) {
                ex.printStackTrace();
                sendJson(exchange, 500,
                        error("The scanner hit an unexpected error. Please try again."));
            } finally {
                exchange.close();
            }
        }
    }

    private static final class StaticHandler implements HttpHandler {
        private final Path root;

        private StaticHandler(Path root) {
            this.root = root;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            if ("OPTIONS".equalsIgnoreCase(method)) {
                sendEmpty(exchange, 204);
                return;
            }
            if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
                exchange.getResponseHeaders().set("Allow", "GET, HEAD");
                sendHtml(exchange, 405, "<h1>405 Method Not Allowed</h1>", false);
                return;
            }

            String requestPath;
            try {
                requestPath = exchange.getRequestURI().getPath();
            } catch (Exception ex) {
                sendHtml(exchange, 400, "<h1>400 Bad Request</h1>", false);
                return;
            }

            if (requestPath == null || requestPath.isEmpty()) {
                requestPath = "/";
            }
            if (requestPath.equals("/")) {
                requestPath = "/index.html";
            }

            // getPath is decoded; normalize and confine the result to public/.
            String decoded;
            try {
                decoded = URLDecoder.decode(requestPath, StandardCharsets.UTF_8.name());
            } catch (Exception ex) {
                sendHtml(exchange, 400, "<h1>400 Bad Request</h1>", false);
                return;
            }
            if (decoded.contains("\u0000")) {
                sendHtml(exchange, 400, "<h1>400 Bad Request</h1>", false);
                return;
            }

            Path candidate = root.resolve(decoded.substring(1)).normalize();
            if (!candidate.startsWith(root)) {
                sendHtml(exchange, 403, "<h1>403 Forbidden</h1>", false);
                return;
            }
            if (Files.isDirectory(candidate)) {
                candidate = candidate.resolve("index.html");
            }
            if (!Files.isRegularFile(candidate)) {
                sendHtml(exchange, 404, notFoundPage(), false);
                return;
            }

            byte[] fileBytes = Files.readAllBytes(candidate);
            String relative = root.relativize(candidate).toString().replace('\\', '/');
            String contentType = mimeType(relative);
            Headers headers = exchange.getResponseHeaders();
            addSecurityHeaders(exchange);
            headers.set("Content-Type", contentType);
            headers.set("Cache-Control", contentType.startsWith("text/html")
                    ? "no-store" : "public, max-age=3600");
            long length = "HEAD".equalsIgnoreCase(method) ? -1 : fileBytes.length;
            exchange.sendResponseHeaders(200, length);
            if (!"HEAD".equalsIgnoreCase(method)) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(fileBytes);
                }
            }
            exchange.close();
        }
    }

    private static final class BodyTooLargeException extends Exception {
        private BodyTooLargeException(String message) {
            super(message);
        }
    }

    private static byte[] readLimited(InputStream in, int limit) throws IOException, BodyTooLargeException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > limit) {
                throw new BodyTooLargeException("Request body exceeds the " + limit + " byte limit.");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static void sendJson(HttpExchange exchange, int status, Object body) throws IOException {
        sendJson(exchange, status, body, false);
    }

    private static void sendJson(HttpExchange exchange, int status, Object body, boolean headOnly)
            throws IOException {
        addSecurityHeaders(exchange);
        byte[] bytes = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, headOnly ? -1 : bytes.length);
        if (!headOnly) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }

    private static void sendEmpty(HttpExchange exchange, int status) throws IOException {
        addSecurityHeaders(exchange);
        exchange.sendResponseHeaders(status, -1);
        exchange.close();
    }

    private static void sendHtml(HttpExchange exchange, int status, String html, boolean headOnly)
            throws IOException {
        addSecurityHeaders(exchange);
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/html; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, headOnly ? -1 : bytes.length);
        if (!headOnly) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }

    private static void addSecurityHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        headers.set("Content-Security-Policy",
                "default-src 'self'; "
                        + "script-src 'self' 'unsafe-inline'; "
                        + "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                        + "font-src https://fonts.gstatic.com; "
                        + "img-src 'self' data:; "
                        + "connect-src 'self'; "
                        + "base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    }

    private static Map<String, Object> error(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message);
        body.put("status", "ERROR");
        return body;
    }

    private static String inferType(String content) {
        String lower = content.toLowerCase(Locale.ROOT);
        if (lower.contains("http://") || lower.contains("https://") || lower.contains("www.")) {
            return "url";
        }
        if (lower.matches("^(?:[a-z0-9-]+\\.)+[a-z]{2,}(?:/\\S*)?$")) {
            return "url";
        }
        return "message";
    }

    private static String stringValue(Object value) {
        return value instanceof String ? (String) value : "";
    }

    private static String mimeType(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html; charset=utf-8";
        if (lower.endsWith(".css")) return "text/css; charset=utf-8";
        if (lower.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (lower.endsWith(".json")) return "application/json; charset=utf-8";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".webp")) return "image/webp";
        if (lower.endsWith(".ico")) return "image/x-icon";
        if (lower.endsWith(".woff")) return "font/woff";
        if (lower.endsWith(".woff2")) return "font/woff2";
        if (lower.endsWith(".txt")) return "text/plain; charset=utf-8";
        if (lower.endsWith(".webmanifest")) return "application/manifest+json";
        return "application/octet-stream";
    }

    private static String notFoundPage() {
        return "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>Not found · ScamShield AI</title>"
                + "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;"
                + "background:#05070d;color:#e7edfa;font-family:Inter,system-ui,sans-serif;text-align:center}"
                + "h1{font-size:64px;margin:0;color:#22e6ff}p{color:#8c99b2}a{color:#22e6ff}</style>"
                + "<div><h1>404</h1><p>This route is off the map.</p>"
                + "<a href=\"/\">Return to ScamShield AI</a></div></html>";
    }

    // ---------------------------------------------------------------------
    // Explainable fraud scoring engine
    // ---------------------------------------------------------------------

    private static final class Analyzer {
        private static final DateTimeFormatter REPORT_TIME =
                DateTimeFormatter.ofPattern("dd MMM yyyy · HH:mm 'UTC'", Locale.ENGLISH)
                        .withZone(ZoneOffset.UTC);

        private static final Set<String> TRUSTED_DOMAINS = new HashSet<>(Arrays.asList(
                // Global marketplaces and technology brands
                "amazon.in", "amazon.com", "amazon.co.uk", "flipkart.com", "myntra.com",
                "ajio.com", "meesho.com", "nykaa.com", "snapdeal.com", "croma.com",
                "reliancedigital.in", "reliance.digital", "bigbasket.com", "swiggy.com",
                "zomato.com", "apple.com", "microsoft.com", "google.com", "netflix.com",
                "spotify.com", "samsung.com", "paytm.com", "phonepe.com", "irctc.co.in",
                "indianrail.gov.in", "indiapost.gov.in", "delhivery.com", "bluedart.com",
                // Financial institutions
                "hdfcbank.com", "icicibank.com", "sbi.co.in", "onlinesbi.sbi", "axisbank.com",
                "kotak.com", "indusind.com", "bankofbaroda.in", "pnb.in", "canarabank.com",
                "yesbank.in", "rbl.bank", "federalbank.co.in",
                // Bangladesh-focused commerce and finance
                "daraz.com.bd", "daraz.com", "shopee.com.bd", "foodpanda.com.bd",
                "bkash.com", "nagad.com.bd", "rocket.com.bd", "bracbank.com",
                "citybank.com.bd", "dutchbanglabank.com", "islamibankbd.com",
                "southeastbank.com.bd", "bdpost.gov.bd", "nidw.gov.bd", "cid.gov.bd",
                // Logistics and official safety portals
                "dhl.com", "fedex.com", "ups.com", "uidai.gov.in", "incometax.gov.in",
                "cybercrime.gov.in"));

        private static final Map<String, List<String>> BRANDS = new LinkedHashMap<>();

        static {
            BRANDS.put("amazon", Arrays.asList("amazon.in", "amazon.com", "amazon.co.uk"));
            BRANDS.put("flipkart", Collections.singletonList("flipkart.com"));
            BRANDS.put("myntra", Collections.singletonList("myntra.com"));
            BRANDS.put("ajio", Collections.singletonList("ajio.com"));
            BRANDS.put("meesho", Collections.singletonList("meesho.com"));
            BRANDS.put("nykaa", Collections.singletonList("nykaa.com"));
            BRANDS.put("snapdeal", Collections.singletonList("snapdeal.com"));
            BRANDS.put("paytm", Collections.singletonList("paytm.com"));
            BRANDS.put("phonepe", Collections.singletonList("phonepe.com"));
            BRANDS.put("google", Collections.singletonList("google.com"));
            BRANDS.put("apple", Collections.singletonList("apple.com"));
            BRANDS.put("microsoft", Collections.singletonList("microsoft.com"));
            BRANDS.put("netflix", Collections.singletonList("netflix.com"));
            BRANDS.put("spotify", Collections.singletonList("spotify.com"));
            BRANDS.put("samsung", Arrays.asList("samsung.com", "samsung.in"));
            BRANDS.put("sbi", Arrays.asList("sbi.co.in", "onlinesbi.sbi"));
            BRANDS.put("statebankofindia", Arrays.asList("sbi.co.in", "onlinesbi.sbi"));
            BRANDS.put("hdfc", Collections.singletonList("hdfcbank.com"));
            BRANDS.put("hdfcbank", Collections.singletonList("hdfcbank.com"));
            BRANDS.put("icici", Collections.singletonList("icicibank.com"));
            BRANDS.put("axis", Collections.singletonList("axisbank.com"));
            BRANDS.put("kotak", Collections.singletonList("kotak.com"));
            BRANDS.put("bkash", Collections.singletonList("bkash.com"));
            BRANDS.put("nagad", Collections.singletonList("nagad.com.bd"));
            BRANDS.put("daraz", Arrays.asList("daraz.com.bd", "daraz.com"));
            BRANDS.put("shopee", Collections.singletonList("shopee.com.bd"));
            BRANDS.put("delhivery", Collections.singletonList("delhivery.com"));
            BRANDS.put("bluedart", Collections.singletonList("bluedart.com"));
            BRANDS.put("dhl", Collections.singletonList("dhl.com"));
            BRANDS.put("fedex", Collections.singletonList("fedex.com"));
            BRANDS.put("indiapost", Collections.singletonList("indiapost.gov.in"));
            BRANDS.put("irctc", Collections.singletonList("irctc.co.in"));
        }

        private static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList(
                "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly",
                "is.gd", "shorturl.at", "rebrand.ly", "ow.ly", "buff.ly", "tiny.cc",
                "bit.do", "soo.gd", "clck.ru", "s-id.co", "shorte.st", "adf.ly"));

        private static final Set<String> RISKY_TLDS = new HashSet<>(Arrays.asList(
                "top", "xyz", "click", "buzz", "shop", "gq", "tk", "ru", "cn", "zip",
                "mov", "fit", "cam", "rest", "icu", "sbs", "cfd", "quest", "win",
                "bid", "download", "stream", "monster", "lol", "host", "website", "site",
                "online", "store", "live"));

        private static final Set<String> CONCRETE_REVIEW_TERMS = new HashSet<>(Arrays.asList(
                "battery", "camera", "delivery", "packaging", "fabric", "fit", "size", "quality",
                "flavour", "flavor", "taste", "smell", "bought", "ordered", "weeks", "months",
                "warranty", "replacement", "compared", "durability", "screen", "sound", "comfort",
                "material", "stitching", "refund", "return", "weight", "performance"));

        private static final Pattern DISCOUNT_PATTERN = Pattern.compile(
                "(?<!\\d)(?:[7-9][0-9]|100)\\s*%\\s*(?:off|discount|discounts)(?!\\d)",
                Pattern.CASE_INSENSITIVE);

        private static final Pattern URL_PATTERN = Pattern.compile(
                "(?i)(?:https?://|www\\.)[^\\s<>\\\"']+");

        private static final Pattern BARE_DOMAIN_PATTERN = Pattern.compile(
                "(?i)(?:[a-z0-9-]+\\.)+[a-z]{2,}(?:/[^\\s<>\\\"']*)?");

        private static Map<String, Object> analyze(String content, String type) {
            String original = content.trim();
            String normalized = normalize(original);
            String lowerType = type.toLowerCase(Locale.ROOT);
            Map<String, Signal> signals = new LinkedHashMap<>();
            List<String> trustedHosts = new ArrayList<>();
            List<String> urls = extractUrls(original, lowerType);
            int untrustedDomains = 0;
            int httpsUrls = 0;

            // Universal language signals that appear across URLs, reviews and messages.
            addPhraseSignal(signals, normalized, "urgency", "High-pressure urgency",
                    "Urgency & pressure",
                    "The content pushes for an immediate decision or threatens that a window is closing.",
                    "message", 9, 2, 18,
                    "act now", "act fast", "hurry", "only today", "ends tonight", "limited time",
                    "limited stock", "last chance", "final warning", "expires in", "expires today",
                    "within 24 hours", "within 48 hours", "immediately", "urgent", "don't wait",
                    "before it's too late", "right now", "claim now", "verify now", "offer ends");
            addPhraseSignal(signals, normalized, "credentials", "Credential harvesting language",
                    "Credential theft",
                    "The content asks for the exact secrets used to empty accounts or hijack identities.",
                    "all", 20, 3, 29,
                    "otp", "one-time password", "one time password", "one-time code", "pin",
                    "cvv", "card number", "net banking password", "password", "login credential",
                    "account number", "aadhaar", "aadhar", "pan card", "bank details",
                    "seed phrase", "recovery phrase", "upi pin", "verify your identity");
            addPhraseSignal(signals, normalized, "threat", "Account or legal threat",
                    "Account threats",
                    "Fear is being used to stop critical thinking and force an unsafe action.",
                    "all", 14, 2, 21,
                    "account will be suspended", "account has been suspended", "will be blocked",
                    "permanently blocked", "permanent block", "deactivated", "legal action",
                    "penalty", "arrest", "account will be closed", "service disconnected",
                    "avoid suspension", "failure to comply", "account compromised");
            addPhraseSignal(signals, normalized, "financial_lure", "Too-good-to-be-true reward",
                    "Financial lure",
                    "A high-value reward or unrealistic return is being used as bait.",
                    "all", 12, 3, 22,
                    "free gift", "cash prize", "you have won", "winner selected", "lottery",
                    "jackpot", "guaranteed returns", "risk-free", "risk free", "double your money",
                    "earn rs", "earn up to", "daily payout", "investment plan", "guaranteed profit",
                    "100% profit", "passive income", "sure shot");
            addPhraseSignal(signals, normalized, "payment_rail", "Unsafe payment request",
                    "Payment risk",
                    "Gift cards, crypto and direct transfers are hard to reverse and are favoured by scammers.",
                    "all", 18, 3, 27,
                    "gift card", "gift cards", "wire transfer", "western union", "moneygram",
                    "crypto", "bitcoin", "usdt", "pay via upi", "pay to reserve", "bank transfer",
                    "amazon gift card", "itunes gift card", "steam card", "send money");
            addPhraseSignal(signals, normalized, "secrecy", "Secrecy instruction",
                    "Urgency & pressure",
                    "A request to keep the conversation hidden is a classic social-engineering control.",
                    "all", 12, 2, 18,
                    "do not tell", "don't tell anyone", "keep this confidential", "between us",
                    "no one should know", "don't inform");
            addPhraseSignal(signals, normalized, "contact_channel", "Off-platform contact request",
                    "Contact risk",
                    "Moving the conversation to an unmonitored channel removes marketplace protections.",
                    "all", 8, 2, 15,
                    "whatsapp", "telegram", "dm us", "text us", "contact on whatsapp",
                    "join telegram", "call this number");
            addPhraseSignal(signals, normalized, "investment", "Investment or easy-money promise",
                    "Financial lure",
                    "Promises of easy, guaranteed or passive income are recurring investment-fraud markers.",
                    "all", 15, 2, 22,
                    "forex", "trading signal", "crypto investment", "double your investment",
                    "work from home", "part time job", "earn from home", "no experience needed",
                    "registration fee", "joining fee", "data entry job", "typing job",
                    "telegram task", "like youtube videos");

            if (DISCOUNT_PATTERN.matcher(normalized).find()) {
                addSignal(signals, "extreme_discount", "Extreme discount bait",
                        "A 70–100% discount is unusually deep for a legitimate retail offer.",
                        "Financial lure", 13);
            }

            // Obfuscation and visual pressure.
            if (containsHiddenCharacters(original)) {
                addSignal(signals, "hidden_characters", "Hidden Unicode characters",
                        "Zero-width or direction-control characters can disguise the true text.",
                        "Language red flags", 16);
            }
            if (hasUppercasePressure(original)) {
                addSignal(signals, "caps_pressure", "Aggressive uppercase emphasis",
                        "A large share of the text is uppercase, a common tactic to amplify urgency.",
                        "Language red flags", 5);
            }
            int bangs = countChar(original, '!');
            if (bangs >= 4) {
                addSignal(signals, "punctuation_pressure", "Excessive exclamation marks",
                        "Repeated exclamation marks are being used to manufacture excitement or fear.",
                        "Language red flags", bangs >= 8 ? 6 : 4);
            }

            // Type-specific message intelligence.
            if ("message".equals(lowerType)) {
                analyzeMessage(signals, normalized, urls);
            } else if ("review".equals(lowerType)) {
                analyzeReview(signals, normalized);
            }

            // URL and domain reputation checks.
            for (String url : urls) {
                UrlInfo info = inspectUrl(url);
                if (info.host.isEmpty()) {
                    addSignal(signals, "invalid_url", "Unparseable destination",
                            "The link could not be resolved to a normal web address.",
                            "Domain & link risk", 10);
                    continue;
                }

                if (info.https) {
                    httpsUrls++;
                }

                if (isTrustedHost(info.host)) {
                    trustedHosts.add(info.host);
                    if (!info.https) {
                        addSignal(signals, "official_http", "Official brand served over HTTP",
                                "The host is recognised, but the connection is not encrypted.",
                                "Domain & link risk", 6);
                    }
                    continue;
                }

                untrustedDomains++;
                if (!info.https) {
                    addSignal(signals, "domain_http", "Unencrypted web address",
                            "The link uses HTTP, so traffic and entered details can be intercepted.",
                            "Domain & link risk", 6);
                }
                if (info.ipHost) {
                    addSignal(signals, "domain_ip", "Raw IP address destination",
                            "Legitimate consumer shops rarely host checkout or login pages on a bare IP address.",
                            "Domain & link risk", 20);
                }
                if (info.punycode || info.nonAsciiHost) {
                    addSignal(signals, "domain_idn", "Internationalised or punycode host",
                            "Unicode domain tricks can make a hostile host look like a familiar brand.",
                            "Domain & link risk", 24);
                }
                if (SHORTENERS.contains(info.host)) {
                    addSignal(signals, "domain_shortener", "URL shortener hides destination",
                            "A shortened link conceals the final domain until you click.",
                            "Domain & link risk", 12);
                }
                if (info.userInfo) {
                    addSignal(signals, "domain_userinfo", "Embedded credentials in URL",
                            "The text before '@' can masquerade as a trusted brand while the real destination sits after it.",
                            "Domain & link risk", 18);
                }
                if (info.port > 0 && info.port != 80 && info.port != 443) {
                    addSignal(signals, "domain_port", "Unusual network port",
                            "A non-standard port is atypical for consumer e-commerce and account pages.",
                            "Domain & link risk", 6);
                }
                if (info.url.length() > 120) {
                    addSignal(signals, "domain_long", "Unusually long link",
                            "Very long URLs can bury the real destination and tracking payload.",
                            "Domain & link risk", 5);
                }
                if (info.host.split("\\.").length > 4) {
                    addSignal(signals, "domain_subdomains", "Deeply nested subdomains",
                            "Many subdomain layers can make an untrusted host appear official at a glance.",
                            "Domain & link risk", 10);
                }
                String tld = info.host.contains(".")
                        ? info.host.substring(info.host.lastIndexOf('.') + 1) : "";
                if (RISKY_TLDS.contains(tld)) {
                    addSignal(signals, "domain_tld", "High-risk top-level domain",
                            "The ." + tld + " TLD is disproportionately common in disposable scam infrastructure.",
                            "Domain & link risk", 14);
                }
                if (info.encodedPath) {
                    addSignal(signals, "domain_encoded", "Obfuscated URL characters",
                            "Encoded characters in the path can hide where a link really leads.",
                            "Domain & link risk", 8);
                }
                if (info.sensitivePath) {
                    addSignal(signals, "domain_path", "Sensitive action path",
                            "The URL contains login, verification, KYC, payment or claim language.",
                            "Domain & link risk", 12);
                }
                if (info.redirectParam) {
                    addSignal(signals, "domain_redirect", "Redirect parameter",
                            "The link is designed to bounce visitors to another destination.",
                            "Domain & link risk", 9);
                }
                if (info.apk) {
                    addSignal(signals, "domain_apk", "Direct app download",
                            "Consumer brands distribute apps through app stores, not random URL downloads.",
                            "Domain & link risk", 18);
                }

                for (String brand : BRANDS.keySet()) {
                    if (info.host.contains(brand) && !isTrustedHost(info.host)) {
                        addSignal(signals, "domain_brand", "Brand name used on an unverified domain",
                                "The host references \"" + displayBrand(brand)
                                        + "\" but is not on the verified official-domain list.",
                                "Impersonation", 28);
                        break;
                    }
                }

                String lookalike = findLookalikeBrand(info.host);
                if (!lookalike.isEmpty()) {
                    addSignal(signals, "domain_lookalike", "Lookalike domain detected",
                            "The host closely resembles \"" + displayBrand(lookalike)
                                    + "\" while sitting on an unverified domain.",
                            "Impersonation", 32);
                }

                String mentioned = findMentionedBrand(normalized);
                if (!mentioned.isEmpty() && !isTrustedHost(info.host)) {
                    addSignal(signals, "domain_brand_redirect", "Brand-to-domain mismatch",
                            "The message references \"" + displayBrand(mentioned)
                                    + "\", but the destination is not that brand's official domain.",
                            "Impersonation", 20);
                }
            }

            if (untrustedDomains > 2) {
                addSignal(signals, "domain_multi", "Multiple unverified destinations",
                        "The input contains several unrelated, unverified domains.",
                        "Domain & link risk", 8);
            }

            // Compound patterns. These make the score more decisive when multiple
            // weak signals combine into one coherent attack.
            addCompoundSignals(signals, urls);

            int rawScore = 0;
            for (Signal signal : signals.values()) {
                rawScore += signal.points;
            }
            int score = Math.min(100, rawScore);
            String status = score >= 70 ? "DANGER" : score >= 30 ? "WARNING" : "SAFE";
            String reportId = "SS-" + UUID.randomUUID().toString()
                    .replace("-", "").substring(0, 8).toUpperCase(Locale.ROOT);
            Instant now = Instant.now();

            int high = 0;
            int medium = 0;
            for (Signal signal : signals.values()) {
                if ("HIGH".equals(signal.severity)) high++;
                else if ("MEDIUM".equals(signal.severity)) medium++;
            }

            List<Signal> orderedSignals = new ArrayList<>(signals.values());
            orderedSignals.sort(Comparator
                    .comparingInt((Signal s) -> s.points).reversed()
                    .thenComparing(s -> s.title));

            List<Map<String, Object>> detailList = new ArrayList<>();
            for (Signal signal : orderedSignals) {
                detailList.add(signal.toMap());
            }

            Map<String, Integer> categoryPoints = new LinkedHashMap<>();
            for (Signal signal : signals.values()) {
                Integer previous = categoryPoints.get(signal.category);
                categoryPoints.put(signal.category, (previous == null ? 0 : previous) + signal.points);
            }
            List<Map<String, Object>> breakdown = new ArrayList<>();
            for (Map.Entry<String, Integer> entry : categoryPoints.entrySet()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("label", entry.getKey());
                item.put("points", entry.getValue());
                breakdown.add(item);
            }
            breakdown.sort((a, b) -> Integer.compare(
                    (Integer) b.get("points"), (Integer) a.get("points")));

            List<String> safeChecks = buildSafeChecks(signals, trustedHosts, urls.size(), normalized,
                    lowerType, httpsUrls);
            List<String> actions = buildActions(status, lowerType);
            String recommendation = buildRecommendation(status, lowerType, orderedSignals);
            String headline = buildHeadline(status, lowerType, orderedSignals);
            int confidence = (int) Math.round(Math.min(98,
                    84 + signals.size() * 2.0 + high * 1.5 + (score >= 70 ? 2 : 0)));
            if (signals.isEmpty()) {
                confidence = 88;
            }

            Map<String, Object> metrics = new LinkedHashMap<>();
            metrics.put("linksInspected", urls.size());
            metrics.put("trustedDomains", trustedHosts.size());
            metrics.put("untrustedDomains", untrustedDomains);
            metrics.put("highSeveritySignals", high);
            metrics.put("mediumSeveritySignals", medium);
            metrics.put("charactersAnalyzed", original.length());

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("score", score);
            result.put("status", status);
            result.put("headline", headline);
            result.put("summary", buildSummary(status, lowerType, signals.size(), high, medium));
            result.put("recommendation", recommendation);
            result.put("actions", actions);
            result.put("details", detailList);
            result.put("breakdown", breakdown);
            result.put("safeChecks", safeChecks);
            result.put("confidence", confidence);
            result.put("inputType", lowerType);
            result.put("reportId", reportId);
            result.put("analyzedAt", REPORT_TIME.format(now));
            result.put("isoTimestamp", DateTimeFormatter.ISO_INSTANT.format(now));
            result.put("engine", ENGINE);
            result.put("version", VERSION);
            result.put("metrics", metrics);
            return result;
        }

        private static void analyzeMessage(Map<String, Signal> signals, String text, List<String> urls) {
            addPhraseSignal(signals, text, "msg_kyc", "KYC or identity-update lure",
                    "Message scam patterns",
                    "KYC, PAN and Aadhaar updates are common pretexts for identity theft.",
                    "message", 15, 2, 21,
                    "kyc", "re-kyc", "video kyc", "update your pan", "update aadhaar",
                    "aadhaar update", "pan update", "identity update");
            addPhraseSignal(signals, text, "msg_delivery", "Courier or delivery trap",
                    "Message scam patterns",
                    "Fake failed-delivery and redelivery-fee messages are widely used to harvest payment data.",
                    "message", 12, 2, 20,
                    "delivery failed", "could not be delivered", "parcel is stuck",
                    "customs clearance", "redelivery fee", "reschedule delivery",
                    "package is waiting", "address incomplete", "shipment held");
            addPhraseSignal(signals, text, "msg_job", "Fraudulent job or task offer",
                    "Message scam patterns",
                    "Easy-money job pitches often escalate into task scams and deposit requests.",
                    "message", 14, 2, 22,
                    "part time job", "daily payout", "work from home", "telegram task",
                    "like youtube videos", "registration fee", "no experience needed",
                    "typing job", "data entry job");
            addPhraseSignal(signals, text, "msg_lottery", "Unrequested prize or lottery",
                    "Message scam patterns",
                    "You cannot win a lottery you never entered; prize claims are a classic advance-fee fraud.",
                    "message", 18, 2, 24,
                    "you have won", "congratulations you", "lucky winner", "claim your prize",
                    "lottery", "jackpot", "prize money", "gift worth", "selected winner");
            addPhraseSignal(signals, text, "msg_government", "Government refund or notice pretext",
                    "Message scam patterns",
                    "Tax, subsidy and utility notices are frequently impersonated to create authority.",
                    "message", 13, 2, 20,
                    "income tax refund", "tax refund", "electricity bill", "court notice",
                    "challan", "subsidy", "pm kisan", "government scheme");
            addPhraseSignal(signals, text, "msg_bank", "Bank security impersonation",
                    "Message scam patterns",
                    "A bank alert plus a link or credential request is a high-confidence phishing shape.",
                    "message", 13, 2, 20,
                    "debit card", "credit card", "net banking", "unauthorized transaction",
                    "new device login", "security alert", "account holder");
            addPhraseSignal(signals, text, "msg_greeting", "Generic mass-market greeting",
                    "Message scam patterns",
                    "Impersonal greetings are common in bulk phishing, though not proof on their own.",
                    "message", 5, 1, 7,
                    "dear customer", "valued customer", "dear user", "dear account holder");

            if (!urls.isEmpty()) {
                List<String> actionWords = matchedPhrases(text,
                        "click", "tap", "verify", "login", "log in", "claim", "update", "confirm");
                if (!actionWords.isEmpty()) {
                    addSignal(signals, "msg_link_action", "Call-to-action link",
                            "The message combines an embedded link with an instruction to click, verify or update.",
                            "Message scam patterns", 9);
                }
            }
        }

        private static void analyzeReview(Map<String, Signal> signals, String text) {
            addPhraseSignal(signals, text, "review_incentive", "Incentivised or sponsored review",
                    "Fake-review patterns",
                    "Disclosed or implied compensation can bias a review away from real customer experience.",
                    "review", 18, 2, 24,
                    "received this product for free", "in exchange for", "free product",
                    "sponsored review", "paid review", "discount code", "promo code",
                    "use my code", "affiliate link");
            addPhraseSignal(signals, text, "review_superlatives", "Stacked generic superlatives",
                    "Fake-review patterns",
                    "A cluster of vague, over-the-top praise with no first-hand detail is a review-farm pattern.",
                    "review", 12, 2, 20,
                    "best product ever", "best ever", "must buy", "life changing", "changed my life",
                    "highly recommend", "5 stars", "five stars", "10/10", "perfect in every way",
                    "amazing product", "100% recommended");

            int superlatives = matchedPhrases(text,
                    "best product ever", "best ever", "must buy", "life changing", "changed my life",
                    "highly recommend", "5 stars", "five stars", "10/10", "perfect in every way",
                    "amazing product", "100% recommended").size();
            boolean specific = false;
            for (String term : CONCRETE_REVIEW_TERMS) {
                if (containsWord(text, term)) {
                    specific = true;
                    break;
                }
            }
            if (superlatives >= 2 && !specific && text.length() < 280) {
                addSignal(signals, "review_vague", "Praise without purchase specifics",
                        "The review is very positive but lacks concrete details about use, delivery or product quality.",
                        "Fake-review patterns", 12);
            }
            if (text.matches("(?s).*\\b(?:buy|purchase|order)\\s+(?:it|this|now)\\b.*")
                    && text.length() < 120) {
                addSignal(signals, "review_push", "Purchase pressure in a review",
                        "Short reviews that directly push an immediate purchase are atypical of genuine customers.",
                        "Fake-review patterns", 8);
            }
        }

        private static void addCompoundSignals(Map<String, Signal> signals, List<String> urls) {
            boolean hasUrgency = signals.containsKey("urgency");
            boolean hasCredentials = signals.containsKey("credentials");
            boolean hasLink = !urls.isEmpty();
            boolean hasDomainRisk = signals.containsKey("domain_brand")
                    || signals.containsKey("domain_lookalike")
                    || signals.containsKey("domain_tld")
                    || signals.containsKey("domain_shortener");
            boolean hasPayment = signals.containsKey("payment_rail");
            boolean hasFinancial = signals.containsKey("financial_lure")
                    || signals.containsKey("extreme_discount");

            if (hasUrgency && hasCredentials && hasLink) {
                addSignal(signals, "compound_phishing", "Coordinated phishing combination",
                        "Urgency + credential request + link is a high-confidence phishing formula.",
                        "Compound risk", 16);
            }
            if (hasUrgency && hasFinancial && hasPayment) {
                addSignal(signals, "compound_offer", "Engineered purchase trap",
                        "A time-limited bargain, an easy-money lure and a hard-to-reverse payment request appear together.",
                        "Compound risk", 15);
            }
            if (hasDomainRisk && hasCredentials) {
                addSignal(signals, "compound_identity", "Credential capture on a risky domain",
                        "Sensitive-data language is paired with an unverified destination.",
                        "Compound risk", 14);
            }
            if (hasLink && signals.containsKey("msg_delivery") && hasPayment) {
                addSignal(signals, "compound_delivery", "Paid-redelivery trap",
                        "A fake delivery failure has been combined with a payment demand.",
                        "Compound risk", 13);
            }
        }

        private static List<String> buildSafeChecks(Map<String, Signal> signals,
                                                    List<String> trustedHosts, int urlCount,
                                                    String text, String type, int httpsUrls) {
            List<String> checks = new ArrayList<>();
            if (!trustedHosts.isEmpty() && httpsUrls > 0) {
                checks.add("Destination matches a verified official domain over HTTPS");
            }
            if (!signals.containsKey("credentials")) {
                checks.add("No request for OTP, PIN, password or card details");
            }
            if (!signals.containsKey("urgency") && !signals.containsKey("threat")) {
                checks.add("No artificial urgency or account-threat pressure");
            }
            if (!signals.containsKey("payment_rail") && !signals.containsKey("financial_lure")) {
                checks.add("No irreversible payment request or easy-money lure");
            }
            if (urlCount == 0) {
                checks.add("No embedded external links to inspect");
            }
            if ("review".equals(type)) {
                for (String term : CONCRETE_REVIEW_TERMS) {
                    if (containsWord(text, term)) {
                        checks.add("Review includes specific, first-hand product context");
                        break;
                    }
                }
            }
            if (checks.isEmpty()) {
                checks.add("No high-severity fraud patterns were detected in this sample");
            }
            return checks.subList(0, Math.min(4, checks.size()));
        }

        private static String buildHeadline(String status, String type, List<Signal> orderedSignals) {
            if ("SAFE".equals(status)) {
                return "No obvious fraud signals found";
            }
            String topCategory = orderedSignals.isEmpty() ? "" : orderedSignals.get(0).category;
            if ("DANGER".equals(status)) {
                if (topCategory.contains("Credential")) {
                    return "Credential theft attempt detected";
                }
                if (topCategory.contains("Impersonation") || topCategory.contains("Domain")) {
                    return "Dangerous destination detected";
                }
                if ("review".equals(type)) {
                    return "High-confidence fake review detected";
                }
                return "High-risk fraud pattern detected";
            }
            if ("review".equals(type)) {
                return "This review needs independent verification";
            }
            return "Suspicious signals need verification";
        }

        private static String buildSummary(String status, String type, int count, int high, int medium) {
            if (count == 0) {
                return "The scanner found no deceptive language, credential requests, payment traps or "
                        + "domain-reputation warnings in this sample.";
            }
            String inputLabel = "url".equals(type) ? "link" : "message".equals(type) ? "message" : "review";
            if ("SAFE".equals(status)) {
                return count + " low-weight signal" + (count == 1 ? "" : "s")
                        + " appeared in this " + inputLabel
                        + ", but none form a meaningful fraud pattern.";
            }
            return count + " fraud indicator" + (count == 1 ? "" : "s")
                    + " fired across this " + inputLabel + " — " + high + " high-risk and "
                    + medium + " medium-risk. The combined pattern is "
                    + ("DANGER".equals(status) ? "strong enough to avoid engagement." : "worth verifying before you act.");
        }

        private static String buildRecommendation(String status, String type, List<Signal> orderedSignals) {
            String topSignal = orderedSignals.isEmpty() ? "the detected pattern" : orderedSignals.get(0).title;
            if ("DANGER".equals(status)) {
                if ("message".equals(type)) {
                    return "Stop. Do not tap links, reply, call the number or share OTPs, PINs, passwords or card details. "
                            + "This message matches a coordinated phishing pattern (top signal: "
                            + topSignal + "). Verify through the organisation's official app or website, then report and block the sender.";
                }
                if ("url".equals(type)) {
                    return "Do not open this checkout, log in or send money. The destination carries high-risk domain signals "
                            + "and may be built to capture credentials or payment data. Close the tab and reach the store through its official app or a manually typed address.";
                }
                return "Do not rely on this review for a purchase decision. It combines fake-review patterns with "
                        + "trust-eroding signals. Check verified-purchase reviews, seller history and the return policy before spending anything.";
            }
            if ("WARNING".equals(status)) {
                if ("review".equals(type)) {
                    return "Treat this review as unverified. Pause before buying, look for confirmed-purchase reviews "
                            + "with concrete product details, and keep the purchase inside the platform's protection.";
                }
                return "Pause before clicking or paying. Some signals are ambiguous, but the combination warrants independent verification "
                        + "(top signal: " + topSignal + "). Open the official app or type the known URL yourself; never let urgency make the decision.";
            }
            if ("review".equals(type)) {
                return "No obvious fake-review pattern was found. Still compare multiple verified-purchase reviews, "
                        + "check the seller's return policy and avoid paying outside the marketplace.";
            }
            return "No obvious fraud pattern was found in this sample. Before paying, confirm you are on the official domain, "
                    + "use buyer-protected checkout and never share OTPs, PINs or passwords with anyone.";
        }

        private static List<String> buildActions(String status, String type) {
            List<String> actions = new ArrayList<>();
            if ("DANGER".equals(status)) {
                if ("message".equals(type)) {
                    actions.add("Do not click links, download attachments or call numbers in this message.");
                    actions.add("If you shared credentials, contact your bank immediately and change affected passwords.");
                    actions.add("Report and block the sender; verify separately through the official app or helpline.");
                } else if ("url".equals(type)) {
                    actions.add("Close the page now — do not log in, enter card details or complete checkout.");
                    actions.add("Open the official store manually or through its app, and compare the exact domain.");
                    actions.add("Pay only with buyer-protected checkout; report the domain to the brand and local cyber authority.");
                } else {
                    actions.add("Do not let this review influence a purchase decision.");
                    actions.add("Filter for verified purchases and reviews that mention specific use, fit or delivery details.");
                    actions.add("Keep payment inside the marketplace; refuse off-platform transfers or gift-card requests.");
                }
            } else if ("WARNING".equals(status)) {
                actions.add("Pause. Verify the seller, link and offer through an independent official source.");
                actions.add("Never share OTPs, PINs, passwords or full card details to 'confirm' anything.");
                actions.add("Use buyer-protected payment and keep evidence of the listing and conversation.");
            } else {
                actions.add("Confirm the exact domain and seller before entering payment information.");
                actions.add("Use a credit card or buyer-protected checkout for high-value purchases.");
                actions.add("Never share OTPs, PINs or passwords — even with someone claiming to be support.");
            }
            return actions;
        }

        private static String normalize(String text) {
            String value = text.toLowerCase(Locale.ROOT)
                    .replace('\u2018', '\'').replace('\u2019', '\'')
                    .replace('\u201c', '"').replace('\u201d', '"')
                    .replace('\u2013', '-').replace('\u2014', '-')
                    .replace('\u00a0', ' ');
            return value.replaceAll("[\\u200B-\\u200D\\u200E\\u200F\\uFEFF]", "")
                    .replaceAll("\\s+", " ").trim();
        }

        private static List<String> extractUrls(String content, String type) {
            LinkedHashSet<String> urls = new LinkedHashSet<>();
            Matcher matcher = URL_PATTERN.matcher(content);
            while (matcher.find()) {
                urls.add(trimUrl(matcher.group()));
            }

            if (urls.isEmpty() && "url".equals(type)) {
                String trimmed = content.trim();
                if (!trimmed.contains(" ")) {
                    String candidate = BARE_DOMAIN_PATTERN.matcher(trimmed).matches()
                            ? trimmed : trimmed;
                    if (candidate.contains(".")) {
                        urls.add(trimUrl(candidate.startsWith("http") ? candidate : "https://" + candidate));
                    }
                }
            }
            return new ArrayList<>(urls);
        }

        private static String trimUrl(String raw) {
            String value = raw.trim();
            while (value.endsWith(".") || value.endsWith(",") || value.endsWith(";")
                    || value.endsWith("!") || value.endsWith("?") || value.endsWith(")")
                    || value.endsWith("]") || value.endsWith("}")) {
                value = value.substring(0, value.length() - 1);
            }
            return value;
        }

        private static UrlInfo inspectUrl(String raw) {
            String normalized = raw.startsWith("www.") ? "https://" + raw : raw;
            UrlInfo info = new UrlInfo();
            info.url = normalized;
            try {
                URI uri = new URI(normalized.replace(" ", "%20"));
                info.https = "https".equalsIgnoreCase(uri.getScheme());
                info.host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
                info.port = uri.getPort();
                info.userInfo = uri.getUserInfo() != null && !uri.getUserInfo().isEmpty();
                info.ipHost = info.host.matches("^\\d{1,3}(?:\\.\\d{1,3}){3}$")
                        || info.host.startsWith("[");
                info.punycode = info.host.contains("xn--");
                info.nonAsciiHost = containsNonAscii(info.host);
                String path = uri.getPath() == null ? "" : uri.getPath().toLowerCase(Locale.ROOT);
                String query = uri.getQuery() == null ? "" : uri.getQuery().toLowerCase(Locale.ROOT);
                info.sensitivePath = path.matches(".*(?:/login|/signin|/verify|/kyc|/secure|/account|"
                        + "/billing|/update|/claim|/refund|/unlock|/auth|/payment).*");
                info.encodedPath = path.contains("%2f") || path.contains("%40")
                        || path.contains("%3a") || path.contains("%00");
                info.redirectParam = query.contains("redirect=") || query.contains("url=")
                        || query.contains("next=") || query.contains("return=")
                        || query.contains("target=") || query.contains("continue=");
                info.apk = path.endsWith(".apk") || query.contains(".apk");
            } catch (Exception ex) {
                if (raw.contains("://")) {
                    try {
                        String authority = raw.split("://", 2)[1].split("/", 2)[0];
                        info.host = authority.replaceAll(":.*$", "").toLowerCase(Locale.ROOT);
                    } catch (Exception ignored) {
                        // Leave host empty; the caller will emit an invalid-url signal.
                    }
                }
            }
            return info;
        }

        private static boolean isTrustedHost(String host) {
            if (host == null || host.isEmpty()) return false;
            for (String trusted : TRUSTED_DOMAINS) {
                if (host.equals(trusted) || host.endsWith("." + trusted)) {
                    return true;
                }
            }
            return false;
        }

        private static String findMentionedBrand(String text) {
            for (String brand : BRANDS.keySet()) {
                if (containsWord(text, brand)) {
                    return brand;
                }
            }
            return "";
        }

        private static String findLookalikeBrand(String host) {
            String[] labels = host.split("\\.");
            for (String label : labels) {
                String normalized = deLeet(label);
                for (String brand : BRANDS.keySet()) {
                    if (brand.length() < 4 || normalized.length() < 4) continue;
                    if (normalized.equals(brand)) return brand;
                    if (Math.abs(normalized.length() - brand.length()) <= 1
                            && levenshtein(normalized, brand) <= 1) {
                        return brand;
                    }
                }
            }
            return "";
        }

        private static String deLeet(String value) {
            return value.toLowerCase(Locale.ROOT)
                    .replace('0', 'o')
                    .replace('1', 'l')
                    .replace('3', 'e')
                    .replace('5', 's')
                    .replace('@', 'a')
                    .replace('$', 's');
        }

        private static int levenshtein(String a, String b) {
            int[] previous = new int[b.length() + 1];
            int[] current = new int[b.length() + 1];
            for (int j = 0; j <= b.length(); j++) previous[j] = j;
            for (int i = 1; i <= a.length(); i++) {
                current[0] = i;
                for (int j = 1; j <= b.length(); j++) {
                    int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                    current[j] = Math.min(Math.min(current[j - 1] + 1, previous[j] + 1),
                            previous[j - 1] + cost);
                }
                int[] temp = previous;
                previous = current;
                current = temp;
            }
            return previous[b.length()];
        }

        private static String displayBrand(String brand) {
            if (brand.isEmpty()) return brand;
            return Character.toUpperCase(brand.charAt(0)) + brand.substring(1);
        }

        private static void addPhraseSignal(Map<String, Signal> signals, String text, String id,
                                            String title, String category, String description,
                                            String applicableType, int basePoints, int perExtra,
                                            int maxPoints, String... phrases) {
            List<String> matched = matchedPhrases(text, phrases);
            if (matched.isEmpty()) return;
            int points = Math.min(maxPoints, basePoints + perExtra * (matched.size() - 1));
            String examples = String.join(", ", matched.subList(0, Math.min(4, matched.size())));
            addSignal(signals, id, title,
                    description + " Matched: \"" + examples + "\".",
                    category, points);
        }

        private static List<String> matchedPhrases(String text, String... phrases) {
            List<String> found = new ArrayList<>();
            for (String phrase : phrases) {
                if (containsWord(text, phrase)) {
                    found.add(phrase);
                }
            }
            return found;
        }

        private static boolean containsWord(String text, String phrase) {
            if (phrase.isEmpty()) return false;
            Pattern pattern = Pattern.compile(
                    "(?<![\\p{L}\\p{N}])" + Pattern.quote(phrase.toLowerCase(Locale.ROOT))
                            + "(?![\\p{L}\\p{N}])",
                    Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
            return pattern.matcher(text).find();
        }

        private static void addSignal(Map<String, Signal> signals, String id, String title,
                                      String description, String category, int points) {
            if (signals.containsKey(id)) return;
            String severity = points >= 15 ? "HIGH" : points >= 9 ? "MEDIUM" : "LOW";
            signals.put(id, new Signal(id, title, description, category, severity, points));
        }

        private static boolean containsHiddenCharacters(String text) {
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\u200E'
                        || c == '\u200F' || c == '\uFEFF') {
                    return true;
                }
            }
            return false;
        }

        private static boolean containsNonAscii(String text) {
            for (int i = 0; i < text.length(); i++) {
                if (text.charAt(i) > 127) return true;
            }
            return false;
        }

        private static boolean hasUppercasePressure(String text) {
            int letters = 0;
            int upper = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isLetter(c)) {
                    letters++;
                    if (Character.isUpperCase(c)) upper++;
                }
            }
            return letters >= 24 && upper >= 12 && upper * 100.0 / letters >= 32.0;
        }

        private static int countChar(String text, char needle) {
            int count = 0;
            for (int i = 0; i < text.length(); i++) {
                if (text.charAt(i) == needle) count++;
            }
            return count;
        }

        private static final class UrlInfo {
            String url = "";
            String host = "";
            int port = -1;
            boolean https;
            boolean userInfo;
            boolean ipHost;
            boolean punycode;
            boolean nonAsciiHost;
            boolean sensitivePath;
            boolean encodedPath;
            boolean redirectParam;
            boolean apk;
        }

        private static final class Signal {
            final String id;
            final String title;
            final String description;
            final String category;
            final String severity;
            final int points;

            Signal(String id, String title, String description, String category,
                   String severity, int points) {
                this.id = id;
                this.title = title;
                this.description = description;
                this.category = category;
                this.severity = severity;
                this.points = points;
            }

            Map<String, Object> toMap() {
                Map<String, Object> map = new LinkedHashMap<>();
                map.put("id", id);
                map.put("title", title);
                map.put("description", description);
                map.put("category", category);
                map.put("severity", severity);
                map.put("points", points);
                return map;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Minimal JSON parser/stringifier (keeps the project dependency-free)
    // ---------------------------------------------------------------------

    private static final class Json {
        private static final int MAX_DEPTH = 32;

        static Object parse(String input) {
            Parser parser = new Parser(input);
            Object value = parser.parseValue(0);
            parser.skipWhitespace();
            if (!parser.atEnd()) {
                throw new IllegalArgumentException("Unexpected trailing content at position " + parser.position);
            }
            return value;
        }

        static String stringify(Object value) {
            StringBuilder out = new StringBuilder();
            write(value, out);
            return out.toString();
        }

        private static void write(Object value, StringBuilder out) {
            if (value == null) {
                out.append("null");
            } else if (value instanceof String) {
                writeString((String) value, out);
            } else if (value instanceof Boolean) {
                out.append(value.toString());
            } else if (value instanceof Number) {
                if (value instanceof Double || value instanceof Float) {
                    double d = ((Number) value).doubleValue();
                    if (!Double.isFinite(d)) {
                        out.append("null");
                    } else {
                        out.append(d);
                    }
                } else {
                    out.append(value.toString());
                }
            } else if (value instanceof Map) {
                out.append('{');
                boolean first = true;
                for (Object entryObject : ((Map<?, ?>) value).entrySet()) {
                    Map.Entry<?, ?> entry = (Map.Entry<?, ?>) entryObject;
                    if (!first) out.append(',');
                    first = false;
                    writeString(String.valueOf(entry.getKey()), out);
                    out.append(':');
                    write(entry.getValue(), out);
                }
                out.append('}');
            } else if (value instanceof Iterable) {
                out.append('[');
                boolean first = true;
                for (Object item : (Iterable<?>) value) {
                    if (!first) out.append(',');
                    first = false;
                    write(item, out);
                }
                out.append(']');
            } else if (value.getClass().isArray()) {
                out.append('[');
                int length = java.lang.reflect.Array.getLength(value);
                for (int i = 0; i < length; i++) {
                    if (i > 0) out.append(',');
                    write(java.lang.reflect.Array.get(value, i), out);
                }
                out.append(']');
            } else {
                writeString(String.valueOf(value), out);
            }
        }

        private static void writeString(String value, StringBuilder out) {
            out.append('"');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"': out.append("\\\""); break;
                    case '\\': out.append("\\\\"); break;
                    case '\b': out.append("\\b"); break;
                    case '\f': out.append("\\f"); break;
                    case '\n': out.append("\\n"); break;
                    case '\r': out.append("\\r"); break;
                    case '\t': out.append("\\t"); break;
                    default:
                        if (c < 0x20) {
                            out.append(String.format("\\u%04x", (int) c));
                        } else {
                            out.append(c);
                        }
                }
            }
            out.append('"');
        }

        private static final class Parser {
            private final String text;
            private int position;

            Parser(String text) {
                this.text = text;
            }

            boolean atEnd() {
                return position >= text.length();
            }

            void skipWhitespace() {
                while (!atEnd() && Character.isWhitespace(text.charAt(position))) {
                    position++;
                }
            }

            Object parseValue(int depth) {
                if (depth > MAX_DEPTH) {
                    throw new IllegalArgumentException("JSON nesting is too deep.");
                }
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("Unexpected end of JSON.");
                }
                char c = text.charAt(position);
                if (c == '{') return parseObject(depth);
                if (c == '[') return parseArray(depth);
                if (c == '"') return parseString();
                if (c == 't') return parseKeyword("true", Boolean.TRUE);
                if (c == 'f') return parseKeyword("false", Boolean.FALSE);
                if (c == 'n') return parseKeyword("null", null);
                if (c == '-' || Character.isDigit(c)) return parseNumber();
                throw new IllegalArgumentException("Unexpected character '" + c + "' at position " + position);
            }

            Map<String, Object> parseObject(int depth) {
                expect('{');
                Map<String, Object> map = new LinkedHashMap<>();
                skipWhitespace();
                if (peek('}')) {
                    position++;
                    return map;
                }
                while (true) {
                    skipWhitespace();
                    String key = parseString();
                    skipWhitespace();
                    expect(':');
                    map.put(key, parseValue(depth + 1));
                    skipWhitespace();
                    if (peek(',')) {
                        position++;
                        continue;
                    }
                    expect('}');
                    return map;
                }
            }

            List<Object> parseArray(int depth) {
                expect('[');
                List<Object> list = new ArrayList<>();
                skipWhitespace();
                if (peek(']')) {
                    position++;
                    return list;
                }
                while (true) {
                    list.add(parseValue(depth + 1));
                    skipWhitespace();
                    if (peek(',')) {
                        position++;
                        continue;
                    }
                    expect(']');
                    return list;
                }
            }

            String parseString() {
                expect('"');
                StringBuilder out = new StringBuilder();
                while (!atEnd()) {
                    char c = text.charAt(position++);
                    if (c == '"') return out.toString();
                    if (c == '\\') {
                        if (atEnd()) throw new IllegalArgumentException("Unfinished escape sequence.");
                        char escape = text.charAt(position++);
                        switch (escape) {
                            case '"': out.append('"'); break;
                            case '\\': out.append('\\'); break;
                            case '/': out.append('/'); break;
                            case 'b': out.append('\b'); break;
                            case 'f': out.append('\f'); break;
                            case 'n': out.append('\n'); break;
                            case 'r': out.append('\r'); break;
                            case 't': out.append('\t'); break;
                            case 'u':
                                if (position + 4 > text.length()) {
                                    throw new IllegalArgumentException("Invalid unicode escape.");
                                }
                                String hex = text.substring(position, position + 4);
                                try {
                                    out.append((char) Integer.parseInt(hex, 16));
                                } catch (NumberFormatException ex) {
                                    throw new IllegalArgumentException("Invalid unicode escape: \\u" + hex);
                                }
                                position += 4;
                                break;
                            default:
                                throw new IllegalArgumentException("Invalid escape character: \\" + escape);
                        }
                    } else if (c < 0x20) {
                        throw new IllegalArgumentException("Unescaped control character in string.");
                    } else {
                        out.append(c);
                    }
                }
                throw new IllegalArgumentException("Unterminated string.");
            }

            Number parseNumber() {
                int start = position;
                if (peek('-')) position++;
                while (!atEnd() && Character.isDigit(text.charAt(position))) position++;
                boolean decimal = false;
                if (!atEnd() && text.charAt(position) == '.') {
                    decimal = true;
                    position++;
                    while (!atEnd() && Character.isDigit(text.charAt(position))) position++;
                }
                if (!atEnd() && (text.charAt(position) == 'e' || text.charAt(position) == 'E')) {
                    decimal = true;
                    position++;
                    if (!atEnd() && (text.charAt(position) == '+' || text.charAt(position) == '-')) position++;
                    while (!atEnd() && Character.isDigit(text.charAt(position))) position++;
                }
                String number = text.substring(start, position);
                if (number.isEmpty() || "-".equals(number)) {
                    throw new IllegalArgumentException("Invalid number at position " + start);
                }
                try {
                    if (decimal) return Double.parseDouble(number);
                    return Long.parseLong(number);
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Invalid number: " + number);
                }
            }

            Object parseKeyword(String keyword, Object value) {
                if (!text.startsWith(keyword, position)) {
                    throw new IllegalArgumentException("Invalid literal at position " + position);
                }
                position += keyword.length();
                return value;
            }

            boolean peek(char c) {
                return !atEnd() && text.charAt(position) == c;
            }

            void expect(char c) {
                if (!peek(c)) {
                    throw new IllegalArgumentException("Expected '" + c + "' at position " + position);
                }
                position++;
            }
        }
    }
}
