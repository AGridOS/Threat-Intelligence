<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
date_default_timezone_set('Europe/Brussels');

$config = [
    // -----------------------------------------------------------------
    // Open-source example settings (set these for your deployment)
    // -----------------------------------------------------------------
    'site_name' => 'Example Threat Map',
    'source_name' => 'Example Threat Provider',
    'source_url' => 'https://provider.example.com',

    // UI/display settings
    'ui' => [
        // Maximum number of threats rendered on the map.
        // The paged table below the map still works on full dataset.
        'max_map_threats' => 3000,
    ],

    // Request protection / anti-scraping settings
    'security' => [
        'rate_limit_enabled' => true,
        'session_window_seconds' => 60,
        'session_max_requests' => 90,
        'ip_window_seconds' => 60,
        'ip_max_requests' => 180,
        'challenge_score_threshold' => 35,
        'challenge_session_threshold' => 30,
        'challenge_ip_threshold' => 70,
        'block_score_threshold' => 85,
        'block_session_threshold' => 160,
        'block_ip_threshold' => 320,
        'human_verify_ttl_seconds' => 1800,
    ],

    // Database (provided)
    'db' => [
        'host' => '127.0.0.1',
        'name' => 'example_threats',
        'user' => 'example_user',
        'pass' => 'change_me',
        'charset' => 'utf8mb4',
    ],

    // External API settings
    'api' => [
        'endpoint' => 'https://globalthreatsignal.org/api/v1/threats/query',
        'api_key' => 'replace_with_api_key',
        'fetch_interval_hours' => 12,
        'timeout_seconds' => 20,
        'limit' => 500,
        'log_enabled' => true,
        'log_file' => __DIR__ . '/logs/threat-api.log',
    ],

    // Contact/admin settings
    'admin' => [
        'email' => 'admin@example.com',
        // Admin password (plain text or password_hash() output). Change immediately.
        'password' => 'ChangeMeNow!123',
    ],

    // Mail transport settings for app emails
    'mail' => [
        'from_email' => 'no-reply@example.com',
        'from_name' => 'Example Threat Map',
        // If empty, app falls back to admin.email above.
        'admin_email' => 'admin@example.com',
        // SMTP reference values (example)
        'smtp_host' => 'smtp.example.com',
        'smtp_port' => 587,
        'smtp_username' => 'smtp-user@example.com',
        'smtp_password' => 'change_me',
        'smtp_secure' => 'tls',
        // This app sends via PHP mail() by default.
    ],
];

function e(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function appLog(array $config, string $message, array $context = []): void
{
    $enabled = (bool)($config['api']['log_enabled'] ?? false);
    if (!$enabled) {
        return;
    }

    $logFile = (string)($config['api']['log_file'] ?? (__DIR__ . '/logs/threat-api.log'));
    $logDir = dirname($logFile);
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0775, true);
    }

    $line = '[' . date('Y-m-d H:i:s') . '] ' . $message;
    if ($context) {
        $json = json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (is_string($json)) {
            $line .= ' | ' . $json;
        }
    }
    $line .= PHP_EOL;
    @file_put_contents($logFile, $line, FILE_APPEND);
}

function sendSecurityHeaders(): void
{
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header("Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://unpkg.com; script-src 'self' 'unsafe-inline' https://unpkg.com; connect-src 'self'; font-src 'self' https:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'");
}

function db(array $config): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=%s',
        $config['db']['host'],
        $config['db']['name'],
        $config['db']['charset']
    );

    $pdo = new PDO($dsn, $config['db']['user'], $config['db']['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

function initSchema(PDO $pdo): void
{
    $pdo->exec("CREATE TABLE IF NOT EXISTS app_settings (
        setting_key VARCHAR(120) PRIMARY KEY,
        setting_value TEXT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS threat_events (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        external_id VARCHAR(120) NOT NULL,
        title VARCHAR(255) NOT NULL,
        slug VARCHAR(255) NOT NULL,
        category VARCHAR(120) NOT NULL,
        country VARCHAR(120) NULL,
        region VARCHAR(120) NULL,
        latitude DECIMAL(10,7) NULL,
        longitude DECIMAL(10,7) NULL,
        details_url TEXT NULL,
        summary TEXT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'active',
        started_at DATETIME NULL,
        raw_json JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_threat_external_id (external_id),
        KEY idx_threat_status (status),
        KEY idx_threat_category (category),
        KEY idx_threat_slug (slug)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $columnCheck = $pdo->prepare("SELECT COUNT(*) AS c
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'threat_events'
          AND COLUMN_NAME = 'long_description'");
    $columnCheck->execute();
    $columnExists = (int)(($columnCheck->fetch())['c'] ?? 0) > 0;
    if (!$columnExists) {
        $pdo->exec("ALTER TABLE threat_events ADD COLUMN long_description MEDIUMTEXT NULL AFTER summary");
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS risk_assessments (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(180) NOT NULL,
        body MEDIUMTEXT NOT NULL,
        tags VARCHAR(255) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        KEY idx_risk_title (title),
        KEY idx_risk_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $tagsColumnCheck = $pdo->prepare("SELECT CHARACTER_MAXIMUM_LENGTH AS len
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'risk_assessments'
          AND COLUMN_NAME = 'tags'
        LIMIT 1");
    $tagsColumnCheck->execute();
    $tagsColumnLen = (int)(($tagsColumnCheck->fetch())['len'] ?? 0);
    if ($tagsColumnLen > 0 && $tagsColumnLen < 512) {
        $pdo->exec("ALTER TABLE risk_assessments MODIFY tags VARCHAR(512) NULL");
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS daily_visits (
        visit_date DATE NOT NULL,
        visitor_hash CHAR(64) NOT NULL,
        hits INT UNSIGNED NOT NULL DEFAULT 1,
        first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (visit_date, visitor_hash),
        KEY idx_visit_date (visit_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

}

function getSetting(PDO $pdo, string $key, ?string $default = null): ?string
{
    $stmt = $pdo->prepare('SELECT setting_value FROM app_settings WHERE setting_key = ? LIMIT 1');
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return $row ? (string) $row['setting_value'] : $default;
}

function setSetting(PDO $pdo, string $key, string $value): void
{
    $stmt = $pdo->prepare('INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)');
    $stmt->execute([$key, $value]);
}

function getClientIp(): string
{
    $candidates = [
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
        $_SERVER['REMOTE_ADDR'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (!$candidate) {
            continue;
        }
        $ip = trim(explode(',', $candidate)[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    return '0.0.0.0';
}

function trackVisit(PDO $pdo): void
{
    $ip = getClientIp();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $hash = hash('sha256', $ip . '|' . $ua);

    $stmt = $pdo->prepare("INSERT INTO daily_visits (visit_date, visitor_hash, hits) VALUES (CURDATE(), ?, 1)
        ON DUPLICATE KEY UPDATE hits = hits + 1, last_seen = CURRENT_TIMESTAMP");
    $stmt->execute([$hash]);
}

function slugify(string $text): string
{
    $text = strtolower(trim($text));
    $text = preg_replace('/[^a-z0-9]+/i', '-', $text) ?? '';
    $text = trim($text, '-');
    return $text !== '' ? $text : 'threat';
}

function normalizeCategory(string $raw): string
{
    $rawL = strtolower(trim($raw));
    $map = [
        'environmental' => 'Environmental',
        'climate' => 'Environmental',
        'geopolitical conflict' => 'Geopolitical Conflict',
        'geopolitical' => 'Geopolitical Conflict',
        'technology' => 'Technology',
        'cyber' => 'Technology',
        'health' => 'Health',
        'economic' => 'Economic',
        'criminal' => 'Large Criminal Activity',
        'large criminal activity' => 'Large Criminal Activity',
        'crime' => 'Large Criminal Activity',
    ];

    if (isset($map[$rawL])) {
        return $map[$rawL];
    }

    foreach ($map as $k => $v) {
        if (str_contains($rawL, $k)) {
            return $v;
        }
    }

    return 'Technology';
}

function europeCountries(): array
{
    return [
        'Albania','Andorra','Austria','Belarus','Belgium','Bosnia and Herzegovina','Bulgaria','Croatia','Cyprus',
        'Czech Republic','Denmark','Estonia','Finland','France','Germany','Greece','Hungary','Iceland','Ireland',
        'Italy','Kosovo','Latvia','Liechtenstein','Lithuania','Luxembourg','Malta','Moldova','Monaco','Montenegro',
        'Netherlands','North Macedonia','Norway','Poland','Portugal','Romania','San Marino','Serbia','Slovakia',
        'Slovenia','Spain','Sweden','Switzerland','Ukraine','United Kingdom','Vatican City'
    ];
}

function apiEuropeCountriesFilter(): array
{
    // Conservative country set for API-side filtering (avoids invalid-country 400 responses).
    return [
        'Austria', 'Belgium', 'Bulgaria', 'Croatia', 'Cyprus', 'Czech Republic', 'Denmark',
        'Estonia', 'Finland', 'France', 'Germany', 'Greece', 'Hungary', 'Ireland', 'Italy',
        'Latvia', 'Lithuania', 'Luxembourg', 'Malta', 'Netherlands', 'Norway', 'Poland',
        'Portugal', 'Romania', 'Slovakia', 'Slovenia', 'Spain', 'Sweden', 'Switzerland',
        'United Kingdom', 'Ukraine', 'Serbia', 'Bosnia and Herzegovina', 'Albania', 'Montenegro',
        'North Macedonia', 'Moldova', 'Belarus', 'Iceland'
    ];
}

function countryCentroid(string $country): ?array
{
    static $map = [
        'albania' => [41.1533, 20.1683], 'andorra' => [42.5063, 1.5218], 'austria' => [47.5162, 14.5501],
        'belarus' => [53.7098, 27.9534], 'belgium' => [50.5039, 4.4699], 'bosnia and herzegovina' => [43.9159, 17.6791],
        'bulgaria' => [42.7339, 25.4858], 'croatia' => [45.1, 15.2], 'cyprus' => [35.1264, 33.4299],
        'czech republic' => [49.8175, 15.473], 'denmark' => [56.2639, 9.5018], 'estonia' => [58.5953, 25.0136],
        'finland' => [61.9241, 25.7482], 'france' => [46.2276, 2.2137], 'germany' => [51.1657, 10.4515],
        'greece' => [39.0742, 21.8243], 'hungary' => [47.1625, 19.5033], 'iceland' => [64.9631, -19.0208],
        'ireland' => [53.4129, -8.2439], 'italy' => [41.8719, 12.5674], 'kosovo' => [42.6026, 20.903],
        'latvia' => [56.8796, 24.6032], 'liechtenstein' => [47.166, 9.5554], 'lithuania' => [55.1694, 23.8813],
        'luxembourg' => [49.8153, 6.1296], 'malta' => [35.9375, 14.3754], 'moldova' => [47.4116, 28.3699],
        'monaco' => [43.7384, 7.4246], 'montenegro' => [42.7087, 19.3744], 'netherlands' => [52.1326, 5.2913],
        'north macedonia' => [41.6086, 21.7453], 'norway' => [60.472, 8.4689], 'poland' => [51.9194, 19.1451],
        'portugal' => [39.3999, -8.2245], 'romania' => [45.9432, 24.9668], 'san marino' => [43.9424, 12.4578],
        'serbia' => [44.0165, 21.0059], 'slovakia' => [48.669, 19.699], 'slovenia' => [46.1512, 14.9955],
        'spain' => [40.4637, -3.7492], 'sweden' => [60.1282, 18.6435], 'switzerland' => [46.8182, 8.2275],
        'ukraine' => [48.3794, 31.1656], 'united kingdom' => [55.3781, -3.436], 'vatican city' => [41.9029, 12.4534],
        'vatican' => [41.9029, 12.4534]
    ];

    $key = strtolower(trim($country));
    return $map[$key] ?? null;
}

function detectCountryFromEvent(array $event): string
{
    $country = trim((string)($event['country'] ?? $event['country_name'] ?? ''));
    if ($country !== '') {
        return $country;
    }

    $location = strtolower((string)($event['location'] ?? $event['location_text'] ?? $event['region'] ?? ''));
    if ($location === '') {
        return '';
    }

    foreach (europeCountries() as $candidate) {
        if (str_contains($location, strtolower($candidate))) {
            return $candidate;
        }
    }

    return '';
}

function isLikelyEurope(array $event): bool
{
    $region = strtolower((string)($event['region'] ?? $event['area'] ?? $event['continent'] ?? ''));
    $country = strtolower(detectCountryFromEvent($event));

    if (str_contains($region, 'europe')) {
        return true;
    }

    $europeCountries = array_map('strtolower', europeCountries());

    foreach ($europeCountries as $c) {
        if (str_contains($country, $c)) {
            return true;
        }
    }

    $lat = isset($event['latitude']) ? (float)$event['latitude'] : (isset($event['lat']) ? (float)$event['lat'] : null);
    $lng = isset($event['longitude']) ? (float)$event['longitude'] : (isset($event['lng']) ? (float)$event['lng'] : (isset($event['lon']) ? (float)$event['lon'] : null));

    if ($lat !== null && $lng !== null) {
        return $lat >= 34.0 && $lat <= 72.0 && $lng >= -25.0 && $lng <= 45.0;
    }

    return false;
}

function fetchThreatEventsFromApi(array $config): array
{
    $endpoint = (string)$config['api']['endpoint'];
    $apiKey = (string)$config['api']['api_key'];
    $limit = max(1, min(500, (int)($config['api']['limit'] ?? 500)));
    $offset = 0;
    $maxOffset = 5000;
    $result = [];

    if ($apiKey === '') {
        appLog($config, 'API fetch aborted: missing API key');
        return [];
    }

    appLog($config, 'API fetch start', [
        'endpoint' => $endpoint,
        'limit' => $limit,
        'maxOffset' => $maxOffset,
        'api_key_length' => strlen($apiKey),
    ]);

    do {
        $payload = [
            'countries' => apiEuropeCountriesFilter(),
            'include_reviewed_by_human' => true,
            'include_advanced_ai' => true,
            'include_direct_response' => true,
            'include_inactive' => false,
            'limit' => $limit,
            'offset' => $offset,
        ];

        appLog($config, 'API request payload', [
            'offset' => $offset,
            'limit' => $limit,
            'countries_count' => count($payload['countries']),
            'include_inactive' => $payload['include_inactive'],
        ]);

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => (int)$config['api']['timeout_seconds'],
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Content-Type: application/json',
                'X-API-Key: ' . $apiKey,
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErrNo = curl_errno($ch);
        $curlErr = curl_error($ch);
        curl_close($ch);

        appLog($config, 'API response received', [
            'http_code' => $httpCode,
            'curl_errno' => $curlErrNo,
            'curl_error' => $curlErr,
            'response_preview' => is_string($response) ? mb_substr($response, 0, 800) : null,
        ]);

        if (!is_string($response) || $response === '' || $httpCode >= 400) {
            appLog($config, 'API response rejected', [
                'reason' => 'empty response or HTTP error',
                'http_code' => $httpCode,
                'curl_errno' => $curlErrNo,
                'curl_error' => $curlErr,
            ]);
            break;
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            appLog($config, 'API decode failed', ['json_last_error' => json_last_error_msg()]);
            break;
        }

        $data = [];
        if (isset($decoded['data']) && is_array($decoded['data'])) {
            $data = $decoded['data'];
        } elseif (isset($decoded['events']) && is_array($decoded['events'])) {
            $data = $decoded['events'];
        }

        if (!$data) {
            appLog($config, 'API returned empty data', [
                'meta' => $decoded['meta'] ?? null,
            ]);
            break;
        }

        foreach ($data as $item) {
        if (!is_array($item)) {
            continue;
        }

        $status = strtolower((string)($item['status'] ?? $item['state'] ?? 'active'));
        if ($status !== 'active') {
            continue;
        }
        if (!isLikelyEurope($item)) {
            continue;
        }

        $title = trim((string)($item['title'] ?? $item['name'] ?? 'Untitled Threat'));
        $summary = trim((string)($item['short_description'] ?? $item['shortDescription'] ?? $item['summary'] ?? ''));
        $longDescription = trim((string)($item['long_description'] ?? $item['longDescription'] ?? $item['description'] ?? $item['details'] ?? $item['full_description'] ?? $item['content'] ?? ''));
        if ($summary === '' && $longDescription !== '') {
            $summary = mb_substr(trim(strip_tags($longDescription)), 0, 280);
        }
        if ($longDescription === '' && $summary !== '') {
            $longDescription = $summary;
        }
        $cat = normalizeCategory((string)($item['category'] ?? $item['type'] ?? 'Technology'));

        $countryDetected = detectCountryFromEvent($item);

        $lat = $item['latitude'] ?? $item['lat'] ?? ($item['geo']['lat'] ?? null);
        $lng = $item['longitude'] ?? $item['lng'] ?? $item['lon'] ?? ($item['geo']['lng'] ?? null);
        $lat = is_numeric($lat) ? (float)$lat : null;
        $lng = is_numeric($lng) ? (float)$lng : null;

        if ($lat === null || $lng === null) {
            $centroid = countryCentroid($countryDetected);
            if ($centroid) {
                $lat = $centroid[0];
                $lng = $centroid[1];
            }
        }

        $externalId = (string)($item['id'] ?? $item['event_id'] ?? '');
        if ($externalId === '') {
            $externalId = hash('sha1', $title . '|' . (string)$lat . '|' . (string)$lng . '|' . (string)($item['started_at'] ?? $item['date'] ?? ''));
        }

        $result[] = [
            'external_id' => $externalId,
            'title' => $title,
            'slug' => slugify($title),
            'category' => $cat,
            'country' => $countryDetected,
            'region' => (string)($item['region'] ?? $item['area'] ?? 'Europe'),
            'latitude' => $lat,
            'longitude' => $lng,
            'details_url' => (string)($item['details_url'] ?? $item['url'] ?? ''),
            'summary' => $summary,
            'long_description' => $longDescription,
            'status' => 'active',
            'started_at' => (string)($item['started_at'] ?? $item['date'] ?? ''),
            'raw_json' => json_encode($item, JSON_UNESCAPED_UNICODE),
        ];
    }

        $receivedCount = count($data);
        $total = (int)($decoded['meta']['total'] ?? 0);
        appLog($config, 'API page processed', [
            'offset' => $offset,
            'received_count' => $receivedCount,
            'meta_total' => $total,
            'accumulated_events' => count($result),
        ]);
        $offset += $limit;
        $continue = $receivedCount === $limit && $offset <= $maxOffset && ($total === 0 || $offset < $total);
    } while ($continue);

    appLog($config, 'API fetch completed', [
        'stored_candidate_events' => count($result),
    ]);

    return $result;
}

function refreshThreatDataIfDue(PDO $pdo, array $config): void
{
    $last = getSetting($pdo, 'last_api_fetch_at');
    $hours = (int)$config['api']['fetch_interval_hours'];
    $due = true;

    $countStmt = $pdo->query('SELECT COUNT(*) AS c FROM threat_events');
    $countRow = $countStmt->fetch();
    $isEmpty = ((int)($countRow['c'] ?? 0)) === 0;

    if ($isEmpty) {
        $due = true;
        appLog($config, 'Refresh reason: threat_events table empty, forcing immediate API fetch');
    }

    if (!$isEmpty && $last) {
        $due = (time() - strtotime($last)) >= ($hours * 3600);
        if (!$due) {
            appLog($config, 'Refresh skipped: interval not reached', [
                'last_fetch_at' => $last,
                'hours_required' => $hours,
            ]);
        }
    }

    if (!$due) {
        return;
    }

    $events = fetchThreatEventsFromApi($config);
    if (!$events) {
        appLog($config, 'No events returned from API fetch', [
            'table_empty' => $isEmpty,
        ]);
        setSetting($pdo, 'last_api_fetch_at', date('Y-m-d H:i:s'));
        setSetting($pdo, 'last_api_fetch_count', '0');
        return;
    }

    $sql = "INSERT INTO threat_events
        (external_id, title, slug, category, country, region, latitude, longitude, details_url, summary, long_description, status, started_at, raw_json)
        VALUES
        (:external_id, :title, :slug, :category, :country, :region, :latitude, :longitude, :details_url, :summary, :long_description, :status, :started_at, :raw_json)
        ON DUPLICATE KEY UPDATE
            title = VALUES(title),
            slug = VALUES(slug),
            category = VALUES(category),
            country = VALUES(country),
            region = VALUES(region),
            latitude = VALUES(latitude),
            longitude = VALUES(longitude),
            details_url = VALUES(details_url),
            summary = VALUES(summary),
            long_description = VALUES(long_description),
            status = VALUES(status),
            started_at = VALUES(started_at),
            raw_json = VALUES(raw_json)";

    $stmt = $pdo->prepare($sql);
    $dedupeByTitleCountryStmt = $pdo->prepare('SELECT external_id FROM threat_events WHERE LOWER(title) = LOWER(?) AND LOWER(COALESCE(country, "")) = LOWER(?) LIMIT 1');
    foreach ($events as $event) {
        $dedupeByTitleCountryStmt->execute([
            (string)$event['title'],
            (string)($event['country'] ?? ''),
        ]);
        $existingByTitleCountry = $dedupeByTitleCountryStmt->fetch();
        if ($existingByTitleCountry && !empty($existingByTitleCountry['external_id'])) {
            // If same title+country already exists, force upsert against that existing row.
            $event['external_id'] = (string)$existingByTitleCountry['external_id'];
        }

        $startedAt = $event['started_at'] !== '' ? date('Y-m-d H:i:s', strtotime($event['started_at'])) : null;
        $stmt->execute([
            ':external_id' => $event['external_id'],
            ':title' => $event['title'],
            ':slug' => $event['slug'],
            ':category' => $event['category'],
            ':country' => $event['country'] ?: null,
            ':region' => $event['region'] ?: null,
            ':latitude' => $event['latitude'],
            ':longitude' => $event['longitude'],
            ':details_url' => $event['details_url'] ?: null,
            ':summary' => $event['summary'] ?: null,
            ':long_description' => $event['long_description'] ?: null,
            ':status' => 'active',
            ':started_at' => $startedAt,
            ':raw_json' => $event['raw_json'],
        ]);
    }

    appLog($config, 'Threat events upsert complete', [
        'events_count' => count($events),
    ]);
    setSetting($pdo, 'last_api_fetch_at', date('Y-m-d H:i:s'));
    setSetting($pdo, 'last_api_fetch_count', (string)count($events));
}

function isAdminLoggedIn(): bool
{
    return !empty($_SESSION['is_admin']);
}

function requireAdmin(): void
{
    if (!isAdminLoggedIn()) {
        header('Location: index.php?p=login');
        exit;
    }
}

function getCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(): bool
{
    $token = $_POST['csrf_token'] ?? '';
    return is_string($token) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function ensureContactChallenge(): void
{
    if (!isset($_SESSION['contact_human_a'], $_SESSION['contact_human_b'])) {
        $_SESSION['contact_human_a'] = random_int(2, 9);
        $_SESSION['contact_human_b'] = random_int(1, 9);
    }
}

function getContactChallengeQuestion(): string
{
    ensureContactChallenge();
    $a = (int)$_SESSION['contact_human_a'];
    $b = (int)$_SESSION['contact_human_b'];
    return "What is {$a} + {$b}?";
}

function verifyContactChallenge(string $answer): bool
{
    ensureContactChallenge();
    if (!preg_match('/^\d{1,3}$/', trim($answer))) {
        return false;
    }
    $expected = (int)$_SESSION['contact_human_a'] + (int)$_SESSION['contact_human_b'];
    return ((int)$answer) === $expected;
}

function resetContactChallenge(): void
{
    unset($_SESSION['contact_human_a'], $_SESSION['contact_human_b']);
}

function ensureBotChallenge(): void
{
    if (!isset($_SESSION['bot_human_a'], $_SESSION['bot_human_b'], $_SESSION['bot_human_op'])) {
        $_SESSION['bot_human_a'] = random_int(2, 15);
        $_SESSION['bot_human_b'] = random_int(1, 12);
        $_SESSION['bot_human_op'] = random_int(0, 1) === 1 ? '+' : '*';
    }
}

function getBotChallengeQuestion(): string
{
    ensureBotChallenge();
    $a = (int)$_SESSION['bot_human_a'];
    $b = (int)$_SESSION['bot_human_b'];
    $op = (string)$_SESSION['bot_human_op'];
    return "Solve: {$a} {$op} {$b} = ?";
}

function verifyBotChallenge(string $answer): bool
{
    ensureBotChallenge();
    if (!preg_match('/^-?\d{1,6}$/', trim($answer))) {
        return false;
    }
    $a = (int)$_SESSION['bot_human_a'];
    $b = (int)$_SESSION['bot_human_b'];
    $op = (string)$_SESSION['bot_human_op'];
    $expected = $op === '*' ? ($a * $b) : ($a + $b);
    return ((int)$answer) === $expected;
}

function resetBotChallenge(): void
{
    unset($_SESSION['bot_human_a'], $_SESSION['bot_human_b'], $_SESSION['bot_human_op']);
}

function isHumanVerified(array $config): bool
{
    $until = (int)($_SESSION['human_verified_until'] ?? 0);
    return $until > time();
}

function markHumanVerified(array $config): void
{
    $ttl = max(300, (int)($config['security']['human_verify_ttl_seconds'] ?? 1800));
    $_SESSION['human_verified_until'] = time() + $ttl;
}

function rateLimitDir(array $config): string
{
    $base = dirname((string)($config['api']['log_file'] ?? (__DIR__ . '/logs/threat-api.log')));
    $dir = $base . '/ratelimit';
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    return $dir;
}

function updateHitWindow(array $hits, int $windowSeconds): array
{
    $now = time();
    $minTs = $now - max(1, $windowSeconds);
    $filtered = [];
    foreach ($hits as $ts) {
        $n = (int)$ts;
        if ($n >= $minTs && $n <= $now + 2) {
            $filtered[] = $n;
        }
    }
    $filtered[] = $now;
    return $filtered;
}

function updateIpHitWindow(array $config, string $ip, int $windowSeconds): array
{
    $file = rateLimitDir($config) . '/' . sha1($ip) . '.json';
    $stored = [];
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        if (is_array($decoded) && isset($decoded['hits']) && is_array($decoded['hits'])) {
            $stored = $decoded['hits'];
        }
    }

    $updated = updateHitWindow($stored, $windowSeconds);
    @file_put_contents($file, json_encode(['hits' => $updated], JSON_UNESCAPED_UNICODE));
    return $updated;
}

function botScoreForRequest(string $page): int
{
    $score = 0;
    $ua = strtolower(trim((string)($_SERVER['HTTP_USER_AGENT'] ?? '')));
    $accept = strtolower(trim((string)($_SERVER['HTTP_ACCEPT'] ?? '')));
    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $uri = strtolower((string)($_SERVER['REQUEST_URI'] ?? ''));

    if ($ua === '') {
        $score += 30;
    }

    $botSignals = [
        'bot', 'spider', 'crawler', 'scrapy', 'python-requests', 'curl/', 'wget/',
        'httpclient', 'go-http-client', 'axios', 'aiohttp', 'java/', 'okhttp',
    ];
    foreach ($botSignals as $sig) {
        if ($ua !== '' && str_contains($ua, $sig)) {
            $score += 35;
            break;
        }
    }

    if ($accept === '' || $accept === '*/*') {
        $score += 8;
    }

    if (!in_array($method, ['GET', 'POST'], true)) {
        $score += 25;
    }

    if (in_array($page, ['show_threat_details', 'risk_view'], true)) {
        $score += 6;
    }

    if (preg_match('/[?&]page=\d{2,}/', $uri) === 1) {
        $score += 8;
    }

    if (preg_match('/[?&](offset|limit)=\d+/', $uri) === 1) {
        $score += 8;
    }

    return $score;
}

function sanitizeReturnTarget(string $target): string
{
    $target = trim($target);
    $target = preg_replace('/[\r\n]+/', '', $target) ?? '';
    if ($target === '' || str_contains($target, '://') || str_starts_with($target, '//')) {
        return 'index.php';
    }
    if (str_starts_with($target, '/')) {
        return $target;
    }
    if (!str_starts_with($target, 'index.php')) {
        return 'index.php';
    }
    return $target;
}

function evaluateRequestProtection(array $config, string $page): array
{
    if (isAdminLoggedIn()) {
        return ['blocked' => false, 'require_challenge' => false, 'bot_score' => 0, 'session_hits' => 0, 'ip_hits' => 0];
    }

    if (!(bool)($config['security']['rate_limit_enabled'] ?? true)) {
        return ['blocked' => false, 'require_challenge' => false, 'bot_score' => 0, 'session_hits' => 0, 'ip_hits' => 0];
    }

    $protectedPages = [
        'home', 'show_threat_details', 'risk_assessments', 'risk_view', 'sitemap', 'notifications',
    ];
    if (!in_array($page, $protectedPages, true)) {
        return ['blocked' => false, 'require_challenge' => false, 'bot_score' => 0, 'session_hits' => 0, 'ip_hits' => 0];
    }

    $sessionWindowSeconds = max(10, (int)($config['security']['session_window_seconds'] ?? 60));
    $sessionHits = updateHitWindow((array)($_SESSION['rate_limit_hits'] ?? []), $sessionWindowSeconds);
    $_SESSION['rate_limit_hits'] = $sessionHits;

    $ipWindowSeconds = max(10, (int)($config['security']['ip_window_seconds'] ?? 60));
    $ip = getClientIp();
    $ipHits = updateIpHitWindow($config, $ip, $ipWindowSeconds);

    $sessionCount = count($sessionHits);
    $ipCount = count($ipHits);
    $botScore = botScoreForRequest($page);

    $block =
        $botScore >= (int)($config['security']['block_score_threshold'] ?? 85)
        || $sessionCount >= (int)($config['security']['block_session_threshold'] ?? 160)
        || $ipCount >= (int)($config['security']['block_ip_threshold'] ?? 320);

    if ($block) {
        return [
            'blocked' => true,
            'require_challenge' => false,
            'bot_score' => $botScore,
            'session_hits' => $sessionCount,
            'ip_hits' => $ipCount,
        ];
    }

    $rateExceeded =
        $sessionCount >= (int)($config['security']['session_max_requests'] ?? 90)
        || $ipCount >= (int)($config['security']['ip_max_requests'] ?? 180);

    $needsChallenge =
        !isHumanVerified($config)
        && (
            $rateExceeded
            || $botScore >= (int)($config['security']['challenge_score_threshold'] ?? 35)
            || $sessionCount >= (int)($config['security']['challenge_session_threshold'] ?? 30)
            || $ipCount >= (int)($config['security']['challenge_ip_threshold'] ?? 70)
        );

    return [
        'blocked' => false,
        'require_challenge' => $needsChallenge,
        'bot_score' => $botScore,
        'session_hits' => $sessionCount,
        'ip_hits' => $ipCount,
    ];
}

function sanitizePlainInput(string $value, int $maxLen = 255): string
{
    $value = strip_tags($value);
    $value = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $value) ?? $value;
    $value = trim(preg_replace('/\s+/u', ' ', $value) ?? $value);
    if ($maxLen > 0) {
        $value = mb_substr($value, 0, $maxLen);
    }
    return $value;
}

function parseTags(string $tags): array
{
    $parts = array_filter(array_map('trim', explode(',', $tags)), fn($x) => $x !== '');
    $parts = array_slice($parts, 0, 10);
    $clean = [];
    foreach ($parts as $tag) {
        $tag = sanitizePlainInput($tag, 50);
        $tag = preg_replace('/[^a-zA-Z0-9\s\-]/', '', $tag) ?? '';
        $tag = trim($tag);
        if ($tag !== '') {
            $clean[] = $tag;
        }
    }
    return array_values(array_unique($clean));
}

function sanitizeRiskBody(string $body): string
{
    $allowed = '<p><br><strong><em><b><i><ul><ol><li><a><blockquote><h3><h4>';
    $clean = trim(strip_tags($body, $allowed));

    // Remove inline event handlers and style attributes.
    $clean = preg_replace('/\son[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $clean) ?? $clean;
    $clean = preg_replace('/\sstyle\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $clean) ?? $clean;

    // Neutralize javascript/data/vbscript links in href attributes.
    $clean = preg_replace_callback(
        '/<a\b([^>]*)href\s*=\s*("|\')([^"\']*)(\2)([^>]*)>/i',
        static function (array $m): string {
            $url = trim($m[3]);
            if (preg_match('/^(javascript:|vbscript:|data:)/i', $url)) {
                $url = '#';
            }
            return '<a' . $m[1] . 'href="' . htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"' . $m[5] . '>';
        },
        $clean
    ) ?? $clean;

    return $clean;
}

function sendContactEmail(array $config, string $name, string $email, string $subject, string $message): bool
{
    $to = trim((string)($config['mail']['admin_email'] ?? ''));
    if ($to === '') {
        $to = (string)($config['admin']['email'] ?? '');
    }
    $fromEmail = $config['mail']['from_email'];
    $fromName = $config['mail']['from_name'];

    $safeName = trim(preg_replace('/[\r\n]+/', ' ', $name) ?? $name);
    $safeEmail = trim(preg_replace('/[\r\n]+/', ' ', $email) ?? $email);
    $safeSubject = trim(preg_replace('/[\r\n]+/', ' ', $subject) ?? $subject);
    $safeMessage = trim($message);

    $mailSubject = '[' . ($config['site_name'] ?? 'Site') . ' Contact] ' . $safeSubject;
    $body = "Name: {$safeName}\nEmail: {$safeEmail}\n\nMessage:\n{$safeMessage}\n";
    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'From: ' . $fromName . ' <' . $fromEmail . '>',
        'Reply-To: ' . $safeEmail,
        'X-Mailer: PHP/' . phpversion(),
    ];

    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $additionalParams = '-f' . $fromEmail;
    return @mail($to, $mailSubject, $body, implode("\r\n", $headers), $additionalParams);
}

function verifyAdminPassword(string $inputPassword, string $storedValue): bool
{
    if (str_starts_with($storedValue, '$2y$') || str_starts_with($storedValue, '$2a$') || str_starts_with($storedValue, '$argon2')) {
        return password_verify($inputPassword, $storedValue);
    }
    return hash_equals($storedValue, $inputPassword);
}

$pdo = db($config);
initSchema($pdo);
trackVisit($pdo);
refreshThreatDataIfDue($pdo, $config);

$p = $_GET['p'] ?? 'home';
$flash = '';
$error = '';

$allowedPages = [
    'home',
    'verify-human',
    'sitemap',
    'show_threat_details',
    'risk_assessments',
    'risk_view',
    'risk_edit',
    'risk_save',
    'risk_delete',
    'analytics',
    'contact',
    'cookie-policy',
    'login',
    'logout',
    'notifications',
];
if (!in_array($p, $allowedPages, true)) {
    header('Location: index.php');
    exit;
}

sendSecurityHeaders();

if ($p === 'verify-human' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $answer = trim((string)($_POST['human_check'] ?? ''));
    $returnTarget = sanitizeReturnTarget((string)($_POST['return'] ?? 'index.php'));
    if (!verifyCsrfToken()) {
        $error = 'Invalid form token. Please retry.';
    } elseif (!verifyBotChallenge($answer)) {
        $error = 'Verification failed. Please solve the challenge correctly.';
    } else {
        markHumanVerified($config);
        resetBotChallenge();
        header('Location: ' . $returnTarget);
        exit;
    }
}

if ($p === 'verify-human') {
    ensureBotChallenge();
}

$protection = evaluateRequestProtection($config, (string)$p);
if (($protection['blocked'] ?? false) === true) {
    http_response_code(429);
    if ($p === 'notifications') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Too many requests']);
    } else {
        echo 'Too many requests. Please try again later.';
    }
    exit;
}

if (($protection['require_challenge'] ?? false) === true && $p !== 'verify-human') {
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'GET') {
        http_response_code(429);
        echo 'Human verification required.';
        exit;
    }
    $target = sanitizeReturnTarget((string)($_SERVER['REQUEST_URI'] ?? 'index.php'));
    header('Location: index.php?p=verify-human&return=' . urlencode($target));
    exit;
}

if ($p === 'logout') {
    session_unset();
    session_destroy();
    header('Location: index.php');
    exit;
}

if ($p === 'notifications') {
    header('Content-Type: application/json; charset=utf-8');
    $stmt = $pdo->query('SELECT id, title, created_at FROM risk_assessments ORDER BY id DESC LIMIT 1');
    $latest = $stmt->fetch();
    echo json_encode(['latest' => $latest ?: null]);
    exit;
}

if ($p === 'sitemap') {
    header('Content-Type: application/xml; charset=UTF-8');

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'example.com';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $base = $scheme . '://' . $host . $script;
    $home = $scheme . '://' . $host . '/';

    $urls = [
        ['loc' => $home, 'changefreq' => 'hourly', 'priority' => '1.0', 'lastmod' => date('c')],
        ['loc' => $base . '?p=risk_assessments', 'changefreq' => 'daily', 'priority' => '0.8', 'lastmod' => date('c')],
        ['loc' => $base . '?p=contact', 'changefreq' => 'monthly', 'priority' => '0.6', 'lastmod' => date('c')],
        ['loc' => $base . '?p=cookie-policy', 'changefreq' => 'yearly', 'priority' => '0.3', 'lastmod' => date('c')],
    ];

    $riskStmt = $pdo->query('SELECT id, updated_at, created_at FROM risk_assessments ORDER BY id DESC');
    $riskRows = $riskStmt->fetchAll();
    foreach ($riskRows as $row) {
        $lastmodRaw = (string)($row['updated_at'] ?? $row['created_at'] ?? '');
        $lastmod = $lastmodRaw !== '' ? date('c', strtotime($lastmodRaw)) : date('c');
        $urls[] = [
            'loc' => $base . '?p=risk_view&id=' . (int)$row['id'],
            'changefreq' => 'weekly',
            'priority' => '0.7',
            'lastmod' => $lastmod,
        ];
    }

    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';
    foreach ($urls as $u) {
        echo '<url>';
        echo '<loc>' . htmlspecialchars($u['loc'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</loc>';
        echo '<lastmod>' . htmlspecialchars($u['lastmod'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</lastmod>';
        echo '<changefreq>' . htmlspecialchars($u['changefreq'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</changefreq>';
        echo '<priority>' . htmlspecialchars($u['priority'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</priority>';
        echo '</url>';
    }
    echo '</urlset>';
    exit;
}

if ($p === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $ok = hash_equals(strtolower($config['admin']['email']), strtolower($email))
        && verifyAdminPassword($password, (string)$config['admin']['password']);

    if ($ok) {
        session_regenerate_id(true);
        $_SESSION['is_admin'] = true;
        header('Location: index.php?p=risk_assessments');
        exit;
    }
    $error = 'Invalid credentials.';
}

if ($p === 'contact' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = sanitizePlainInput((string)($_POST['name'] ?? ''), 120);
    $email = trim((string)($_POST['email'] ?? ''));
    $subject = sanitizePlainInput((string)($_POST['subject'] ?? ''), 200);
    $message = trim((string)($_POST['message'] ?? ''));
    $humanCheck = trim((string)($_POST['human_check'] ?? ''));
    $websiteTrap = trim((string)($_POST['website'] ?? ''));

    if (!verifyCsrfToken()) {
        $error = 'Invalid form token. Please retry.';
    } elseif ($websiteTrap !== '') {
        $error = 'Human verification failed.';
    } elseif (!verifyContactChallenge($humanCheck)) {
        $error = 'Please solve the human verification check correctly.';
    } elseif ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $subject === '' || $message === '') {
        $error = 'Please complete all fields with a valid email.';
    } else {
        if (sendContactEmail($config, $name, $email, $subject, $message)) {
            $flash = 'Message sent successfully.';
            resetContactChallenge();
        } else {
            $error = 'Unable to send email right now. Please try again later.';
        }
    }
}

if ($p === 'contact') {
    ensureContactChallenge();
}

if ($p === 'risk_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireAdmin();
    if (!verifyCsrfToken()) {
        $error = 'Invalid CSRF token.';
    } else {
        $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
        $title = sanitizePlainInput((string)($_POST['title'] ?? ''), 180);
        $body = sanitizeRiskBody((string)($_POST['body'] ?? ''));
        $tagsArr = parseTags((string)($_POST['tags'] ?? ''));
        $tags = implode(', ', $tagsArr);

        if ($title === '' || mb_strlen($title) > 180 || strip_tags($title) !== $title) {
            $error = 'Title is required, text-only, max 180 chars.';
        } elseif ($body === '') {
            $error = 'Body is required.';
        } else {
            $dupStmt = $pdo->prepare('SELECT id FROM risk_assessments WHERE LOWER(title) = LOWER(?) AND id <> ? LIMIT 1');
            $dupStmt->execute([$title, $id]);
            $existingDup = $dupStmt->fetch();
            if ($existingDup) {
                $error = 'A risk assessment with the same title already exists.';
            }
        }

        if ($error === '') {
            if ($id > 0) {
                $stmt = $pdo->prepare('UPDATE risk_assessments SET title = ?, body = ?, tags = ? WHERE id = ?');
                $stmt->execute([$title, $body, $tags, $id]);
                header('Location: index.php?p=risk_assessments&ok=updated');
                exit;
            } else {
                $stmt = $pdo->prepare('INSERT INTO risk_assessments (title, body, tags) VALUES (?, ?, ?)');
                $stmt->execute([$title, $body, $tags]);
                header('Location: index.php?p=risk_assessments&ok=added');
                exit;
            }
        }
    }
}

if ($p === 'risk_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireAdmin();
    if (verifyCsrfToken()) {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare('DELETE FROM risk_assessments WHERE id = ?');
            $stmt->execute([$id]);
        }
    }
    header('Location: index.php?p=risk_assessments&ok=deleted');
    exit;
}

if (in_array($p, ['analytics', 'risk_edit', 'risk_save', 'risk_delete'], true) && !isAdminLoggedIn()) {
    header('Location: index.php?p=login');
    exit;
}

$allowedThreatTypes = ['Environmental', 'Geopolitical Conflict', 'Technology', 'Health', 'Economic', 'Large Criminal Activity'];
$selectedThreatType = sanitizePlainInput((string)($_GET['type'] ?? ''), 80);
if (!in_array($selectedThreatType, $allowedThreatTypes, true)) {
    $selectedThreatType = '';
}
$threatPage = max(1, (int)($_GET['page'] ?? 1));
$threatsPerPage = 20;
$threatOffset = ($threatPage - 1) * $threatsPerPage;

$threatWhereSql = "status = 'active'";
$threatParams = [];
if ($selectedThreatType !== '') {
    $threatWhereSql .= ' AND category = :category';
    $threatParams[':category'] = $selectedThreatType;
}

$threatCountStmt = $pdo->prepare("SELECT COUNT(*) AS total FROM threat_events WHERE {$threatWhereSql}");
$threatCountStmt->execute($threatParams);
$threatTotal = (int)(($threatCountStmt->fetch())['total'] ?? 0);
$threatTotalPages = max(1, (int)ceil($threatTotal / $threatsPerPage));
if ($threatPage > $threatTotalPages) {
    $threatPage = $threatTotalPages;
    $threatOffset = ($threatPage - 1) * $threatsPerPage;
}

$threatSql = "SELECT * FROM threat_events WHERE {$threatWhereSql} ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset";
$threatStmt = $pdo->prepare($threatSql);
foreach ($threatParams as $paramName => $paramValue) {
    $threatStmt->bindValue($paramName, $paramValue, PDO::PARAM_STR);
}
$threatStmt->bindValue(':limit', $threatsPerPage, PDO::PARAM_INT);
$threatStmt->bindValue(':offset', $threatOffset, PDO::PARAM_INT);
$threatStmt->execute();
$threats = $threatStmt->fetchAll();

$maxMapThreats = max(1, (int)($config['ui']['max_map_threats'] ?? 300));
$mapThreatStmt = $pdo->prepare("SELECT id, slug, title, category, country, latitude, longitude FROM threat_events WHERE {$threatWhereSql} ORDER BY created_at DESC, id DESC LIMIT :map_limit");
foreach ($threatParams as $paramName => $paramValue) {
    $mapThreatStmt->bindValue($paramName, $paramValue, PDO::PARAM_STR);
}
$mapThreatStmt->bindValue(':map_limit', $maxMapThreats, PDO::PARAM_INT);
$mapThreatStmt->execute();
$mapThreats = $mapThreatStmt->fetchAll();
$threatsForMapPrepared = [];
foreach ($mapThreats as $mapThreat) {
    if (($mapThreat['latitude'] === null || $mapThreat['longitude'] === null) && !empty($mapThreat['country'])) {
        $centroid = countryCentroid((string)$mapThreat['country']);
        if ($centroid) {
            $mapThreat['latitude'] = $centroid[0];
            $mapThreat['longitude'] = $centroid[1];
        }
    }
    if ($mapThreat['latitude'] !== null && $mapThreat['longitude'] !== null) {
        $threatsForMapPrepared[] = $mapThreat;
    }
}
$threatsForMap = array_values($threatsForMapPrepared);

function buildAbsoluteUrl(array $params = []): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $base = $scheme . '://' . $host . $script;
    if (!$params) {
        return $base;
    }
    return $base . '?' . http_build_query($params);
}

function buildAssetAbsoluteUrl(string $assetPath): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $dir = str_replace('\\', '/', dirname($script));
    if ($dir === '/' || $dir === '.') {
        $dir = '';
    }
    return $scheme . '://' . $host . $dir . '/' . ltrim($assetPath, '/');
}

function getSeoMeta(string $p, PDO $pdo, array $config): array
{
    $site = (string)$config['site_name'];
    $default = [
        'title' => $site,
        'description' => 'Example Threat Map provides a real-time map of threat events in Europe, including Environmental, Geopolitical, Technology, Health, Economic, and Criminal activity risks.',
        'canonical' => buildAbsoluteUrl(),
        'robots' => 'index,follow',
        'type' => 'website',
        'image' => buildAssetAbsoluteUrl('assets/social-share.svg'),
    ];

    if ($p === 'home') {
        $default['title'] = 'Example Threat Map - Threat Events in Europe on a Map';
        return $default;
    }

    if ($p === 'show_threat_details') {
        $id = (int)($_GET['id'] ?? 0);
        $slug = trim((string)($_GET['threat_title'] ?? ''));
        if ($id > 0) {
            $stmt = $pdo->prepare('SELECT title, summary FROM threat_events WHERE id = ? LIMIT 1');
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            $default['canonical'] = buildAbsoluteUrl(['p' => 'show_threat_details', 'id' => $id]);
        } else {
            $stmt = $pdo->prepare('SELECT title, summary, id FROM threat_events WHERE slug = ? ORDER BY id DESC LIMIT 1');
            $stmt->execute([$slug]);
            $row = $stmt->fetch();
            $canonicalParams = ['p' => 'show_threat_details'];
            if ($row && isset($row['id'])) {
                $canonicalParams['id'] = (int)$row['id'];
            }
            $default['canonical'] = buildAbsoluteUrl($canonicalParams);
        }
        if (!empty($row['title'])) {
            $default['title'] = (string)$row['title'] . ' - Threat Details - ' . $site;
            $sum = trim((string)($row['summary'] ?? ''));
            if ($sum !== '') {
                $default['description'] = mb_substr(strip_tags($sum), 0, 160);
            }
            $default['type'] = 'article';
        }
        return $default;
    }

    if ($p === 'risk_assessments') {
        $default['title'] = 'Risk Assessments - Example Threat Map';
        $default['description'] = 'Browse risk assessments for European threats. Search by title and filter by tags.';
        $default['canonical'] = buildAbsoluteUrl(['p' => 'risk_assessments']);
        return $default;
    }

    if ($p === 'risk_view') {
        $id = (int)($_GET['id'] ?? 0);
        $default['canonical'] = buildAbsoluteUrl(['p' => 'risk_view', 'id' => $id]);
        if ($id > 0) {
            $stmt = $pdo->prepare('SELECT title, body FROM risk_assessments WHERE id = ? LIMIT 1');
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            if ($row) {
                $default['title'] = (string)$row['title'] . ' - Risk Assessment - ' . $site;
                $default['description'] = mb_substr(trim(strip_tags((string)$row['body'])), 0, 160);
                $default['type'] = 'article';
            }
        }
        return $default;
    }

    if (in_array($p, ['login', 'analytics', 'risk_edit', 'risk_save', 'risk_delete', 'logout', 'notifications', 'verify-human'], true)) {
        $default['robots'] = 'noindex,nofollow';
        return $default;
    }

    return $default;
}

function renderHeader(array $seo, array $config): void
{
    $token = getCsrfToken();
    ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="google-site-verification" content="VyCqifAio0xFF9H8x4ozgIFit3Fk4yutxwZmqnDRCCQ" />
    <title><?= e($seo['title']) ?></title>
    <meta name="description" content="<?= e($seo['description']) ?>">
    <meta name="robots" content="<?= e($seo['robots']) ?>">
    <link rel="canonical" href="<?= e($seo['canonical']) ?>">
    <meta property="og:type" content="<?= e($seo['type']) ?>">
    <meta property="og:site_name" content="<?= e($config['site_name']) ?>">
    <meta property="og:title" content="<?= e($seo['title']) ?>">
    <meta property="og:description" content="<?= e($seo['description']) ?>">
    <meta property="og:url" content="<?= e($seo['canonical']) ?>">
    <meta property="og:image" content="<?= e($seo['image']) ?>">
    <meta property="og:image:alt" content="Example Threat Map - Threat Events in Europe on a Map">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">
    <meta property="og:image:type" content="image/svg+xml">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="<?= e($seo['title']) ?>">
    <meta name="twitter:description" content="<?= e($seo['description']) ?>">
    <meta name="twitter:image" content="<?= e($seo['image']) ?>">
    <link rel="icon" type="image/svg+xml" href="assets/favicon.svg">
    <link rel="preconnect" href="https://unpkg.com">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
    <style>
        :root {
            --bg: #0b1220;
            --card: #121b2f;
            --card-2: #0f172a;
            --text: #e5e7eb;
            --muted: #94a3b8;
            --accent: #22c55e;
            --danger: #ef4444;
            --link: #60a5fa;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Inter, Segoe UI, Roboto, Arial, sans-serif;
            background: radial-gradient(circle at top, #111827, #0b1220 45%);
            color: var(--text);
        }
        a { color: var(--link); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .container { max-width: 1120px; margin: 0 auto; padding: 12px; }
        .top {
            display: flex; align-items: center; justify-content: space-between;
            gap: 10px; flex-wrap: wrap; margin-bottom: 12px;
        }
        .top img { max-width: min(100%, 340px); height: auto; }
        .menu { display: flex; flex-wrap: wrap; gap: 8px; }
        .menu a {
            background: #0f172a; border: 1px solid #22304b; color: #dbeafe;
            padding: 8px 10px; border-radius: 10px; font-size: 14px;
        }
        .card {
            background: linear-gradient(180deg, rgba(18,27,47,.95), rgba(15,23,42,.95));
            border: 1px solid #263552;
            border-radius: 14px;
            padding: 12px;
            margin-bottom: 12px;
        }
        #map {
            width: 100%;
            height: min(70vh, 560px);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #22304b;
        }
        .attribution-note {
            margin-top: 8px;
            color: var(--muted);
            font-size: 13px;
        }
        .legend {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 6px;
            margin-top: 10px;
            font-size: 13px;
        }
        .legend span { display: flex; align-items: center; gap: 7px; }
        .dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            overflow-x: auto;
        }
        th, td {
            border-bottom: 1px solid #25324d;
            padding: 10px 8px;
            text-align: left;
            vertical-align: top;
        }
        th { color: #dbeafe; font-weight: 600; }
        .badge {
            display: inline-block;
            padding: 3px 7px;
            border-radius: 999px;
            background: #1e293b;
            border: 1px solid #334155;
            font-size: 12px;
            color: #cbd5e1;
        }
        .flash, .error {
            padding: 10px;
            border-radius: 10px;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .flash { background: rgba(34, 197, 94, .15); border: 1px solid rgba(34, 197, 94, .45); }
        .error { background: rgba(239, 68, 68, .12); border: 1px solid rgba(239, 68, 68, .45); }
        input[type="text"], input[type="email"], input[type="password"], textarea, select {
            width: 100%;
            background: #0b1220;
            color: var(--text);
            border: 1px solid #2a3a5c;
            border-radius: 8px;
            padding: 9px 10px;
            font-size: 14px;
            margin-top: 5px;
            margin-bottom: 10px;
        }
        textarea { min-height: 120px; resize: vertical; }
        button, .btn {
            border: 1px solid #2a3a5c;
            background: #1d4ed8;
            color: white;
            border-radius: 8px;
            padding: 8px 12px;
            cursor: pointer;
            font-size: 14px;
        }
        .btn-danger { background: #b91c1c; }
        .btn-secondary { background: #334155; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .footer-note {
            border-top: 1px solid #24334f;
            margin-top: 16px;
            padding-top: 10px;
            font-size: 13px;
            color: #a7b6cf;
        }
        .share-footer {
            border-top: 1px solid #24334f;
            margin-top: 14px;
            padding-top: 10px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        .share-footer .share-btn {
            display: inline-block;
            padding: 7px 10px;
            border-radius: 8px;
            font-size: 13px;
            border: 1px solid #334155;
            background: #0b1220;
            color: #dbeafe;
        }
        .cookie-banner {
            position: fixed;
            left: 10px;
            right: 10px;
            bottom: 10px;
            z-index: 99999;
            background: #111827;
            border: 1px solid #2a3a5c;
            border-radius: 10px;
            padding: 10px;
            display: none;
        }
        .ts-overlay {
            position: absolute;
            top: 14px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid #334155;
            color: #f8fafc;
            font-weight: 700;
            padding: 5px 10px;
            border-radius: 999px;
            z-index: 500;
            pointer-events: none;
            backdrop-filter: blur(3px);
        }
        .toast {
            position: fixed;
            right: 12px;
            bottom: 80px;
            background: #16a34a;
            color: white;
            padding: 10px 12px;
            border-radius: 10px;
            border: 1px solid rgba(255,255,255,.3);
            display: none;
            z-index: 100000;
        }
        @media (max-width: 800px) {
            .grid-2 { grid-template-columns: 1fr; }
            th:nth-child(3), td:nth-child(3) { display: none; }
        }
    </style>
    <script>window.__CSRF_TOKEN__ = <?= json_encode($token) ?>;</script>
</head>
<body>
<div class="container">
    <header class="top">
        <a href="index.php"><img src="assets/logo.svg" alt="<?= e((string)$config['site_name']) ?>"></a>
        <nav class="menu">
            <a href="index.php">Map</a>
            <a href="index.php?p=risk_assessments">Risk Assessments</a>
            <?php if (isAdminLoggedIn()): ?>
                <a href="index.php?p=analytics">Analytics</a>
            <?php endif; ?>
            <a href="index.php?p=contact">Contact</a>
            <?php if (isAdminLoggedIn()): ?>
                <a href="index.php?p=logout">Admin Logout</a>
            <?php endif; ?>
        </nav>
    </header>
<?php
}

function renderFooter(bool $showRiskFooter = false, bool $showShare = false, string $shareTitle = 'Example Threat Map'): void
{
    $shareUrl = buildAbsoluteUrl($_GET);
    $encUrl = urlencode($shareUrl);
    $encTitle = urlencode($shareTitle);
    $encText = urlencode($shareTitle . ' ' . $shareUrl);
    ?>
    <?php if ($showShare): ?>
    <div class="share-footer">
        <strong>Share:</strong>
        <a class="share-btn" target="_blank" rel="noopener" href="https://www.facebook.com/sharer/sharer.php?u=<?= $encUrl ?>">Facebook</a>
        <a class="share-btn" target="_blank" rel="noopener" href="https://www.linkedin.com/sharing/share-offsite/?url=<?= $encUrl ?>">LinkedIn</a>
        <a class="share-btn" target="_blank" rel="noopener" href="https://twitter.com/intent/tweet?url=<?= $encUrl ?>&text=<?= $encTitle ?>">X</a>
        <a class="share-btn" target="_blank" rel="noopener" href="https://bsky.app/intent/compose?text=<?= $encText ?>">Bluesky</a>
        <a class="share-btn" target="_blank" rel="noopener" href="https://www.instagram.com/">Instagram</a>
        <a class="share-btn" target="_blank" rel="noopener" href="https://www.tiktok.com/">TikTok</a>
        <a class="share-btn" href="mailto:?subject=<?= $encTitle ?>&body=<?= $encUrl ?>">Email</a>
    </div>
    <?php endif; ?>
    <?php if ($showRiskFooter): ?>
    <div class="footer-note">
        Risk Assessments are provided by Example Threat Provider (<a href="https://provider.example.com" target="_blank" rel="noopener">https://provider.example.com</a>).
    </div>
    <?php endif; ?>
</div>

<div class="cookie-banner" id="cookieBanner">
    <strong>Cookie consent</strong><br>
    We use a minimal cookie/session mechanism for login and preferences.
    <a href="index.php?p=cookie-policy">Read policy</a>
    <div style="margin-top:8px;">
        <button id="acceptCookies" class="btn-secondary">Accept</button>
    </div>
</div>

<div class="cookie-banner" id="notificationBanner" style="bottom:88px;display:none;">
    <strong>Enable notifications</strong><br>
    Get browser alerts when a new Risk Assessment is published.
    <div style="margin-top:8px; display:flex; gap:8px;">
        <button id="enableNotifications" class="btn-secondary" type="button">Enable</button>
        <button id="dismissNotifications" class="btn-secondary" type="button">Later</button>
    </div>
</div>

<div class="toast" id="riskToast"></div>

<script>
(function() {
    const cookieBanner = document.getElementById('cookieBanner');
    const notificationBanner = document.getElementById('notificationBanner');
    if (!localStorage.getItem('ts_cookie_consent')) {
        cookieBanner.style.display = 'block';
    }
    document.getElementById('acceptCookies')?.addEventListener('click', () => {
        localStorage.setItem('ts_cookie_consent', '1');
        cookieBanner.style.display = 'none';
    });

    function canPromptNotifications() {
        if (!('Notification' in window)) return false;
        const isSecure = window.isSecureContext || window.location.protocol === 'https:' || window.location.hostname === 'localhost';
        if (!isSecure) return false;
        if (Notification.permission !== 'default') return false;
        if (localStorage.getItem('ts_notifications_dismissed') === '1') return false;
        return true;
    }

    if (canPromptNotifications() && notificationBanner) {
        notificationBanner.style.display = 'block';
    }

    document.getElementById('enableNotifications')?.addEventListener('click', async () => {
        try {
            if (!('Notification' in window)) return;
            const permission = await Notification.requestPermission();
            if (permission === 'granted') {
                showToast('Browser notifications enabled.');
            }
            if (notificationBanner) notificationBanner.style.display = 'none';
            localStorage.setItem('ts_notifications_dismissed', '1');
        } catch (e) {}
    });

    document.getElementById('dismissNotifications')?.addEventListener('click', () => {
        if (notificationBanner) notificationBanner.style.display = 'none';
        localStorage.setItem('ts_notifications_dismissed', '1');
    });

    const toast = document.getElementById('riskToast');
    function showToast(msg) {
        if (!toast) return;
        toast.textContent = msg;
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 6000);
    }

    async function checkRiskNotifications() {
        try {
            const res = await fetch('index.php?p=notifications', { credentials: 'same-origin' });
            const data = await res.json();
            if (!data || !data.latest) return;
            const latestId = String(data.latest.id);
            const key = 'ts_last_seen_risk_id';
            const seen = localStorage.getItem(key);
            if (seen && seen !== latestId) {
                const msg = 'New Risk Assessment: ' + data.latest.title;
                showToast(msg);
                if ('Notification' in window) {
                    if (Notification.permission === 'granted') {
                        new Notification(msg);
                    }
                }
            }
            localStorage.setItem(key, latestId);
        } catch (e) {}
    }

    checkRiskNotifications();
    setInterval(checkRiskNotifications, 60000);
})();
</script>
</body>
</html>
<?php
}

$seo = getSeoMeta((string)$p, $pdo, $config);
renderHeader($seo, $config);

if ($flash || isset($_GET['ok'])) {
    $ok = $_GET['ok'] ?? '';
    $message = $flash;
    if ($ok === 'added') $message = 'Risk assessment added.';
    if ($ok === 'updated') $message = 'Risk assessment updated.';
    if ($ok === 'deleted') $message = 'Risk assessment deleted.';
    if ($message !== '') echo '<div class="flash">' . e($message) . '</div>';
}
if ($error !== '') {
    echo '<div class="error">' . e($error) . '</div>';
}

if ($p === 'home') {
    $categories = [
        'Environmental' => '#16a34a',
        'Geopolitical Conflict' => '#dc2626',
        'Technology' => '#2563eb',
        'Health' => '#8b5cf6',
        'Economic' => '#f59e0b',
        'Large Criminal Activity' => '#ec4899',
    ];
    ?>
    <section class="card" style="position:relative;">
        <div style="display:flex;gap:10px;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;">
            <h2 style="margin:0;">Threat Events in Europe</h2>
            <form method="get" id="threatTypeForm" style="min-width:260px;">
                <input type="hidden" name="p" value="home">
                <label style="display:block;margin:0;">
                    <select name="type" id="threatTypeSelect" style="margin-bottom:0;">
                        <option value="">All threat types</option>
                        <?php foreach ($allowedThreatTypes as $typeOpt): ?>
                            <option value="<?= e($typeOpt) ?>" <?= $selectedThreatType === $typeOpt ? 'selected' : '' ?>><?= e($typeOpt) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
            </form>
        </div>
        <div id="map"></div>
        <div class="attribution-note">Using content from <a href="<?= e((string)$config['source_url']) ?>" target="_blank" rel="noopener"><?= e((string)$config['source_url']) ?></a>.</div>
        <div class="attribution-note">Content is user and machine generated and may contain inaccuracies and/or false information; no warranties are provided.</div>
        <div class="legend">
            <?php foreach ($categories as $name => $color): ?>
                <span><i class="dot" style="background:<?= e($color) ?>"></i><?= e($name) ?></span>
            <?php endforeach; ?>
        </div>
    </section>

    <section class="card">
        <h3 style="margin-top:0;">Threat Event List</h3>
        <div style="overflow:auto;">
            <table>
                <thead>
                <tr>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Country/Region</th>
                    <th>Date Added</th>
                </tr>
                </thead>
                <tbody>
                <?php if (!$threats): ?>
                    <tr><td colspan="4">No active events found for this filter.</td></tr>
                <?php else: foreach ($threats as $t): ?>
                    <tr>
                        <td>
                            <a href="index.php?p=show_threat_details&threat_title=<?= urlencode($t['slug']) ?>&id=<?= (int)$t['id'] ?>">
                                <?= e($t['title']) ?>
                            </a>
                        </td>
                        <td><span class="badge"><?= e($t['category']) ?></span></td>
                        <td><?= e(trim(($t['country'] ?? '') . ' ' . ($t['region'] ?? ''))) ?></td>
                        <td><?= e(date('Y-m-d', strtotime((string)$t['created_at']))) ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
        <?php if ($threatTotal > 0): ?>
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:10px;flex-wrap:wrap;">
                <span class="badge">Page <?= (int)$threatPage ?> of <?= (int)$threatTotalPages ?> (<?= (int)$threatTotal ?> threats)</span>
                <div style="display:flex;gap:8px;">
                    <?php if ($threatPage > 1): ?>
                        <a class="btn btn-secondary" href="index.php?p=home&page=<?= (int)($threatPage - 1) ?><?= $selectedThreatType !== '' ? '&type=' . urlencode($selectedThreatType) : '' ?>">Previous</a>
                    <?php endif; ?>
                    <?php if ($threatPage < $threatTotalPages): ?>
                        <a class="btn btn-secondary" href="index.php?p=home&page=<?= (int)($threatPage + 1) ?><?= $selectedThreatType !== '' ? '&type=' . urlencode($selectedThreatType) : '' ?>">Next</a>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </section>

    <script>
        (function() {
            const savedMapState = localStorage.getItem('ts_map_state');
            let initialCenter = [52.0, 14.0];
            let initialZoom = 4;
            if (savedMapState) {
                try {
                    const parsed = JSON.parse(savedMapState);
                    if (Array.isArray(parsed.center) && parsed.center.length === 2 && Number.isFinite(parsed.zoom)) {
                        initialCenter = [parseFloat(parsed.center[0]), parseFloat(parsed.center[1])];
                        initialZoom = parseInt(parsed.zoom, 10);
                    }
                } catch (e) {}
            }

            const map = L.map('map', { zoomControl: true }).setView(initialCenter, initialZoom);
            L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
                maxZoom: 17,
                attribution: '&copy; OpenStreetMap contributors, SRTM | Map style: OpenTopoMap'
            }).addTo(map);

            map.on('moveend zoomend', () => {
                const c = map.getCenter();
                localStorage.setItem('ts_map_state', JSON.stringify({ center: [c.lat, c.lng], zoom: map.getZoom() }));
            });

            const filterSelect = document.getElementById('threatTypeSelect');
            filterSelect?.addEventListener('change', function() {
                const selected = this.value || '';
                const params = new URLSearchParams(window.location.search);
                params.set('p', 'home');
                params.delete('page');
                if (selected === '') {
                    params.delete('type');
                } else {
                    params.set('type', selected);
                }
                window.location.search = params.toString();
            });

            const colors = {
                'Environmental': '#16a34a',
                'Geopolitical Conflict': '#dc2626',
                'Technology': '#2563eb',
                'Health': '#8b5cf6',
                'Economic': '#f59e0b',
                'Large Criminal Activity': '#ec4899'
            };

            const events = <?= json_encode($threatsForMap, JSON_UNESCAPED_UNICODE) ?>;
            events.forEach((ev) => {
                const lat = parseFloat(ev.latitude);
                const lng = parseFloat(ev.longitude);
                if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;
                const color = colors[ev.category] || '#60a5fa';

                // Glow layer
                L.circleMarker([lat, lng], {
                    radius: 14,
                    color,
                    fillColor: color,
                    fillOpacity: 0.18,
                    weight: 0,
                    interactive: false
                }).addTo(map);

                // Main ring
                const marker = L.circleMarker([lat, lng], {
                    radius: 9,
                    color: '#ffffff',
                    fillColor: color,
                    fillOpacity: 0.9,
                    weight: 1.4
                }).addTo(map);

                // Core highlight
                L.circleMarker([lat, lng], {
                    radius: 3,
                    color: '#ffffff',
                    fillColor: '#ffffff',
                    fillOpacity: 0.95,
                    weight: 0,
                    interactive: false
                }).addTo(map);

                const detailsLink = 'index.php?p=show_threat_details&threat_title=' + encodeURIComponent(ev.slug) + '&id=' + encodeURIComponent(ev.id);
                marker.bindPopup(
                    '<strong>' + (ev.title || 'Threat') + '</strong><br>' +
                    '<span>' + (ev.category || '') + '</span><br>' +
                    '<a href="' + detailsLink + '">View details</a>'
                );
            });
        })();
    </script>
    <?php
}
elseif ($p === 'show_threat_details') {
    $id = (int)($_GET['id'] ?? 0);
    $slug = trim((string)($_GET['threat_title'] ?? ''));

    if ($id > 0) {
        $stmt = $pdo->prepare('SELECT * FROM threat_events WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
    } else {
        $stmt = $pdo->prepare('SELECT * FROM threat_events WHERE slug = ? ORDER BY id DESC LIMIT 1');
        $stmt->execute([$slug]);
    }

    $threat = $stmt->fetch();
    ?>
    <section class="card">
        <h2 style="margin-top:0;">Threat Details</h2>
        <?php if (!$threat): ?>
            <p>Threat not found.</p>
        <?php else: ?>
            <?php
            $rawThreat = [];
            if (!empty($threat['raw_json'])) {
                $decodedRaw = json_decode((string)$threat['raw_json'], true);
                if (is_array($decodedRaw)) {
                    $rawThreat = $decodedRaw;
                }
            }
            $shortDescription = trim((string)($threat['summary'] ?? ''));
            if ($shortDescription === '') {
                $shortDescription = trim((string)($rawThreat['short_description'] ?? $rawThreat['shortDescription'] ?? $rawThreat['summary'] ?? ''));
            }
            $longDescription = trim((string)($threat['long_description'] ?? ''));
            if ($longDescription === '') {
                $longDescription = trim((string)($rawThreat['long_description'] ?? $rawThreat['longDescription'] ?? $rawThreat['description'] ?? $rawThreat['details'] ?? $rawThreat['full_description'] ?? $rawThreat['content'] ?? ''));
            }
            if ($shortDescription === '' && $longDescription !== '') {
                $shortDescription = mb_substr(trim(strip_tags($longDescription)), 0, 280);
            }
            ?>
            <h3><?= e($threat['title']) ?></h3>
            <p><span class="badge"><?= e($threat['category']) ?></span></p>
            <p><strong>Location:</strong> <?= e(trim(($threat['country'] ?? '') . ' ' . ($threat['region'] ?? ''))) ?></p>
            <p><strong>Date Added:</strong> <?= e(date('Y-m-d H:i', strtotime((string)$threat['created_at']))) ?></p>
            <p><strong>Short Description:</strong><br><?= $shortDescription !== '' ? nl2br(e($shortDescription)) : 'Not available.' ?></p>
            <p><strong>Long Description:</strong><br><?= $longDescription !== '' ? nl2br(e($longDescription)) : 'Not available.' ?></p>
            <p class="attribution-note">Content is user and machine generated and may contain inaccuracies and/or false information; no warranties are provided.</p>
            <p class="attribution-note">Content from <a href="<?= e((string)$config['source_url']) ?>" target="_blank" rel="noopener"><?= e((string)$config['source_url']) ?></a>.</p>
            <?php if (!empty($threat['details_url'])): ?>
                <p><a href="<?= e($threat['details_url']) ?>" target="_blank" rel="noopener">External source link</a></p>
            <?php endif; ?>
        <?php endif; ?>
    </section>
    <?php
}
elseif ($p === 'risk_assessments') {
    $q = sanitizePlainInput((string)($_GET['q'] ?? ''), 120);
    $tag = sanitizePlainInput((string)($_GET['tag'] ?? ''), 120);

    $where = [];
    $params = [];
    if ($q !== '') {
        $where[] = 'LOWER(title) LIKE LOWER(?)';
        $params[] = '%' . $q . '%';
    }
    if ($tag !== '') {
        $where[] = 'LOWER(tags) LIKE LOWER(?)';
        $params[] = '%' . $tag . '%';
    }

    $sql = 'SELECT * FROM risk_assessments';
    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY created_at DESC';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $items = $stmt->fetchAll();

    ?>
    <section class="card">
        <h2 style="margin-top:0;">Risk Assessments</h2>
        <form method="get" class="grid-2">
            <input type="hidden" name="p" value="risk_assessments">
            <div>
                <label>Search title
                    <input type="text" name="q" value="<?= e($q) ?>" placeholder="Search by title">
                </label>
            </div>
            <div>
                <label>Filter by tag
                    <input type="text" name="tag" value="<?= e($tag) ?>" placeholder="e.g. Geopolitical conflict">
                </label>
            </div>
            <div><button type="submit">Apply filters</button></div>
        </form>

        <?php if (isAdminLoggedIn()): ?>
            <p><a class="btn" href="index.php?p=risk_edit">Add Risk Assessment</a></p>
        <?php endif; ?>

        <div style="overflow:auto;">
            <table>
                <thead>
                <tr>
                    <th>Title</th>
                    <th>Date Added</th>
                    <th>Tags</th>
                    <?php if (isAdminLoggedIn()): ?><th>Actions</th><?php endif; ?>
                </tr>
                </thead>
                <tbody>
                <?php if (!$items): ?>
                    <tr><td colspan="4">No risk assessments found.</td></tr>
                <?php else: foreach ($items as $item): ?>
                    <tr>
                        <td><a href="index.php?p=risk_view&id=<?= (int)$item['id'] ?>"><?= e($item['title']) ?></a></td>
                        <td><?= e(date('Y-m-d', strtotime((string)$item['created_at']))) ?></td>
                        <td><?= e((string)$item['tags']) ?></td>
                        <?php if (isAdminLoggedIn()): ?>
                        <td>
                            <a class="btn btn-secondary" href="index.php?p=risk_edit&id=<?= (int)$item['id'] ?>">Edit</a>
                            <form method="post" action="index.php?p=risk_delete" style="display:inline;" onsubmit="return confirm('Delete this risk assessment?')">
                                <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
                                <input type="hidden" name="id" value="<?= (int)$item['id'] ?>">
                                <button class="btn btn-danger" type="submit">Delete</button>
                            </form>
                        </td>
                        <?php endif; ?>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </section>
    <?php
    renderFooter(true, true, (string)$seo['title']);
    exit;
}
elseif ($p === 'risk_view') {
    $id = (int)($_GET['id'] ?? 0);
    $stmt = $pdo->prepare('SELECT * FROM risk_assessments WHERE id = ? LIMIT 1');
    $stmt->execute([$id]);
    $risk = $stmt->fetch();
    ?>
    <section class="card">
        <?php if (!$risk): ?>
            <p>Risk assessment not found.</p>
        <?php else: ?>
            <h2 style="margin-top:0;"><?= e($risk['title']) ?></h2>
            <p><strong>Date:</strong> <?= e((string)$risk['created_at']) ?></p>
            <p><strong>Tags:</strong> <?= e((string)$risk['tags']) ?></p>
            <div style="background:#0b1220;border:1px solid #2a3a5c;border-radius:10px;padding:12px;">
                <?= sanitizeRiskBody((string)$risk['body']) ?>
            </div>
            <p class="attribution-note">Content is user and machine generated and may contain inaccuracies and/or false information; no warranties are provided.</p>
        <?php endif; ?>
    </section>
    <?php
    renderFooter(true, true, (string)$seo['title']);
    exit;
}
elseif ($p === 'risk_edit') {
    requireAdmin();
    $id = (int)($_GET['id'] ?? 0);
    $risk = ['id' => 0, 'title' => '', 'body' => '', 'tags' => ''];
    if ($id > 0) {
        $stmt = $pdo->prepare('SELECT * FROM risk_assessments WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if ($row) {
            $risk = $row;
        }
    }
    ?>
    <section class="card">
        <h2 style="margin-top:0;"><?= $id > 0 ? 'Edit' : 'Add' ?> Risk Assessment</h2>
        <form method="post" action="index.php?p=risk_save">
            <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
            <input type="hidden" name="id" value="<?= (int)$risk['id'] ?>">

            <label>Title (text only, max 180)
                <input type="text" name="title" maxlength="180" required value="<?= e((string)$risk['title']) ?>">
            </label>
            <label>Body (basic HTML allowed)
                <textarea name="body" required><?= e((string)$risk['body']) ?></textarea>
            </label>
            <label>Tags (comma separated, max 10)
                <input type="text" name="tags" maxlength="512" value="<?= e((string)$risk['tags']) ?>" placeholder="energy, cyber, health">
            </label>

            <button type="submit">Save</button>
        </form>
    </section>
    <?php
}
elseif ($p === 'analytics') {
    $stmt = $pdo->query("SELECT visit_date, COUNT(*) AS unique_visitors, SUM(hits) AS visits
                         FROM daily_visits
                         GROUP BY visit_date
                         ORDER BY visit_date DESC
                         LIMIT 60");
    $rows = $stmt->fetchAll();
    ?>
    <section class="card">
        <h2 style="margin-top:0;">Analytics</h2>
        <p>Unique visitors and visits per day.</p>
        <div style="overflow:auto;">
            <table>
                <thead>
                <tr><th>Date</th><th>Unique Visitors</th><th>Total Visits</th></tr>
                </thead>
                <tbody>
                <?php if (!$rows): ?>
                    <tr><td colspan="3">No analytics data yet.</td></tr>
                <?php else: foreach ($rows as $row): ?>
                    <tr>
                        <td><?= e((string)$row['visit_date']) ?></td>
                        <td><?= (int)$row['unique_visitors'] ?></td>
                        <td><?= (int)$row['visits'] ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </section>
    <?php
}
elseif ($p === 'contact') {
    ?>
    <section class="card">
        <h2 style="margin-top:0;">Contact</h2>
        <p>Use this form to contact the administrator.</p>
        <form method="post" action="index.php?p=contact">
            <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
            <div class="grid-2">
                <label>Name
                    <input type="text" name="name" required>
                </label>
                <label>Email
                    <input type="email" name="email" required>
                </label>
            </div>
            <label>Subject
                <input type="text" name="subject" required>
            </label>
            <label>Message
                <textarea name="message" required></textarea>
            </label>
            <div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden;" aria-hidden="true">
                <label>Leave this field empty
                    <input type="text" name="website" tabindex="-1" autocomplete="off">
                </label>
            </div>
            <label>Human verification: <?= e(getContactChallengeQuestion()) ?>
                <input type="text" name="human_check" inputmode="numeric" pattern="[0-9]*" required>
            </label>
            <button type="submit">Send message</button>
        </form>
    </section>
    <?php
}
elseif ($p === 'verify-human') {
    $returnTarget = sanitizeReturnTarget((string)($_GET['return'] ?? ($_POST['return'] ?? 'index.php')));
    ?>
    <section class="card" style="max-width:560px;margin-inline:auto;">
        <h2 style="margin-top:0;">Human Verification</h2>
        <p>We detected unusual traffic. Please solve this quick math challenge to continue.</p>
        <form method="post" action="index.php?p=verify-human">
            <input type="hidden" name="csrf_token" value="<?= e(getCsrfToken()) ?>">
            <input type="hidden" name="return" value="<?= e($returnTarget) ?>">
            <label><?= e(getBotChallengeQuestion()) ?>
                <input type="text" name="human_check" inputmode="numeric" required>
            </label>
            <button type="submit">Verify</button>
        </form>
    </section>
    <?php
}
elseif ($p === 'cookie-policy') {
    ?>
    <section class="card">
        <h2 style="margin-top:0;">Cookie Policy</h2>
        <p>This site uses minimal cookies/session data for authentication and user preferences (for example cookie consent).</p>
        <p>No third-party ad tracking cookies are used in this implementation.</p>
    </section>
    <?php
}
elseif ($p === 'login') {
    ?>
    <section class="card" style="max-width:520px;margin-inline:auto;">
        <h2 style="margin-top:0;">Admin Login</h2>
        <form method="post" action="index.php?p=login">
            <label>Email
                <input type="email" name="email" required>
            </label>
            <label>Password
                <input type="password" name="password" required>
            </label>
            <button type="submit">Login</button>
        </form>
    </section>
    <?php
}
else {
    ?>
    <section class="card">
        <h2 style="margin-top:0;">Page not found</h2>
        <p>The requested page does not exist.</p>
    </section>
    <?php
}

$enableShareFooter = in_array($p, ['home', 'show_threat_details'], true);
renderFooter(false, $enableShareFooter, (string)$seo['title']);
