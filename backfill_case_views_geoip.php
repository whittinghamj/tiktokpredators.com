<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from CLI.\n");
    exit(1);
}

if (!extension_loaded('curl')) {
    fwrite(STDERR, "The cURL extension is required.\n");
    exit(1);
}

$options = getopt('', [
    'help',
    'max-rows::',
    'batch-size::',
    'sleep-ms::',
    'dry-run',
    'dsn::',
    'db-user::',
    'db-pass::',
    'api-base::',
]);

if (isset($options['help'])) {
    echo "Backfill GeoIP data for case_views rows.\n\n";
    echo "Usage:\n";
    echo "  php backfill_case_views_geoip.php [--max-rows=1000] [--batch-size=100] [--sleep-ms=750] [--dry-run]\n";
    echo "                                  [--dsn=...] [--db-user=...] [--db-pass=...]\n";
    echo "                                  [--api-base=https://tiktokpredators.com/geoip.php]\n\n";
    echo "Defaults:\n";
    echo "  --max-rows   1000\n";
    echo "  --batch-size 100\n";
    echo "  --sleep-ms   750\n";
    echo "  --api-base   https://tiktokpredators.com/geoip.php\n";
    exit(0);
}

$maxRows = max(1, (int)($options['max-rows'] ?? 1000));
$batchSize = max(1, min(500, (int)($options['batch-size'] ?? 100)));
$sleepMs = max(0, (int)($options['sleep-ms'] ?? 750));
$dryRun = isset($options['dry-run']);

$dsn = (string)($options['dsn'] ?? getenv('DB_DSN') ?: 'mysql:host=10.254.6.110;dbname=tiktokpredators;charset=utf8mb4');
$dbUser = (string)($options['db-user'] ?? getenv('DB_USER') ?: 'stiliam');
$dbPass = (string)($options['db-pass'] ?? getenv('DB_PASS') ?: 'WRceFeIy58I0ypAgD5fu');
$apiBase = rtrim((string)($options['api-base'] ?? 'https://tiktokpredators.com/geoip.php'), '/');

function is_public_ip(string $ip): bool
{
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

function str_limit(?string $value, int $len): ?string
{
    if ($value === null) {
        return null;
    }
    $value = trim($value);
    if ($value === '') {
        return null;
    }
    return substr($value, 0, $len);
}

function fetch_geo(string $apiBase, string $ip): ?array
{
    $url = $apiBase . '?ip=' . rawurlencode($ip);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_FAILONERROR => false,
        CURLOPT_USERAGENT => 'tiktokpredators-case-views-backfill/1.0',
    ]);

    $response = curl_exec($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($response === false || $err !== '' || $httpCode < 200 || $httpCode >= 300) {
        return null;
    }

    $payload = json_decode($response, true);
    if (!is_array($payload) || empty($payload['success']) || !is_array($payload['data'] ?? null)) {
        return null;
    }

    $data = $payload['data'];

    return [
        'geo_ip' => str_limit((string)($data['ip'] ?? $ip), 45),
        'geo_continent_name' => str_limit((string)($data['continent']['name'] ?? ''), 64),
        'geo_continent_code' => str_limit(strtoupper((string)($data['continent']['code'] ?? '')), 2),
        'geo_country_name' => str_limit((string)($data['country']['name'] ?? ''), 128),
        'geo_country' => str_limit(strtoupper((string)($data['country']['code'] ?? '')), 2),
        'geo_region_code' => str_limit((string)($data['region']['code'] ?? ''), 16),
        'geo_region' => str_limit((string)($data['region']['name'] ?? ''), 128),
        'geo_city' => str_limit((string)($data['city'] ?? ''), 128),
        'geo_district' => str_limit((string)($data['district'] ?? ''), 128),
        'geo_postcode' => str_limit((string)($data['postcode'] ?? ''), 32),
        'geo_lat' => isset($data['location']['lat']) ? (float)$data['location']['lat'] : null,
        'geo_lon' => isset($data['location']['lon']) ? (float)$data['location']['lon'] : null,
        'geo_timezone' => str_limit((string)($data['location']['timezone'] ?? ''), 64),
        'geo_utc_offset' => isset($data['location']['utc_offset']) ? (int)$data['location']['utc_offset'] : null,
        'geo_currency' => str_limit((string)($data['currency'] ?? ''), 8),
        'net_isp' => str_limit((string)($data['network']['isp'] ?? ''), 255),
        'net_org' => str_limit((string)($data['network']['org'] ?? ''), 255),
        'net_as' => str_limit((string)($data['network']['as'] ?? ''), 255),
        'net_as_name' => str_limit((string)($data['network']['as_name'] ?? ''), 255),
        'net_reverse_dns' => str_limit((string)($data['network']['reverse_dns'] ?? ''), 255),
        'is_mobile' => array_key_exists('mobile', $data['flags'] ?? []) ? ((bool)$data['flags']['mobile'] ? 1 : 0) : null,
        'is_proxy' => array_key_exists('proxy', $data['flags'] ?? []) ? ((bool)$data['flags']['proxy'] ? 1 : 0) : null,
        'is_hosting' => array_key_exists('hosting', $data['flags'] ?? []) ? ((bool)$data['flags']['hosting'] ? 1 : 0) : null,
        'geo_source' => 'geoip.php-backfill',
    ];
}

try {
    $pdo = new PDO(
        $dsn,
        $dbUser,
        $dbPass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (Throwable $e) {
    fwrite(STDERR, "Database connection failed: " . $e->getMessage() . "\n");
    exit(1);
}

$selectSql = "
SELECT id, public_ip
FROM case_views
WHERE id > :last_id
  AND public_ip IS NOT NULL
  AND public_ip <> ''
  AND (
    geo_source IS NULL OR geo_source = '' OR
    geo_ip IS NULL OR geo_ip = '' OR
    geo_country IS NULL OR geo_country = ''
  )
ORDER BY id ASC
LIMIT :lim
";

$updateSql = "
UPDATE case_views
SET
  geo_ip = :geo_ip,
  geo_continent_name = :geo_continent_name,
  geo_continent_code = :geo_continent_code,
  geo_country_name = :geo_country_name,
  geo_country = :geo_country,
  geo_region_code = :geo_region_code,
  geo_region = :geo_region,
  geo_city = :geo_city,
  geo_district = :geo_district,
  geo_postcode = :geo_postcode,
  geo_lat = :geo_lat,
  geo_lon = :geo_lon,
  geo_timezone = :geo_timezone,
  geo_utc_offset = :geo_utc_offset,
  geo_currency = :geo_currency,
  net_isp = :net_isp,
  net_org = :net_org,
  net_as = :net_as,
  net_as_name = :net_as_name,
  net_reverse_dns = :net_reverse_dns,
  is_mobile = :is_mobile,
  is_proxy = :is_proxy,
  is_hosting = :is_hosting,
  geo_source = :geo_source
WHERE id = :id
";

$selectStmt = $pdo->prepare($selectSql);
$updateStmt = $pdo->prepare($updateSql);

$cache = [];
$lastId = 0;
$totalScanned = 0;
$totalUpdated = 0;
$totalSkipped = 0;
$totalApiErrors = 0;
$apiCalls = 0;

while ($totalScanned < $maxRows) {
    $remaining = $maxRows - $totalScanned;
    $lim = min($batchSize, $remaining);

    $selectStmt->bindValue(':last_id', $lastId, PDO::PARAM_INT);
    $selectStmt->bindValue(':lim', $lim, PDO::PARAM_INT);
    $selectStmt->execute();
    $rows = $selectStmt->fetchAll();

    if (!$rows) {
        break;
    }

    foreach ($rows as $row) {
        $id = (int)$row['id'];
        $lastId = $id;
        $totalScanned++;

        $ip = trim((string)($row['public_ip'] ?? ''));
        if ($ip === '' || !is_public_ip($ip)) {
            $totalSkipped++;
            continue;
        }

        if (!array_key_exists($ip, $cache)) {
            $cache[$ip] = fetch_geo($apiBase, $ip);
            $apiCalls++;
            if ($cache[$ip] === null) {
                $totalApiErrors++;
            }
            if ($sleepMs > 0) {
                usleep($sleepMs * 1000);
            }
        }

        $geo = $cache[$ip];
        if (!is_array($geo)) {
            $totalSkipped++;
            continue;
        }

        if ($dryRun) {
            $totalUpdated++;
            continue;
        }

        $params = $geo;
        $params['id'] = $id;

        $updateStmt->execute($params);
        if ($updateStmt->rowCount() > 0) {
            $totalUpdated++;
        }
    }

    echo sprintf(
        "Progress: scanned=%d updated=%d skipped=%d api_calls=%d api_errors=%d last_id=%d\n",
        $totalScanned,
        $totalUpdated,
        $totalSkipped,
        $apiCalls,
        $totalApiErrors,
        $lastId
    );
}

echo "\nBackfill complete.\n";
echo sprintf("Scanned: %d\n", $totalScanned);
echo sprintf("Updated: %d\n", $totalUpdated);
echo sprintf("Skipped: %d\n", $totalSkipped);
echo sprintf("API calls: %d\n", $apiCalls);
echo sprintf("API errors: %d\n", $totalApiErrors);
