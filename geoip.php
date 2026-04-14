<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

// Get IP from query string, or use visitor IP
$ip = $_GET['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');

if ($ip === '') {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => 'No IP address provided'
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// Validate IP
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => 'Invalid IP address',
        'ip' => $ip
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// Fields to request from ip-api
$fields = implode(',', [
    'status',
    'message',
    'continent',
    'continentCode',
    'country',
    'countryCode',
    'region',
    'regionName',
    'city',
    'district',
    'zip',
    'lat',
    'lon',
    'timezone',
    'offset',
    'currency',
    'isp',
    'org',
    'as',
    'asname',
    'reverse',
    'mobile',
    'proxy',
    'hosting',
    'query'
]);

$apiUrl = "http://ip-api.com/json/" . urlencode($ip) . "?fields=" . urlencode($fields);

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $apiUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_FAILONERROR => false,
    CURLOPT_USERAGENT => 'PHP GeoIP Lookup Script'
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if ($response === false || $curlError) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Failed to contact GeoIP API',
        'details' => $curlError
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$data = json_decode($response, true);

if (!is_array($data)) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Invalid JSON returned from API',
        'raw_response' => $response
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

if (($data['status'] ?? '') !== 'success') {
    http_response_code($httpCode > 0 ? $httpCode : 400);
    echo json_encode([
        'success' => false,
        'error' => 'GeoIP lookup failed',
        'api_response' => $data
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// Return a clean JSON array/object
$result = [
    'success' => true,
    'data' => [
        'ip' => $data['query'] ?? null,
        'continent' => [
            'name' => $data['continent'] ?? null,
            'code' => $data['continentCode'] ?? null
        ],
        'country' => [
            'name' => $data['country'] ?? null,
            'code' => $data['countryCode'] ?? null
        ],
        'region' => [
            'code' => $data['region'] ?? null,
            'name' => $data['regionName'] ?? null
        ],
        'city' => $data['city'] ?? null,
        'district' => $data['district'] ?? null,
        'postcode' => $data['zip'] ?? null,
        'location' => [
            'lat' => $data['lat'] ?? null,
            'lon' => $data['lon'] ?? null,
            'timezone' => $data['timezone'] ?? null,
            'utc_offset' => $data['offset'] ?? null
        ],
        'network' => [
            'isp' => $data['isp'] ?? null,
            'org' => $data['org'] ?? null,
            'as' => $data['as'] ?? null,
            'as_name' => $data['asname'] ?? null,
            'reverse_dns' => $data['reverse'] ?? null
        ],
        'flags' => [
            'mobile' => $data['mobile'] ?? null,
            'proxy' => $data['proxy'] ?? null,
            'hosting' => $data['hosting'] ?? null
        ],
        'currency' => $data['currency'] ?? null
    ]
];

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);