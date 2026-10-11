<?php

function tp_ollama_settings_defaults(): array {
  return [
    'ollama_base_url' => '',
    'ollama_api_key' => '',
    'ollama_default_model' => '',
    'ollama_vision_model' => '',
    'ollama_timeout' => '120',
  ];
}

/** Validate connection details without making a request to the server. */
function tp_validate_ollama_settings(array $input): array {
  $settings = tp_ollama_settings_defaults();
  foreach ($settings as $key => $default) {
    if (!array_key_exists($key, $input)) { continue; }
    if (!is_string($input[$key])) {
      throw new InvalidArgumentException('Ollama settings must contain text values.');
    }
    $settings[$key] = trim($input[$key]);
  }

  $url = $settings['ollama_base_url'];
  if ($url !== '') {
    $parts = parse_url($url);
    if (strlen($url) > 2048
        || preg_match('/[\x00-\x20\x7F]/', $url)
        || !filter_var($url, FILTER_VALIDATE_URL)
        || !is_array($parts)
        || !in_array(strtolower((string)($parts['scheme'] ?? '')), ['http', 'https'], true)
        || empty($parts['host'])
        || isset($parts['user']) || isset($parts['pass'])
        || isset($parts['query']) || isset($parts['fragment'])) {
      throw new InvalidArgumentException('Enter a valid HTTP or HTTPS Ollama server URL without credentials, a query string, or a fragment.');
    }
    $settings['ollama_base_url'] = rtrim($url, '/');
  }
  if (strlen($settings['ollama_api_key']) > 4096
      || preg_match('/[\x00-\x20\x7F]/', $settings['ollama_api_key'])) {
    throw new InvalidArgumentException('The Ollama API key must not contain spaces or control characters.');
  }
  foreach (['ollama_default_model', 'ollama_vision_model'] as $key) {
    if (strlen($settings[$key]) > 255 || preg_match('/[\x00-\x20\x7F]/', $settings[$key])) {
      throw new InvalidArgumentException('Enter an Ollama model name of up to 255 characters without spaces or control characters.');
    }
  }
  $timeout = filter_var($settings['ollama_timeout'], FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 5, 'max_range' => 600],
  ]);
  if ($timeout === false) {
    throw new InvalidArgumentException('Ollama request timeout must be a whole number between 5 and 600 seconds.');
  }
  $settings['ollama_timeout'] = (string)$timeout;
  return $settings;
}

/** Read-only check of the native Ollama API; no inference or settings writes. */
function tp_test_ollama_server(array $input): array {
  try {
    $settings = tp_validate_ollama_settings($input);
  } catch (InvalidArgumentException $e) {
    return [false, 0, $e->getMessage()];
  }
  if ($settings['ollama_base_url'] === '') { return [false, 0, 'Enter an Ollama server URL first.']; }
  if (!function_exists('curl_init')) { return [false, 0, 'The server cURL extension is unavailable.']; }

  $headers = ['Accept: application/json'];
  if ($settings['ollama_api_key'] !== '') {
    $headers[] = 'Authorization: Bearer ' . $settings['ollama_api_key'];
  }
  $ch = curl_init($settings['ollama_base_url'] . '/api/tags');
  curl_setopt_array($ch, [
    CURLOPT_HTTPGET => true,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => min(10, (int)$settings['ollama_timeout']),
    CURLOPT_TIMEOUT => min(20, (int)$settings['ollama_timeout']),
    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    CURLOPT_FOLLOWLOCATION => false,
  ]);
  $response = curl_exec($ch);
  $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
  if ($response === false) {
    return [false, $httpCode, 'Unable to connect to Ollama. Check that the server URL is reachable from this web server.'];
  }
  if ($httpCode === 401 || $httpCode === 403) {
    return [false, $httpCode, 'The Ollama server rejected the credentials. Check the optional API key.'];
  }
  if ($httpCode === 404) {
    return [false, $httpCode, 'The Ollama API was not found. Enter the base server URL without /api or /v1.'];
  }
  if ($httpCode < 200 || $httpCode >= 300) {
    return [false, $httpCode, 'Ollama test failed with HTTP ' . ($httpCode > 0 ? $httpCode : 'unknown') . '.'];
  }
  $decoded = json_decode($response, true);
  if (!is_array($decoded) || !isset($decoded['models']) || !is_array($decoded['models'])) {
    return [false, $httpCode, 'The server did not return a valid Ollama model list. Check the server URL.'];
  }
  $models = [];
  foreach ($decoded['models'] as $model) {
    if (!is_array($model) || !is_string($model['name'] ?? null) || trim($model['name']) === '') {
      return [false, $httpCode, 'The server did not return a valid Ollama model list.'];
    }
    $models[] = $model['name'];
  }
  $message = 'Ollama connection succeeded. ';
  if (count($models) === 0) {
    $message .= 'No models are installed yet.';
  } else {
    $message .= 'Available models: ' . implode(', ', array_slice($models, 0, 5));
    if (count($models) > 5) { $message .= ' (and ' . (count($models) - 5) . ' more)'; }
    $message .= '.';
  }
  $defaultModel = $settings['ollama_default_model'];
  if ($defaultModel !== '' && !in_array($defaultModel, $models, true)
      && !in_array($defaultModel . ':latest', $models, true)) {
    $message .= ' The configured default model is not in the server model list.';
  }
  return [true, $httpCode, $message];
}

/** Server-side native API calls. Never expose credentials or remote error bodies. */
function tp_ollama_request(array $config, string $endpoint, array $payload): array {
  if (!in_array($endpoint, ['chat', 'show'], true)) { throw new InvalidArgumentException('Unsupported Ollama endpoint.'); }
  $validated = tp_validate_ollama_settings([
    'ollama_base_url' => (string)($config['base_url'] ?? ''),
    'ollama_api_key' => (string)($config['api_key'] ?? ''),
    'ollama_timeout' => (string)($config['timeout'] ?? 120),
  ]);
  if ($validated['ollama_base_url'] === '') { throw new RuntimeException('Configure the Ollama server in Project Settings first.'); }
  if (!function_exists('curl_init')) { throw new RuntimeException('The server cURL extension is unavailable.'); }
  $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
  if ($json === false) { throw new RuntimeException('Unable to prepare the Ollama request.'); }
  $headers = ['Content-Type: application/json', 'Accept: application/json'];
  if ($validated['ollama_api_key'] !== '') { $headers[] = 'Authorization: Bearer ' . $validated['ollama_api_key']; }
  $response = ''; $tooLarge = false;
  $ch = curl_init($validated['ollama_base_url'] . '/api/' . $endpoint);
  curl_setopt_array($ch, [
    CURLOPT_POST => true, CURLOPT_POSTFIELDS => $json, CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CONNECTTIMEOUT => min(10, (int)$validated['ollama_timeout']),
    CURLOPT_TIMEOUT => (int)$validated['ollama_timeout'],
    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_WRITEFUNCTION => static function ($handle, string $data) use (&$response, &$tooLarge): int {
      if (strlen($response) + strlen($data) > 8 * 1024 * 1024) { $tooLarge = true; return 0; }
      $response .= $data; return strlen($data);
    },
  ]);
  $result = curl_exec($ch);
  $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
  if ($tooLarge) { throw new RuntimeException('Ollama returned a response that exceeded the size limit.'); }
  if ($result === false) { throw new RuntimeException('Unable to connect to Ollama, or the request timed out. Check the server and timeout settings.'); }
  if ($httpCode === 401 || $httpCode === 403) { throw new RuntimeException('Ollama rejected the API credentials.'); }
  if ($httpCode < 200 || $httpCode >= 300) { throw new RuntimeException('Ollama request failed (HTTP ' . $httpCode . '). Check the server URL and installed model.'); }
  $decoded = json_decode($response, true);
  if (!is_array($decoded) || !empty($decoded['error'])) { throw new RuntimeException('Ollama returned an invalid or unsuccessful response.'); }
  return $decoded;
}

function tp_ollama_chat(array $config, array $messages, string $model = '', int $outputTokens = 4096): string {
  $model = trim($model !== '' ? $model : (string)($config['default_model'] ?? ''));
  if ($model === '') { throw new RuntimeException('Set an Ollama default model in Project Settings first.'); }
  $response = tp_ollama_request($config, 'chat', [
    'model' => $model, 'messages' => $messages, 'stream' => false,
    'options' => ['temperature' => 0.1, 'num_ctx' => 16384, 'num_predict' => $outputTokens],
  ]);
  $answer = $response['message']['content'] ?? null;
  if (!is_string($answer) || trim($answer) === '' || ($response['done'] ?? false) !== true) {
    throw new RuntimeException('Ollama did not return a complete answer.');
  }
  if (($response['done_reason'] ?? '') === 'length') {
    throw new RuntimeException('Ollama reached the output limit. The analysis was not stored as complete.');
  }
  return trim($answer);
}
