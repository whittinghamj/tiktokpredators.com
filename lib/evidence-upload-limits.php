<?php

/** Report the usable per-file limit from the application and active PHP settings. */
function tp_evidence_upload_limit(): int {
    $limits = [500 * 1024 * 1024];
    $fileLimit = tp_evidence_ini_bytes((string)ini_get('upload_max_filesize'));
    $postLimit = tp_evidence_ini_bytes((string)ini_get('post_max_size'));
    if ($fileLimit > 0) { $limits[] = $fileLimit; }
    // Reserve room for the multipart boundaries and ordinary evidence metadata.
    if ($postLimit > 0) { $limits[] = max(1, $postLimit - 64 * 1024); }
    return min($limits);
}

function tp_evidence_upload_size_label(int $bytes): string {
    if ($bytes < 1024) { return $bytes . ' bytes'; }
    $divisor = $bytes < 1024 * 1024 ? 1024 : 1024 * 1024;
    return rtrim(rtrim(number_format($bytes / $divisor, 2, '.', ''), '0'), '.') . ($divisor === 1024 ? ' KB' : ' MB');
}

/** PHP discards POST and FILES when the whole request exceeds post_max_size. */
function tp_evidence_reject_oversized_post(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { return; }
    $postLimit = tp_evidence_ini_bytes((string)ini_get('post_max_size'));
    if ($postLimit <= 0 || (int)($_SERVER['CONTENT_LENGTH'] ?? 0) <= $postLimit) { return; }
    http_response_code(413);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode(['ok' => false, 'error' => 'The upload exceeds the server request-size limit of '
        . tp_evidence_upload_size_label($postLimit) . '. Maximum file size: '
        . tp_evidence_upload_size_label(tp_evidence_upload_limit()) . '.']);
    exit;
}

function tp_evidence_upload_error(array $file): string {
    switch ((int)($file['error'] ?? UPLOAD_ERR_NO_FILE)) {
        case UPLOAD_ERR_OK:
            return (int)($file['size'] ?? 0) > tp_evidence_upload_limit()
                ? 'File is too large. Maximum file size: ' . tp_evidence_upload_size_label(tp_evidence_upload_limit()) . '.'
                : '';
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
            return 'File is too large. Maximum file size: ' . tp_evidence_upload_size_label(tp_evidence_upload_limit()) . '.';
        case UPLOAD_ERR_PARTIAL:
            return 'The upload was interrupted before the whole file arrived. Please try again.';
        case UPLOAD_ERR_NO_FILE:
            return 'No file was received. Please choose a file and try again.';
        case UPLOAD_ERR_NO_TMP_DIR:
        case UPLOAD_ERR_CANT_WRITE:
            return 'The server could not store the upload. Please ask the site administrator to check storage space and permissions.';
        default:
            return 'The server stopped the upload. Please try again or contact the site administrator.';
    }
}
