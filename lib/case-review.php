<?php

function tp_case_is_unpublished(array $case): bool {
    return in_array(($case['status'] ?? ''), ['Being Built', 'Pending', 'Rejected'], true);
}

function tp_can_share_case_review(array $case): bool {
    if (!tp_case_is_unpublished($case) || empty($_SESSION['user'])) { return false; }
    if (is_admin()) { return true; }
    if (is_moderator() && in_array(($case['status'] ?? ''), ['Pending', 'Rejected'], true)) { return true; }
    return in_array(current_user_role(), ['viewer', 'moderator'], true)
        && (int)($case['created_by'] ?? 0) > 0
        && (int)$case['created_by'] === (int)($_SESSION['user']['id'] ?? 0);
}

/** Bearer links grant read access to one unpublished case, never account privileges. */
function tp_case_review_lookup(PDO $pdo, $token): ?array {
    if (!is_string($token) || !preg_match('/\A[a-f0-9]{64}\z/D', $token)) { return null; }
    try {
        $query = $pdo->prepare("SELECT c.id, c.case_code, c.case_name, c.person_name, c.location, c.phone_number,
            c.snapchat_username, c.discord_username, c.tiktok_username, c.initial_summary, c.status,
            c.sensitivity, c.opened_at, r.expires_at
            FROM case_review_links r JOIN cases c ON c.id = r.case_id
            WHERE r.token_hash = ? AND r.revoked_at IS NULL AND r.expires_at > UTC_TIMESTAMP()
            AND c.status IN ('Being Built', 'Pending', 'Rejected') LIMIT 1");
        $query->execute([hash('sha256', $token)]);
        return $query->fetch(PDO::FETCH_ASSOC) ?: null;
    } catch (Throwable $e) {
        // Missing schema or storage outages must never open a private case.
        return null;
    }
}

function tp_case_review_headers(): void {
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    header('Referrer-Policy: no-referrer');
    header('X-Robots-Tag: noindex, nofollow, noarchive, noimageindex');
    header('X-Content-Type-Options: nosniff');
}
