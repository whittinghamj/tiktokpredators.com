<?php

function tp_case_is_unpublished(array $case): bool {
    return in_array(($case['status'] ?? ''), ['Being Built', 'Pending', 'Rejected', 'Archived'], true);
}

/** Shared by case pages, metadata, photos and evidence; private statuses fail closed. */
function tp_case_is_visible(array $case): bool {
    if (!tp_case_is_unpublished($case)) { return true; }
    if (is_admin()) { return true; }
    if (is_moderator() && in_array(($case['status'] ?? ''), ['Pending', 'Rejected', 'Archived'], true)) { return true; }
    return !empty($_SESSION['user']) && (int)($case['created_by'] ?? 0) > 0
        && (int)$case['created_by'] === (int)($_SESSION['user']['id'] ?? 0);
}

function tp_case_review_warning(array $case): array {
    if (($case['status'] ?? '') === 'Archived') {
        return ['ARCHIVED CASE — NON-PUBLIC INFORMATION', 'This case is archived and is no longer publicly visible. Its details and evidence are non-public information. This private link is for read-only access. Do not publish or redistribute this information.'];
    }
    return ['UNVERIFIED & UNPUBLISHED CASE', 'This case has NOT been verified, approved, or published. It may contain mistakes or unverified allegations. This private link is for read-only review.'];
}

function tp_can_share_case_review(array $case): bool {
    if (!tp_case_is_unpublished($case) || empty($_SESSION['user'])) { return false; }
    if (is_admin()) { return true; }
    if (is_moderator() && in_array(($case['status'] ?? ''), ['Pending', 'Rejected', 'Archived'], true)) { return true; }
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
            AND c.status IN ('Being Built', 'Pending', 'Rejected', 'Archived') LIMIT 1");
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
