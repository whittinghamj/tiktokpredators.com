# Private case evidence reports and chat

Project Settings configures the Ollama base URL, optional bearer API key, Default Model, optional separate Vision Model, and request timeout. The Default Model is required for reports and case chat. Images need a vision-capable model; without a separate Vision Model, the Default Model is checked for vision support. Both models must already be installed on the configured server. Requests are made by the web server/worker, so Ollama must be reachable from that host.

Reports are queued when cases are created, submitted or resubmitted, approved, or changed, and when evidence/notes are added, updated, rotated or removed. Existing cases are queued once by the migration. The worker processes one case per invocation, with a database advisory lock preventing overlapping workers. Submission and approval do not wait for inference and remain available if Ollama is offline. Failed jobs show a private error and can be retried using Generate / Refresh Report.

The detailed report, original extracted text, per-source analyses and coverage are stored in `case_ollama_reports`, separately from public case fields. Chat is restricted to the admin role, including all report/status/chat endpoints. Viewers, submitters and moderators receive no panel and cannot access the API. Each admin's conversations are stored separately in `case_ollama_messages`. New evidence invalidates the old report; stale reports and old report-version chat history are not used. Case deletion removes both private tables' rows. Reports and chat are rendered as text, without executing HTML or Markdown from an upload or model.

The Cases grid shows admins an **AI Summary** badge on each card: **Complete** for a current Ready report, **Pending** for queued/in-progress work or a stale report, and **Not started** when no report has been queued. Coverage gaps show **Partial** and generation errors show **Failed**. Missing report tables show **Unavailable** without breaking the case list. The badges read only status/version metadata for the current page and update when the list is refreshed.

Open **Administration → AI Summary Failures** to review failed attempts and current partial summaries on a separate private page. Filter by Failed or Partial, then use **View Report** for the recorded error, timestamps, source coverage issues, any available partial summary, and up to 40 retained worker events since that job was queued. Failed attempts may have no saved AI summary; the page shows recorded diagnostics instead. Retry queues a fresh version through an admin-only CSRF-protected form. Duplicate or outdated retries are rejected. Successfully completed and queued cases leave this list; this is the current issues list, not a permanent archive of every historical failure. No schema changes are required for this page.

Ingestion reads original private evidence through the existing safe path resolver, including full evidence notes, case notes, supplied case details and the profile photo. Long text is chunked; large images are tiled at original resolution, respecting display rotation. PDFs have every page extracted as text and rendered for vision analysis. DOCX includes document text, headers/footers, footnotes/endnotes/comments and embedded images. A hierarchical overview is stored alongside every detailed source analysis. For large reports, chat retrieves relevant stored text/analysis excerpts and the overview; the prompt explicitly identifies omitted excerpts and requires answers to acknowledge missing information. This is keyword retrieval, not vector search, and cannot guarantee that every relevant passage is selected for a broad question.

Unsupported or unreadable uploads are listed explicitly and produce a Partial report. Audio/video files and legacy binary Word files need a transcript or supported text/image export. URL evidence records the submitted link without crawling its destination. Image decoding supports static JPEG, PNG and WebP through the existing GD helper; animated images are not flattened silently. Limits are explicit coverage failures: 128 MiB per file/expanded DOCX, 32 MiB plain text, 500 PDF pages, 128 image tiles, and a 64 MiB stored analysis budget. Exceeding the overall report budget fails the job rather than claiming a complete report. Model output truncation is also treated as a failure. Original evidence is never modified by ingestion.

## Deployment

Deploy all changed files together. Run `php scripts/migrate.php` with the same DB_DSN, DB_USER and DB_PASS as PHP-FPM. The normal `sudo bash update.sh` path runs migrations and installs/enables the systemd worker timer. The installer uses the private storage owner's user/group (or OLLAMA_WORKER_USER / OLLAMA_WORKER_GROUP overrides). Its account needs read access to private evidence and database access. On the first installation, explicit DB environment overrides are saved in `/etc/tiktokpredators/ollama-worker.env`, protected outside the web root. That file is preserved on future updates; update it when DB credentials change. Default DB connection behavior otherwise matches the existing application bootstrap.

PHP CLI needs curl, mbstring, GD, ZIP and DOM. The installed worker has a 512 MiB PHP memory limit. PDF ingestion additionally needs Poppler's `pdfinfo`, `pdftotext` and `pdftoppm` (typically the `poppler-utils` package on Debian/Ubuntu). Poppler runs through argument arrays, without shell interpolation. Temporary extraction files are created in a random private directory and removed after each job; the systemd service also has a private temporary directory.

The timer runs the next queued job 20 seconds after the previous worker finishes. Monitor it with `systemctl status tiktokpredators-ollama.timer` and `journalctl -u tiktokpredators-ollama.service`. Logs contain progress metadata, not reports or credentials. On a host without systemd, schedule `php /var/www/html/tiktokpredators.com/scripts/ollama-worker.php` every minute as the storage owner with the PHP-FPM database environment. Overlapping invocations exit without processing a second job.

## Live worker monitoring

Open **Administration → Ollama Worker Log** (also shown on System Health and the admin dashboard). The panel refreshes every three seconds and shows the active case, current source, source/part progress, selected model, activity duration, heartbeat age, queue counts and the latest events. Live updates and automatic scrolling can be paused independently. It detects when a Processing job no longer has an active database worker lock, rather than treating a saved Processing status as proof that a worker is still running.

The worker records progress at extraction, model requests, analysis completion, overview synthesis and report saves. During cURL waits and document extraction, its heartbeat updates at most once every ten seconds. The database retains approximately 5,000 recent events; the browser shows up to 500 during a viewing session. Stored event metadata can include original filenames, but never prompts, extracted evidence text, model answers or API credentials. Journal lines use numeric case/evidence IDs instead of source filenames. Monitoring failures do not block report generation.

Deploy this change with `update.sh` so the new `ollama_worker_state` and `ollama_worker_events` tables are created. A worker already running older code can finish; the panel shows its current case and explains that detailed progress starts with the next invocation. The update does not require killing or restarting an in-progress report.

On the web server, follow the service's journal with:

```sh
sudo journalctl -u tiktokpredators-ollama.service -n 100 -f
```

Inspect the current service and timer with:

```sh
sudo systemctl status tiktokpredators-ollama.service tiktokpredators-ollama.timer
```

After deployment, enter the server/models in Project Settings, test the connection, open an admin case page and confirm that its report completes. Check one public, moderator and submitter case view to confirm the private panel is absent. Inspect coverage before relying on answers.

## Local verification

Run `php tests/ollama.php`, `php tests/case-ollama.php` and `php tests/performance.php`. The Ollama tests use temporary loopback mock servers and synthetic evidence/SQLite data; they never read production evidence or use the application database. They verify text/DOCX/image extraction, model payloads, persistence, workflow queue triggers, access controls, history isolation, and rejection of reports/answers made stale by concurrent changes. PHP/JavaScript/shell syntax checks and an admin/public browser preview complement these tests. Actual model quality and production MySQL/systemd behavior still need a deployment check. Poppler is not installed in the local test environment, so real PDF extraction has not been exercised here.
