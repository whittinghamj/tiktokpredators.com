'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../index.php'), 'utf8');
const start = source.indexOf('  function uploadResponse(xhr)');
const end = source.indexOf('  function detectType(file)', start);
assert(start >= 0 && end > start, 'Uploader response handler missing.');
const context = vm.createContext({ maxUploadLabel: '500 MB' });
vm.runInContext(source.slice(start, end), context);
for (const [status, responseText, expected] of [
  [413, '<html>Request Entity Too Large</html>', /too large/i],
  [504, '<html>Gateway timeout</html>', /timed out/i],
  [524, '', /timed out/i],
  [500, '<html>Server error</html>', /HTTP 500/],
  [502, '{"ok":true}', /HTTP 502/],
  [403, '<html>Sign in</html>', /not authorized/i],
  [200, '<html>Case page after PHP discarded the body</html>', /upload limit/i],
  [200, 'null', /did not return an upload result/i],
  [200, '"unexpected string"', /did not return an upload result/i],
  [200, '{"ok":"yes"}', /did not return an upload result/i],
  [413, '{"ok":false,"error":"Maximum file size: 200 MB."}', /200 MB/],
  [200, '{"ok":false,"error":"Identical file already exists."}', /Identical file/],
]) {
  const result = context.uploadResponse({ status, responseText });
  assert.equal(result.ok, false, 'Rejected or malformed response was treated as success.');
  assert.match(result.error, expected);
  assert(!result.error.includes('Invalid server response'));
}
assert.equal(context.uploadResponse({ status: 200, responseText: '{"ok":true,"evidence_id":123}' }).evidence_id, 123);
console.log('Upload response checks passed: size rejection, timeouts, server/auth errors, malformed responses and valid JSON.');
