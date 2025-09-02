# macOS EPM JIT Log

Logs events when you perform the "Request Administrative Privileges" action in CyberArk EPM.  
Assumes requests are always granted (i.e. through the JIT approver service)

Supply `--json` for JSONL output

---

## Log Types

* `<epoch:ms>,request` - Request made
* `<epoch:ms>,requestPending` - A request that should have been granted already is still pending
  * This only appears after `120` seconds, and will be sent every 5 minutes until the request is granted or cancelled
* `<epoch:ms>,requestStopTracking` - A request that was never granted is being considered cancelled, and pending logs will no longer be emitted for it
  * This only appears after `2` hours
* `<epoch:ms>,grant,<interval:s>` - A request was granted after `interval` seconds
* `<epoch:ms>,grant` - A request was granted but it was not being tracked
  * e.g. if the logger started after the request had been made
* `<epoch:ms>,revoke,<interval:s>` - Administrative privileges have been revoked after `interval` seconds
* `<epoch:ms>,revoke` - Administrative privileges were revoked but it was not being tracked
  * e.g. if the logger started after the privileges had been granted
* `<epoch:ms>,revokePending` - A grant that should have been revoked already is still pending
  * This only appears after `65` minutes, and will be sent every hour until the request is granted or cancelled
* `<epoch:ms>,revokeStopTracking` - A grant that was never revoked is being considered cancelled, and pending logs will no longer be emitted for it
  * This only appears after `24` hours
