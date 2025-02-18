# macOS EPM JIT Log

Logs events when you perform the "Request Administrative Privileges" action in CyberArk EPM.  
Assumes requests are always granted (i.e. through the JIT approver service)

---

## Log Types

* `<epoch:ms>,request` - Request made
* `<epoch:ms>,request,<interval:ms>` - A new request was made `interval` ms after the previous request, before a grant was received
* `<epoch:ms>,requestPending,<interval:ms>` - A request created `interval` ms ago is still pending
  * This only appears after `120` seconds
* `<epoch:ms>,grant:<interval:ms>` - A request was granted after `interval` ms
* `<epoch:ms>,revoke` - Administrative privileges have been revoked
