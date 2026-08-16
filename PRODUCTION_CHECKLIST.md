# WAPOLE STUDIOS v7 — Production & Security Checklist

## Included in v7
- Security response headers
- API rate limiting
- No-cache headers for API responses
- Constant-time comparison for customer access codes
- Protected file-download path resolution
- Production environment template
- Deployment/security checklist

## Before going live
1. Change the default admin username/password.
2. Set a long random `JWT_SECRET`.
3. Use HTTPS/TLS.
4. Keep `backend/wapole.db` outside any public web directory.
5. Keep `storage/` outside any public web directory.
6. Back up the SQLite database and storage regularly.
7. Add malware/virus scanning for customer uploads.
8. Restrict upload MIME types/extensions to the business formats you actually need.
9. Put the app behind a reverse proxy such as Nginx or a managed hosting proxy.
10. Disable verbose error output in production.
11. Test order, payment, file upload/download and notification flows on the real hosting environment.
12. Use a process manager (for example PM2/systemd) so the Node server restarts automatically.
13. Do not commit `.env` or real credentials to Git.
14. Rotate admin credentials and JWT secret if they are ever exposed.

## Important
The payment system is still MANUAL. It does not directly connect to YAS or another payment gateway.

The default development credentials from earlier versions must NOT be used in production.
