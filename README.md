# WAPOLE STUDIOS — Customer + Admin Dashboards v6

This version adds modern dashboards on top of the existing order, payment, file and notification system.

## Customer Dashboard
- Overview and order summary
- Current order status
- Progress timeline
- Payment history
- Payment submission with optional proof
- My Files
- Reference file upload
- File downloads
- Notifications

Access is via Order ID + Access Code (no customer account/password required).

## Admin Dashboard
- Summary statistics
- Total orders
- Pending orders
- Payment verification count
- Processing count
- Completed count
- Verified payment revenue
- Search/filter orders
- Update order status
- View order details
- Verify/reject payments
- Recent notifications

## Run
Node.js 18+ recommended.

```bash
npm install
npm start
```

Open:
- Customer/Home: http://localhost:3000/
- Admin: http://localhost:3000/admin.html

Development admin:
Username: admin
Password: wapole2026

## Important
This is a local development build. Before production: set a strong JWT_SECRET, change admin credentials, use HTTPS, persistent storage/backups, and add virus scanning for uploads.


## v7 Production & Security
This build adds security headers, API rate limiting, safer customer access-code comparison, protected download path resolution, and production configuration templates. See `PRODUCTION_CHECKLIST.md` before deployment.


## v8 Services & Packages
The public home page now displays all 7 official services with their prices, the 3 official packages, and a booking form connected to the order API.

## v9 Multi-Service Ordering + Official Logo
- Uploaded WAPOLE logo is displayed on the Home page.
- Customers can select multiple individual services in one order.
- The order total is calculated automatically.
- Packages are available as an alternative to individual services.
- Selecting Lyrics Video reveals a required lyrics field.
- Lyrics are stored with the order for Admin processing.


## YAS LIPA
Payment number: **170137394**
Name: **FADHILI JACKSON POLE**


## Customer Information
The order form now asks for Full Name, Phone/WhatsApp Number, optional Email Address, Country/Location, and Project Requirements.


## v12 Customer Accounts
Customers can now register and log in before placing their first order. Customer accounts use email + password and have a dashboard showing orders and a first-order action when no orders exist. The legacy Order ID + Access Code access remains available.
