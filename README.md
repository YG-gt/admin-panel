# 🔒 Paranoia Matrix Admin Panel v1.0

```
  ____                            _       
 |  _ \ __ _ _ __ __ _ _ __   ___ (_) __ _ 
 | |_) / _` | '__/ _` | '_ \ / _ \| |/ _` |
 |  __/ (_| | | | (_| | | | | (_) | | (_| |
 |_|   \__,_|_|  \__,_|_| |_|\___/|_|\__,_|
                                          
```

Old-school Matrix Synapse admin panel that just works.

**Created by [EasyProTech LLC](https://www.easypro.tech) • Developed by Brabus**

![PHP](https://img.shields.io/badge/PHP-8.1+-777BB4?style=flat-square&logo=php)
![Matrix](https://img.shields.io/badge/Matrix-Synapse-000000?style=flat-square&logo=matrix)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Security-First-red?style=flat-square)

Paranoia is a minimalist admin panel for Matrix Synapse. No frameworks, no dependencies, no nonsense. Pure PHP that works.

## 📑 Table of Contents

- [🎯 Quick Start](#-quick-start-2-minutes)
- [💡 Why Paranoia](#-why-paranoia)
- [✨ Features](#-features)
- [📸 Screenshots](#-screenshots)
- [🔧 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [🛡️ Security](#️-security)
- [🏗️ Architecture](#️-architecture)
- [📝 License](#-license)
- [📞 Support](#-support)

## 🎯 Quick Start (2 minutes)

```bash
# Download
git clone https://github.com/EPTLLC/paranoia.matrix.git
cd paranoia.matrix

# Configure
cp config.ini.example config.ini
# Edit config.ini with your Matrix server details

# Deploy (example)
sudo ln -sf $(pwd)/* /var/www/paranoia-matrix/
sudo systemctl reload nginx
```

Access your admin panel and login with Matrix admin credentials.

## 💡 Why Paranoia

> *From the author – Brabus*

Matrix admin tools are overcomplicated. Frameworks, dependencies, CORS issues, complex setups.

I needed something that:
- Works immediately after setup
- Has zero external dependencies  
- Can be audited in 30 minutes
- Won't break with updates

So I built Paranoia. Old-school PHP. Simple, secure, reliable.

## ✨ Features

### Core Functionality
- 👥 **User Management** - Create, deactivate, reactivate users
- 🔑 **Password Management** - Change user passwords  
- 👑 **Admin Rights** - Grant/revoke admin privileges
- 📊 **Activity Logging** - All actions logged with CSV export
- 🗄️ **Auto-archiving** - Weekly log rotation
- 🛡️ **Self-protection** - Prevent admin lockout

### Security
- 🔐 **Matrix API Auth** - Admin-only access via Matrix
- 🛡️ **CSRF Protection** - Token-based security
- ⏱️ **Rate Limiting** - Brute force protection
- 📝 **Audit Trail** - Complete action logging
- 🚫 **Input Validation** - All data sanitized

### Interface
- 🎨 **Old-school Design** - Green terminal aesthetic
- 📱 **Mobile Friendly** - Works on all devices
- 🔍 **User Search** - Find users quickly
- 👻 **Deactivated Filter** - Show/hide inactive users
- 📤 **CSV Export** - Download audit logs

## 📸 Screenshots

### Admin Panel
![Admin Panel](screens/admin.jpg)
*User management interface with search and filtering*

### Activity Logs  
![Activity Logs](screens/logs.jpg)
*Complete audit trail with export functionality*

### Landing Page
![Landing Page](screens/index.jpg)
*Simple landing page with project info*

## 🔧 Installation

### Requirements
- PHP 8.1+ with extensions: curl, mbstring, fpm
- Nginx web server
- Matrix Synapse with Admin API enabled
- SSL certificate (recommended)

### 1. System Setup
```bash
apt update
apt install -y nginx php8.1 php8.1-fpm php8.1-curl php8.1-mbstring certbot python3-certbot-nginx
systemctl enable nginx php8.1-fpm
systemctl start nginx php8.1-fpm
```

### 2. Download & Configure
```bash
git clone https://github.com/EPTLLC/paranoia.matrix.git
cd paranoia.matrix
cp config.ini.example config.ini
```

### 3. Web Server Setup
```bash
# Create web directory
sudo mkdir -p /var/www/paranoia-matrix
sudo ln -sf $(pwd)/* /var/www/paranoia-matrix/

# Nginx configuration
sudo tee /etc/nginx/sites-available/paranoia-matrix << 'EOF'
server {
    listen 80;
    server_name your-admin-domain.com;
    root /var/www/paranoia-matrix;
    index index.php;
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Security
    location ~ /\. { deny all; }
    location ~ /config\.ini { deny all; }
    location ~ /.*\.log { deny all; }
}
EOF

sudo ln -sf /etc/nginx/sites-available/paranoia-matrix /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 4. SSL & Permissions
```bash
# SSL certificate
sudo certbot --nginx -d your-admin-domain.com

# Set permissions
sudo chown -R www-data:www-data /var/www/paranoia-matrix
sudo mkdir -p /var/log/paranoia-matrix
sudo chown www-data:www-data /var/log/paranoia-matrix
```

## ⚙️ Configuration

Edit `config.ini`:

```ini
[matrix]
server = "https://your-matrix-server.com"
domain = "your-matrix-domain.com"

[security]
log_file = "/var/log/paranoia-matrix/admin-actions.log"
max_failed_attempts = 5
login_delay_microseconds = 300000
```

| Parameter | Description |
|-----------|-------------|
| `server` | Your Matrix server URL |
| `domain` | Matrix server domain for user IDs |
| `log_file` | Path to activity log file |
| `max_failed_attempts` | Login attempt limit |
| `login_delay_microseconds` | Delay after failed login |

## 🛡️ Security

### Design Principles
- **Zero Dependencies** - No external libraries to compromise
- **Minimal Code** - Easy to audit (< 1000 lines total)
- **Direct API** - No proxy layers or complications
- **File-based** - Simple logging and configuration

### Protection Mechanisms
- Matrix API authentication with admin verification
- CSRF tokens on all forms
- Rate limiting with progressive delays
- Input validation and sanitization
- Self-protection against admin lockout
- Automatic log archiving and rotation

## 🏗️ Architecture

```
paranoia.matrix/
├── config.ini              # Configuration
├── index.php               # Landing page
├── admin.php               # Main admin interface  
├── logs.php                # Log viewer
├── screens/                # Screenshots
└── README.md               # Documentation
```

### Matrix API Integration
- `/_matrix/client/r0/login` - Authentication
- `/_synapse/admin/v1/users/@user:domain/admin` - Admin verification  
- `/_synapse/admin/v2/users` - User listing and management
- `/_synapse/admin/v1/users/@user:domain/password` - Password changes

### Philosophy
Built for admins who value:
- **Simplicity** over complexity
- **Security** over features  
- **Reliability** over trends
- **Auditability** over abstraction

## 📝 License

MIT License

Copyright (c) 2025 EasyProTech LLC  
Developed by Brabus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

--------------------------------------------------------------------------------

**ADDITIONAL NOTICE:**

This software is provided without any support, maintenance, or guarantees.
The author explicitly states:

- NO SUPPORT will be provided (free or paid)
- NO CONSULTATIONS will be offered  
- NO EXPLANATIONS beyond the existing documentation
- NO OBLIGATIONS to fix bugs or add features

Use this software at your own risk. By using this software, you acknowledge
and accept these terms.

Contributions are welcome but will be reviewed at the author's discretion
with no guaranteed timeline for review or acceptance.

## 📞 Support

I do **not** provide support.  
I do **not** consult — not for free, not for money, not in any form.

Please don't ask for help, fixes, or explanations — this project is released as-is.

If someone wants to help with development — contributions are welcome.  
But there are **no obligations from my side** whatsoever. 