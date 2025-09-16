# HAProxy Installation Guide

High-performance TCP/HTTP load balancer and reverse proxy for distributing traffic across multiple backend servers. Industry standard for load balancing with enterprise-grade security and reliability.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- Linux system (any modern distribution)
- Root or sudo access
- 2GB RAM minimum, 4GB+ recommended for high-traffic environments
- Multiple backend servers to load balance (optional for testing)
- SSL certificates for production HTTPS termination


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### Using Package Manager (Recommended)

#### Ubuntu/Debian
```bash
# Update package list
sudo apt-get update

# Install HAProxy and utilities
sudo apt-get install -y haproxy haproxy-doc software-properties-common

# For latest version from PPA
sudo add-apt-repository ppa:vbernat/haproxy-2.8
sudo apt-get update
sudo apt-get install -y haproxy=2.8.*

# Enable and start HAProxy
sudo systemctl enable --now haproxy

# Check status
sudo systemctl status haproxy
```

#### RHEL/CentOS/Rocky Linux/AlmaLinux
```bash
# Install EPEL repository
sudo yum install -y epel-release

# Install HAProxy
sudo yum install -y haproxy

# For newer versions
sudo dnf install -y haproxy

# Enable and start HAProxy
sudo systemctl enable --now haproxy

# Check status
sudo systemctl status haproxy
```

#### Fedora
```bash
# Install HAProxy
sudo dnf install -y haproxy

# Enable and start HAProxy
sudo systemctl enable --now haproxy

# Configure firewall
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=8404/tcp  # Stats interface
sudo firewall-cmd --reload
```

#### Arch Linux
```bash
# Install HAProxy
sudo pacman -Syu haproxy

# Enable and start HAProxy
sudo systemctl enable --now haproxy

# Check status
sudo systemctl status haproxy
```

#### Alpine Linux
```bash
# Install HAProxy
sudo apk update
sudo apk add haproxy

# Enable and start HAProxy
sudo rc-update add haproxy default
sudo service haproxy start
```

### From Source (Latest Features)
```bash
# Install build dependencies
# Ubuntu/Debian
sudo apt-get install -y build-essential libssl-dev libpcre3-dev zlib1g-dev liblua5.3-dev libsystemd-dev

# RHEL/CentOS
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel pcre-devel zlib-devel lua-devel systemd-devel

# Download latest HAProxy LTS
HAPROXY_VERSION="3.0.5"
cd /tmp
wget "https://www.haproxy.org/download/3.0/src/haproxy-${HAPROXY_VERSION}.tar.gz"
tar xzf haproxy-${HAPROXY_VERSION}.tar.gz
cd haproxy-${HAPROXY_VERSION}

# Compile with full features
make clean
make -j$(nproc) TARGET=linux-glibc \
    USE_OPENSSL=1 \
    USE_ZLIB=1 \
    USE_PCRE=1 \
    USE_SYSTEMD=1 \
    USE_LUA=1 \
    USE_PROMEX=1 \
    USE_THREAD=1 \
    USE_CPU_AFFINITY=1 \
    USE_TFO=1 \
    USE_NS=1 \
    USE_DL=1 \
    USE_RT=1

# Install HAProxy
sudo make install
sudo mkdir -p /etc/haproxy /var/lib/haproxy /var/log/haproxy
sudo useradd --system --home /var/lib/haproxy --shell /bin/false haproxy
sudo chown -R haproxy:haproxy /var/lib/haproxy /var/log/haproxy

# Create systemd service
sudo tee /etc/systemd/system/haproxy.service > /dev/null <<EOF
[Unit]
Description=HAProxy Load Balancer
Documentation=man:haproxy(1)
Documentation=file:/usr/share/doc/haproxy/configuration.txt
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/sbin/haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock
ExecReload=/bin/kill -USR2 \$MAINPID
ExecStop=/bin/kill -USR1 \$MAINPID
KillMode=mixed
Restart=on-failure
SuccessExitStatus=143
KillSignal=SIGTERM

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/haproxy
ReadWritePaths=/var/log/haproxy
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now haproxy
```

### Using Docker
```bash
# Create HAProxy configuration directory
mkdir -p ~/haproxy/{config,ssl,logs}

# Create basic configuration
cat > ~/haproxy/config/haproxy.cfg <<EOF
global
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    
    # SSL configuration
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-ciphers ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    option forwardfor
    option http-server-close
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    timeout http-keep-alive 4000
    timeout check 3000

# Frontend
frontend web_frontend
    bind *:80
    bind *:443 ssl crt /usr/local/etc/haproxy/ssl/ alpn h2,http/1.1
    
    # Redirect HTTP to HTTPS
    redirect scheme https code 301 if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend web_servers

# Backend
backend web_servers
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    server web1 192.168.1.10:8080 check
    server web2 192.168.1.11:8080 check
    server web3 192.168.1.12:8080 check

# Stats interface
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOF

# Run HAProxy container
docker run -d \
  --name haproxy \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 8404:8404 \
  -v ~/haproxy/config:/usr/local/etc/haproxy:ro \
  -v ~/haproxy/ssl:/usr/local/etc/haproxy/ssl:ro \
  -v ~/haproxy/logs:/var/log/haproxy \
  haproxy:latest
```

## Production Configuration

### Enterprise Production Configuration
```bash
# Backup original configuration
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.backup

# Create comprehensive production configuration
sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<EOF
#---------------------------------------------------------------------
# HAProxy Enterprise Production Configuration
# Version: 3.0+ LTS
#---------------------------------------------------------------------

global
    log 127.0.0.1:514 local0 info
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL/TLS configuration (2024 best practices)
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets prefer-client-ciphers
    
    ssl-default-server-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets

    # DH parameters for perfect forward secrecy
    ssl-dh-param-file /etc/haproxy/ssl/dhparam.pem
    
    # Performance tuning
    maxconn 40000
    nbthread 4
    cpu-map auto:1/1-4 0-3
    
    # Logging
    log-tag haproxy-prod
    
    # Security
    insecure-fork-wanted
    insecure-setuid-wanted

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    option forwardfor except 127.0.0.0/8
    option http-server-close
    option redispatch
    
    # Timeouts
    timeout connect 10s
    timeout client 1m
    timeout server 1m
    timeout http-keep-alive 10s
    timeout check 10s
    timeout tunnel 2h
    
    # Retries
    retries 3
    
    # Compression
    compression algo gzip
    compression type text/html text/css text/javascript application/javascript application/json application/xml
    
    # Default error pages
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

#---------------------------------------------------------------------
# Frontend Configuration
#---------------------------------------------------------------------

frontend web_frontend
    bind *:80
    bind *:443 ssl crt /etc/haproxy/ssl/ alpn h2,http/1.1 crt-ignore-err all
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny if { sc_http_req_rate(0) gt 20 }
    
    # Block bad bots and crawlers
    acl is_bot hdr_sub(User-Agent) -i bot crawler spider scraper
    http-request deny if is_bot
    
    # ACLs for routing
    acl is_api path_beg /api/
    acl is_admin path_beg /admin/
    acl is_static path_beg /static/ /css/ /js/ /images/
    acl is_websocket hdr(Upgrade) -i websocket
    
    # Force HTTPS
    redirect scheme https code 301 if !{ ssl_fc }
    
    # Routing rules
    use_backend api_servers if is_api
    use_backend admin_servers if is_admin
    use_backend static_servers if is_static
    use_backend websocket_servers if is_websocket
    default_backend web_servers

#---------------------------------------------------------------------
# Backend Configurations
#---------------------------------------------------------------------

# Main web servers
backend web_servers
    balance leastconn
    option httpchk GET /health HTTP/1.1\r\nHost:\ example.com
    http-check expect status 200
    
    # Health check configuration
    default-server inter 2000 rise 2 fall 3 slowstart 60s maxconn 250 maxqueue 256 weight 100
    
    server web1 192.168.1.10:8080 check cookie web1
    server web2 192.168.1.11:8080 check cookie web2
    server web3 192.168.1.12:8080 check cookie web3
    server web4 192.168.1.13:8080 check cookie web4 backup
    
    # Stick table for session persistence
    stick-table type ip size 200k expire 30m
    stick on src

# API servers backend
backend api_servers
    balance roundrobin
    option httpchk GET /api/health HTTP/1.1\r\nHost:\ api.example.com
    http-check expect rstring ^OK$
    
    # Enable HTTP/2 to backend
    server api1 192.168.1.20:3000 check proto h2 verify none
    server api2 192.168.1.21:3000 check proto h2 verify none
    server api3 192.168.1.22:3000 check proto h2 verify none

# Admin backend (restricted access)
backend admin_servers
    balance source
    option httpchk GET /admin/health
    http-check expect status 200
    
    # IP whitelist for admin access
    http-request deny unless { src 192.168.1.0/24 10.0.0.0/8 }
    
    server admin1 192.168.1.30:9000 check

# Static content servers
backend static_servers
    balance roundrobin
    option httpchk GET /health.txt
    http-check expect string "OK"
    
    # Cache control
    http-response set-header Cache-Control "public, max-age=86400"
    
    server static1 192.168.1.40:8080 check
    server static2 192.168.1.41:8080 check

# WebSocket servers
backend websocket_servers
    balance leastconn
    option httpchk GET /ws/health
    http-check expect status 101
    
    # WebSocket specific settings
    timeout tunnel 3600s
    
    server ws1 192.168.1.50:8080 check
    server ws2 192.168.1.51:8080 check

#---------------------------------------------------------------------
# Database Load Balancing (TCP Mode)
#---------------------------------------------------------------------

# MySQL Master-Slave Load Balancing
frontend mysql_frontend
    bind *:3306
    mode tcp
    default_backend mysql_servers

backend mysql_servers
    mode tcp
    balance leastconn
    option mysql-check user haproxy_check
    
    # MySQL health checks
    server mysql-master 192.168.1.60:3306 check weight 1000
    server mysql-slave1 192.168.1.61:3306 check weight 100 backup
    server mysql-slave2 192.168.1.62:3306 check weight 100 backup

# PostgreSQL Load Balancing
frontend postgresql_frontend
    bind *:5432
    mode tcp
    default_backend postgresql_servers

backend postgresql_servers
    mode tcp
    balance roundrobin
    option pgsql-check user haproxy_check
    
    server postgres1 192.168.1.70:5432 check
    server postgres2 192.168.1.71:5432 check

# Redis Cluster Load Balancing
frontend redis_frontend
    bind *:6379
    mode tcp
    default_backend redis_servers

backend redis_servers
    mode tcp
    balance first
    option redis-check
    
    server redis1 192.168.1.80:6379 check
    server redis2 192.168.1.81:6379 check backup

#---------------------------------------------------------------------
# Statistics and Monitoring
#---------------------------------------------------------------------

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if { src 192.168.1.0/24 }
    stats auth admin:secure_stats_password
    
    # Enhanced statistics
    stats show-legends
    stats show-modules
    stats realm "HAProxy Statistics"
    
    # Prometheus metrics (if compiled with USE_PROMEX)
    http-request use-service prometheus-exporter if { path /metrics }

#---------------------------------------------------------------------
# Advanced Features
#---------------------------------------------------------------------

# Global rate limiting
backend rate_limit_backend
    stick-table type ip size 100k expire 30s store gpc0,http_req_rate(10s)

# DDoS protection
frontend ddos_protection
    bind *:80
    
    # Track client IPs
    stick-table type ip size 100k expire 30s store gpc0,http_req_rate(10s),http_err_rate(10s)
    http-request track-sc0 src table rate_limit_backend
    
    # Block clients exceeding rate limits
    http-request deny if { sc_http_req_rate(0) gt 50 }
    http-request deny if { sc_http_err_rate(0) gt 10 }
    
    default_backend web_servers

# Health check backend for external monitoring
backend health_check
    mode http
    http-request return status 200 content-type text/plain string "HAProxy is healthy"
EOF

# Test configuration
sudo haproxy -c -f ~/haproxy/config/haproxy.cfg
```

## SSL/TLS Configuration and Security

### Advanced SSL Termination
```bash
# Generate strong DH parameters
sudo openssl dhparam -out /etc/haproxy/ssl/dhparam.pem 4096

# Create SSL certificate bundle
sudo mkdir -p /etc/haproxy/ssl

# Self-signed certificate for testing
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/haproxy/ssl/example.com.key \
  -out /etc/haproxy/ssl/example.com.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"

# Combine certificate and key for HAProxy
sudo cat /etc/haproxy/ssl/example.com.crt /etc/haproxy/ssl/example.com.key | sudo tee /etc/haproxy/ssl/example.com.pem

# Production: Let's Encrypt certificates
sudo certbot certonly --standalone -d example.com -d www.example.com
sudo cat /etc/letsencrypt/live/example.com/fullchain.pem /etc/letsencrypt/live/example.com/privkey.pem | sudo tee /etc/haproxy/ssl/example.com.pem

# Set proper permissions
sudo chmod 600 /etc/haproxy/ssl/*.pem
sudo chown haproxy:haproxy /etc/haproxy/ssl/*.pem

# Create certificate renewal script
sudo tee /usr/local/bin/haproxy-ssl-renewal.sh > /dev/null <<'EOF'
#!/bin/bash
CERT_PATH="/etc/letsencrypt/live"
HAPROXY_CERT_DIR="/etc/haproxy/ssl"

# Renew certificates
certbot renew --quiet --pre-hook "systemctl stop haproxy" --post-hook "systemctl start haproxy"

# Update HAProxy certificate bundles
for domain in $(ls ${CERT_PATH}/); do
    if [ -f "${CERT_PATH}/${domain}/fullchain.pem" ]; then
        cat "${CERT_PATH}/${domain}/fullchain.pem" "${CERT_PATH}/${domain}/privkey.pem" > "${HAPROXY_CERT_DIR}/${domain}.pem"
        chmod 600 "${HAPROXY_CERT_DIR}/${domain}.pem"
        chown haproxy:haproxy "${HAPROXY_CERT_DIR}/${domain}.pem"
    fi
done

# Reload HAProxy configuration
systemctl reload haproxy

echo "SSL certificates updated for HAProxy"
EOF

sudo chmod +x /usr/local/bin/haproxy-ssl-renewal.sh

# Schedule certificate renewal
echo "0 3 * * 1 root /usr/local/bin/haproxy-ssl-renewal.sh" | sudo tee -a /etc/crontab
```

### Security Hardening Configuration
```bash
# Create security-focused configuration additions
sudo tee /etc/haproxy/conf.d/security.cfg > /dev/null <<EOF
#---------------------------------------------------------------------
# Security Configuration
#---------------------------------------------------------------------

global
    # Security settings
    tune.ssl.default-dh-param 2048
    tune.ssl.capture-buffer-size 0
    tune.ssl.maxrecord 1460
    
    # Disable SSLv3 and weak ciphers
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    # Hide server information
    option hide-version
    
    # Security headers for all responses
    http-response del-header Server
    http-response del-header X-Powered-By
    
    # Request size limits
    http-request deny if { req.body_size gt 10000000 }  # 10MB limit
    
    # Block suspicious request methods
    acl blocked_methods method TRACE CONNECT
    http-request deny if blocked_methods
    
    # Block requests with suspicious headers
    acl suspicious_headers hdr_cnt(host) gt 1
    acl suspicious_headers hdr_cnt(content-length) gt 1
    http-request deny if suspicious_headers

# Rate limiting configuration
backend rate_limit_abuse
    stick-table type ip size 100k expire 30s store gpc0,gpc1,http_req_rate(10s),http_err_rate(10s),conn_rate(10s)

frontend rate_limiting
    # Track requests per IP
    http-request track-sc0 src table rate_limit_abuse
    
    # Deny clients that exceed rate limits
    http-request deny if { sc_http_req_rate(0) gt 100 }
    http-request deny if { sc_conn_rate(0) gt 20 }
    http-request deny if { sc_http_err_rate(0) gt 10 }
    
    # Slow down abusive clients
    http-request set-var(req.delay) int(1000) if { sc_http_req_rate(0) gt 50 }
    http-request lua.delay_request if { var(req.delay) -m found }

# WAF-like filtering
frontend security_frontend
    # Block common attacks
    acl is_sql_injection path_reg -i .*(union|select|insert|delete|update|drop|create|alter|exec|script|javascript|vbscript|onload|onerror|onclick).*
    acl is_xss path_reg -i .*(script|iframe|object|embed|form|img|svg|math|details|svg).*
    acl is_path_traversal path_reg -i .*(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\).*
    
    http-request deny if is_sql_injection
    http-request deny if is_xss
    http-request deny if is_path_traversal
    
    # GeoIP blocking (requires GeoIP data)
    # http-request deny if { src,map_ip(/etc/haproxy/geoip/country.map) -i CN RU }

EOF

# Include security configuration
echo "include /etc/haproxy/conf.d/*.cfg" | sudo tee -a /etc/haproxy/haproxy.cfg
```

## Advanced Load Balancing Strategies

### Multi-Tier Application Load Balancing
```bash
sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<EOF
global
    log stdout local0
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    log global
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 50s
    timeout server 50s

#---------------------------------------------------------------------
# Application Frontend with Advanced Routing
#---------------------------------------------------------------------

frontend app_frontend
    bind *:443 ssl crt /etc/haproxy/ssl/ alpn h2,http/1.1
    
    # ACLs for microservices routing
    acl is_user_service path_beg /api/users/
    acl is_order_service path_beg /api/orders/
    acl is_payment_service path_beg /api/payments/
    acl is_notification_service path_beg /api/notifications/
    acl is_admin_panel path_beg /admin/
    acl is_monitoring path_beg /monitoring/
    
    # Geographic routing
    acl is_us_traffic src 192.168.1.0/24
    acl is_eu_traffic src 192.168.2.0/24
    acl is_asia_traffic src 192.168.3.0/24
    
    # Device detection
    acl is_mobile hdr_reg(User-Agent) -i (mobile|android|iphone|ipad)
    acl is_desktop hdr_reg(User-Agent) -i (windows|macos|linux)
    
    # Routing decisions
    use_backend user_service_us if is_user_service is_us_traffic
    use_backend user_service_eu if is_user_service is_eu_traffic
    use_backend order_service if is_order_service
    use_backend payment_service if is_payment_service
    use_backend notification_service if is_notification_service
    use_backend admin_panel if is_admin_panel
    use_backend monitoring_backend if is_monitoring
    use_backend mobile_servers if is_mobile
    default_backend web_servers

# User Service Backends (Geographic)
backend user_service_us
    balance roundrobin
    option httpchk GET /api/users/health
    http-check expect status 200
    server user-us-1 192.168.1.100:3001 check
    server user-us-2 192.168.1.101:3001 check
    server user-us-3 192.168.1.102:3001 check

backend user_service_eu
    balance roundrobin
    option httpchk GET /api/users/health
    server user-eu-1 192.168.2.100:3001 check
    server user-eu-2 192.168.2.101:3001 check

# Microservices Backends
backend order_service
    balance leastconn
    option httpchk GET /api/orders/health
    server order-1 192.168.1.110:3002 check
    server order-2 192.168.1.111:3002 check
    server order-3 192.168.1.112:3002 check

backend payment_service
    balance roundrobin
    option httpchk GET /api/payments/health
    # Enhanced security for payment service
    http-request set-header X-Forwarded-Proto https
    http-request add-header X-Client-IP %[src]
    server payment-1 192.168.1.120:3003 check ssl verify none
    server payment-2 192.168.1.121:3003 check ssl verify none

backend notification_service
    balance roundrobin
    option httpchk GET /api/notifications/health
    server notification-1 192.168.1.130:3004 check
    server notification-2 192.168.1.131:3004 check

# Admin Panel Backend (Restricted)
backend admin_panel
    balance source
    option httpchk GET /admin/health
    http-check expect status 200
    
    # Additional security
    http-request add-header X-Admin-Access "true"
    timeout server 2m
    
    server admin-1 192.168.1.140:9000 check

# Mobile-Optimized Backend
backend mobile_servers
    balance roundrobin
    option httpchk GET /mobile/health
    # Mobile-specific optimizations
    compression algo gzip
    compression type text/html text/css application/javascript application/json
    server mobile-1 192.168.1.150:8080 check
    server mobile-2 192.168.1.151:8080 check

#---------------------------------------------------------------------
# Monitoring and Statistics
#---------------------------------------------------------------------

listen stats
    bind *:8404 ssl crt /etc/haproxy/ssl/stats.pem
    stats enable
    stats uri /
    stats refresh 5s
    stats admin if { src 192.168.1.0/24 }
    stats auth admin:secure_stats_password
    stats realm "HAProxy Statistics"
    
    # Prometheus metrics endpoint
    http-request use-service prometheus-exporter if { path /metrics }
    
    # JSON stats API
    http-request use-service prometheus-exporter if { path /stats/json }

# Health check endpoint for external monitoring
listen health_check
    bind *:8080
    mode http
    monitor-uri /health
    option httplog
    
    acl site_dead nbsrv(web_servers) lt 1
    acl api_dead nbsrv(api_servers) lt 1
    
    monitor fail if site_dead
    monitor fail if api_dead
EOF
```

### Global Load Balancing with DNS
```bash
# Integration with external DNS load balancing
sudo tee /etc/haproxy/haproxy-dns.cfg > /dev/null <<EOF
global
    # DNS resolution for dynamic backends
    dns-resolver dns1
        nameserver dns1 8.8.8.8:53
        nameserver dns2 8.8.4.4:53
        resolve_retries 3
        timeout retry 1s
        hold nx 30s
        hold other 30s
        hold refused 30s
        hold timeout 30s
        hold valid 10s

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# Dynamic backend resolution
backend dynamic_backend
    balance roundrobin
    option httpchk GET /health
    
    # Servers resolved via DNS
    server-template web- 3 web.example.com:80 check resolvers dns1
    server-template api- 2 api.example.com:80 check resolvers dns1

# Service discovery integration
backend consul_backend
    balance roundrobin
    option httpchk GET /health
    
    # Consul service discovery
    server-template consul- 3 _web._tcp.service.consul:80 check resolvers dns1
EOF
```

## High Availability and Clustering

### HAProxy Keepalived Setup
```bash
# Install keepalived for HA
sudo apt install -y keepalived  # Ubuntu/Debian
sudo yum install -y keepalived  # RHEL/CentOS

# Configure keepalived on primary HAProxy
sudo tee /etc/keepalived/keepalived.conf > /dev/null <<EOF
! Configuration File for keepalived

global_defs {
    router_id HAProxy_Primary
    vrrp_skip_check_adv_addr
    vrrp_strict
    vrrp_garp_interval 0
    vrrp_gna_interval 0
    script_user root
    enable_script_security
}

# Health check script
vrrp_script chk_haproxy {
    script "/usr/bin/killall -0 haproxy"
    interval 2
    weight 2
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 110
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass secure_vrrp_password
    }
    virtual_ipaddress {
        192.168.1.100/24
    }
    track_script {
        chk_haproxy
    }
    notify_master /etc/keepalived/master.sh
    notify_backup /etc/keepalived/backup.sh
}
EOF

# Create notification scripts
sudo tee /etc/keepalived/master.sh > /dev/null <<'EOF'
#!/bin/bash
echo "$(date): Became MASTER" >> /var/log/keepalived.log
# Add any additional master setup commands here
EOF

sudo tee /etc/keepalived/backup.sh > /dev/null <<'EOF'
#!/bin/bash
echo "$(date): Became BACKUP" >> /var/log/keepalived.log
# Add any additional backup setup commands here
EOF

sudo chmod +x /etc/keepalived/{master,backup}.sh
sudo systemctl enable --now keepalived

# Configure backup HAProxy with lower priority (100 instead of 110)
```

### Multi-Site Load Balancing
```bash
# Configure multi-site load balancing
sudo tee /etc/haproxy/haproxy-multisite.cfg > /dev/null <<EOF
global
    log stdout local0
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# Frontend for multi-site routing
frontend multisite_frontend
    bind *:443 ssl crt /etc/haproxy/ssl/ alpn h2,http/1.1
    
    # Site detection based on headers
    acl is_site_a hdr(host) -i site-a.example.com
    acl is_site_b hdr(host) -i site-b.example.com
    acl is_site_c hdr(host) -i site-c.example.com
    
    # Geographic routing based on source IP
    acl is_americas src 10.1.0.0/16
    acl is_europe src 10.2.0.0/16
    acl is_asia src 10.3.0.0/16
    
    # Route to appropriate backends
    use_backend site_a_americas if is_site_a is_americas
    use_backend site_a_europe if is_site_a is_europe
    use_backend site_a_asia if is_site_a is_asia
    use_backend site_b_backend if is_site_b
    use_backend site_c_backend if is_site_c
    
    default_backend default_site

# Regional backends
backend site_a_americas
    balance leastconn
    option httpchk GET /health
    server site-a-us-1 us-east-1.example.com:80 check
    server site-a-us-2 us-west-2.example.com:80 check

backend site_a_europe
    balance leastconn
    option httpchk GET /health
    server site-a-eu-1 eu-west-1.example.com:80 check
    server site-a-eu-2 eu-central-1.example.com:80 check

backend site_a_asia
    balance leastconn
    option httpchk GET /health
    server site-a-ap-1 ap-southeast-1.example.com:80 check
    server site-a-ap-2 ap-northeast-1.example.com:80 check
EOF
```

## Monitoring and Observability

### Prometheus Integration
```bash
# Configure HAProxy for Prometheus scraping
sudo tee -a /etc/haproxy/haproxy.cfg > /dev/null <<EOF

# Prometheus metrics endpoint
frontend prometheus_frontend
    bind *:8405
    http-request use-service prometheus-exporter if { path /metrics }
    http-request deny
EOF

# Create HAProxy exporter configuration
sudo tee /etc/systemd/system/haproxy-exporter.service > /dev/null <<EOF
[Unit]
Description=HAProxy Exporter for Prometheus
After=network.target

[Service]
Type=simple
User=haproxy
ExecStart=/usr/local/bin/haproxy_exporter \
    --haproxy.scrape-uri="http://admin:secure_stats_password@localhost:8404/stats;csv" \
    --web.listen-address="0.0.0.0:9101"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Download HAProxy exporter
HAPROXY_EXPORTER_VERSION="0.15.0"
wget https://github.com/prometheus/haproxy_exporter/releases/download/v${HAPROXY_EXPORTER_VERSION}/haproxy_exporter-${HAPROXY_EXPORTER_VERSION}.linux-amd64.tar.gz
tar xzf haproxy_exporter-${HAPROXY_EXPORTER_VERSION}.linux-amd64.tar.gz
sudo cp haproxy_exporter-${HAPROXY_EXPORTER_VERSION}.linux-amd64/haproxy_exporter /usr/local/bin/

sudo systemctl daemon-reload
sudo systemctl enable --now haproxy-exporter
```

### Comprehensive Logging
```bash
# Configure rsyslog for HAProxy
sudo tee /etc/rsyslog.d/49-haproxy.conf > /dev/null <<EOF
# HAProxy log configuration
\$ModLoad imudp
\$UDPServerRun 514
\$UDPServerAddress 127.0.0.1

# HAProxy logs
local0.*    /var/log/haproxy/haproxy.log
& stop

# Separate access and error logs
local0.info /var/log/haproxy/access.log
local0.err  /var/log/haproxy/error.log
local0.warning /var/log/haproxy/warning.log
EOF

# Create log directory
sudo mkdir -p /var/log/haproxy
sudo chown syslog:adm /var/log/haproxy

# Configure log rotation
sudo tee /etc/logrotate.d/haproxy > /dev/null <<EOF
/var/log/haproxy/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /bin/kill -HUP \`cat /var/run/rsyslogd.pid 2>/dev/null\` 2>/dev/null || true
    endscript
}
EOF

sudo systemctl restart rsyslog
sudo systemctl reload haproxy
```

## Performance Optimization

### System-Level Tuning
```bash
# Kernel optimization for HAProxy
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# HAProxy performance tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.ip_local_port_range = 15000 65000
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
fs.file-max = 100000
vm.swappiness = 1
EOF

sudo sysctl -p

# Set resource limits
sudo tee -a /etc/security/limits.conf > /dev/null <<EOF
haproxy soft nofile 65535
haproxy hard nofile 65535
haproxy soft nproc 65535
haproxy hard nproc 65535
EOF

# Optimize HAProxy service
sudo tee /etc/systemd/system/haproxy.service.d/performance.conf > /dev/null <<EOF
[Service]
LimitNOFILE=65535
LimitNPROC=65535
ExecStart=
ExecStart=/usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock
ExecReload=/usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg -c -q
ExecReload=/bin/kill -USR2 \$MAINPID
EOF

sudo systemctl daemon-reload
sudo systemctl restart haproxy
```

### Advanced Performance Configuration
```bash
sudo tee /etc/haproxy/performance.cfg > /dev/null <<EOF
global
    # Performance optimization
    maxconn 40000
    nbthread 8
    cpu-map auto:1/1-8 0-7
    
    # Memory optimization
    tune.maxrewrite 1024
    tune.bufsize 32768
    
    # Connection optimization
    tune.maxaccept 500
    tune.recv_enough 10000
    
    # SSL optimization
    tune.ssl.default-dh-param 2048
    tune.ssl.maxrecord 1460
    tune.ssl.capture-buffer-size 0
    
    # Compression
    tune.comp.maxlevel 6

defaults
    # Performance settings
    maxconn 8000
    
    # Timeouts
    timeout connect 3s
    timeout client 25s
    timeout server 25s
    timeout tunnel 3600s
    timeout http-keep-alive 1s
    timeout http-request 15s
    timeout queue 30s
    timeout tarpit 60s
    
    # Keep-alive optimization
    option http-keep-alive
    option prefer-last-server
    
    # Compression
    compression algo gzip
    compression type text/html text/css text/javascript application/javascript application/json application/xml

# High-performance backend configuration
backend high_performance_backend
    balance leastconn
    option httpchk GET /health
    http-check expect status 200
    
    # Connection pooling
    option http-reuse always
    
    # Server configuration with optimal settings
    default-server inter 1000 fastinter 500 downinter 2000 rise 2 fall 3 slowstart 30s maxconn 1000 maxqueue 256 weight 100
    
    server web1 192.168.1.10:8080 check
    server web2 192.168.1.11:8080 check
    server web3 192.168.1.12:8080 check
    server web4 192.168.1.13:8080 check
EOF
```

## Backup and Disaster Recovery

### 4. Configuration Management and Backup
```bash
sudo tee /usr/local/bin/haproxy-backup.sh > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/haproxy"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p ${BACKUP_DIR}/{config,ssl,stats,logs}

# Backup configuration files
tar -czf ${BACKUP_DIR}/config/haproxy-config-${DATE}.tar.gz \
    /etc/haproxy/ \
    /etc/systemd/system/haproxy.service* \
    /etc/keepalived/

# Backup SSL certificates
tar -czf ${BACKUP_DIR}/ssl/haproxy-ssl-${DATE}.tar.gz \
    /etc/haproxy/ssl/ \
    /etc/letsencrypt/

# Backup statistics and runtime state
echo "show stat" | socat stdio /run/haproxy/admin.sock > ${BACKUP_DIR}/stats/haproxy-stats-${DATE}.txt
echo "show info" | socat stdio /run/haproxy/admin.sock > ${BACKUP_DIR}/stats/haproxy-info-${DATE}.txt
echo "show sess" | socat stdio /run/haproxy/admin.sock > ${BACKUP_DIR}/stats/haproxy-sessions-${DATE}.txt

# Backup recent logs
find /var/log/haproxy -name "*.log" -mtime -1 -exec tar -czf ${BACKUP_DIR}/logs/haproxy-logs-${DATE}.tar.gz {} +

# Upload to cloud storage
aws s3 cp ${BACKUP_DIR}/ s3://haproxy-backups/ --recursive
az storage blob upload-batch --source ${BACKUP_DIR} --destination haproxy-backups
gsutil cp -r ${BACKUP_DIR}/* gs://haproxy-backups/

# Keep only last 15 backups
find ${BACKUP_DIR} -name "haproxy-*" -type f -mtime +15 -delete

# Test configuration validity
haproxy -c -f /etc/haproxy/haproxy.cfg

echo "HAProxy backup completed: ${DATE}"
EOF

sudo chmod +x /usr/local/bin/haproxy-backup.sh

# Schedule daily backups
echo "0 2 * * * root /usr/local/bin/haproxy-backup.sh" | sudo tee -a /etc/crontab
```

### Disaster Recovery Automation
```bash
sudo tee /usr/local/bin/haproxy-dr.sh > /dev/null <<'EOF'
#!/bin/bash
DR_MODE="${1:-test}"  # test, activate, or deactivate

case "$DR_MODE" in
    "test")
        echo "Testing DR procedures..."
        
        # Test backup restoration
        LATEST_BACKUP=$(ls -t /backup/haproxy/config/haproxy-config-*.tar.gz | head -1)
        if [ -n "$LATEST_BACKUP" ]; then
            echo "✓ Latest backup found: $LATEST_BACKUP"
        else
            echo "✗ No backup files found"
            exit 1
        fi
        
        # Test configuration
        haproxy -c -f /etc/haproxy/haproxy.cfg
        echo "✓ Configuration is valid"
        
        # Test backend connectivity
        for backend in $(echo "show stat" | socat stdio /run/haproxy/admin.sock | grep ",BACKEND," | cut -d, -f1); do
            echo "Testing backend: $backend"
            echo "show stat" | socat stdio /run/haproxy/admin.sock | grep "$backend"
        done
        
        echo "DR test completed"
        ;;
        
    "activate")
        echo "Activating DR procedures..."
        
        # Switch to DR configuration
        cp /etc/haproxy/haproxy-dr.cfg /etc/haproxy/haproxy.cfg
        
        # Reload HAProxy
        systemctl reload haproxy
        
        # Update DNS (example with Route53)
        aws route53 change-resource-record-sets --hosted-zone-id Z123456789 --change-batch file://dr-dns-update.json
        
        echo "DR activated"
        ;;
        
    "deactivate")
        echo "Deactivating DR procedures..."
        
        # Restore original configuration
        cp /etc/haproxy/haproxy.cfg.backup /etc/haproxy/haproxy.cfg
        
        # Reload HAProxy
        systemctl reload haproxy
        
        # Update DNS back to primary
        aws route53 change-resource-record-sets --hosted-zone-id Z123456789 --change-batch file://primary-dns-update.json
        
        echo "DR deactivated"
        ;;
        
    *)
        echo "Usage: $0 {test|activate|deactivate}"
        exit 1
        ;;
esac
EOF

sudo chmod +x /usr/local/bin/haproxy-dr.sh
```

## Verification and Health Checks

### Comprehensive Health Monitoring
```bash
sudo tee /usr/local/bin/haproxy-health-check.sh > /dev/null <<'EOF'
#!/bin/bash
HEALTH_LOG="/var/log/haproxy-health.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a ${HEALTH_LOG}
}

# Check HAProxy service status
if systemctl is-active haproxy >/dev/null 2>&1; then
    log_message "✓ HAProxy service is running"
else
    log_message "✗ HAProxy service is not running"
    exit 1
fi

# Check configuration validity
if haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
    log_message "✓ HAProxy configuration is valid"
else
    log_message "✗ HAProxy configuration has errors"
    haproxy -c -f /etc/haproxy/haproxy.cfg
fi

# Check listening ports
LISTENING_PORTS=$(netstat -tlnp | grep haproxy | wc -l)
log_message "✓ HAProxy is listening on ${LISTENING_PORTS} ports"

# Check backend server health
BACKEND_STATS=$(echo "show stat" | socat stdio /run/haproxy/admin.sock | grep -c ",UP,")
TOTAL_SERVERS=$(echo "show stat" | socat stdio /run/haproxy/admin.sock | grep -c ",.*,")
log_message "✓ ${BACKEND_STATS}/${TOTAL_SERVERS} backend servers are healthy"

# Check SSL certificate expiry
if [ -d /etc/haproxy/ssl ]; then
    for cert in /etc/haproxy/ssl/*.pem; do
        if [ -f "$cert" ]; then
            EXPIRY=$(openssl x509 -in "$cert" -noout -dates | grep notAfter | cut -d= -f2)
            EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
            CURRENT_EPOCH=$(date +%s)
            DAYS_TO_EXPIRY=$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
            
            if [ $DAYS_TO_EXPIRY -lt 30 ]; then
                log_message "⚠ SSL certificate $(basename $cert) expires in ${DAYS_TO_EXPIRY} days"
            else
                log_message "✓ SSL certificate $(basename $cert) expires in ${DAYS_TO_EXPIRY} days"
            fi
        fi
    done
fi

# Check memory usage
MEMORY_USAGE=$(ps -o pid,vsz,rss,comm -C haproxy | tail -1 | awk '{print $3/1024}')
log_message "ℹ HAProxy memory usage: ${MEMORY_USAGE}MB"

# Check connection statistics
CURRENT_CONNS=$(echo "show info" | socat stdio /run/haproxy/admin.sock | grep "CurrConns" | cut -d: -f2 | tr -d ' ')
MAX_CONNS=$(echo "show info" | socat stdio /run/haproxy/admin.sock | grep "MaxConn" | cut -d: -f2 | tr -d ' ')
log_message "ℹ Current connections: ${CURRENT_CONNS}/${MAX_CONNS}"

# Check for any backend servers that are down
DOWN_SERVERS=$(echo "show stat" | socat stdio /run/haproxy/admin.sock | grep ",DOWN," | wc -l)
if [ $DOWN_SERVERS -gt 0 ]; then
    log_message "⚠ ${DOWN_SERVERS} backend servers are down"
    echo "show stat" | socat stdio /run/haproxy/admin.sock | grep ",DOWN," | while IFS=, read pxname svname; do
        log_message "  - ${pxname}/${svname} is DOWN"
    done
fi

log_message "HAProxy health check completed"
EOF

sudo chmod +x /usr/local/bin/haproxy-health-check.sh

# Schedule health checks every 5 minutes
echo "*/5 * * * * root /usr/local/bin/haproxy-health-check.sh" | sudo tee -a /etc/crontab
```

### Load Testing and Performance Validation
```bash
sudo tee /usr/local/bin/haproxy-load-test.sh > /dev/null <<'EOF'
#!/bin/bash
TEST_RESULTS="/tmp/haproxy-load-test-$(date +%Y%m%d_%H%M%S).txt"
TEST_URL="https://example.com"
CONCURRENT_USERS=100
TEST_DURATION=60

echo "HAProxy Load Test Results" > ${TEST_RESULTS}
echo "========================" >> ${TEST_RESULTS}
echo "Date: $(date)" >> ${TEST_RESULTS}
echo "Target URL: ${TEST_URL}" >> ${TEST_RESULTS}
echo "Concurrent Users: ${CONCURRENT_USERS}" >> ${TEST_RESULTS}
echo "Test Duration: ${TEST_DURATION}s" >> ${TEST_RESULTS}
echo "" >> ${TEST_RESULTS}

# Install testing tools if not available
if ! command -v ab &> /dev/null; then
    apt-get update && apt-get install -y apache2-utils
fi

if ! command -v wrk &> /dev/null; then
    git clone https://github.com/wg/wrk.git /tmp/wrk
    cd /tmp/wrk && make && cp wrk /usr/local/bin/
fi

# Run Apache Bench test
echo "Apache Bench Results:" >> ${TEST_RESULTS}
ab -n 10000 -c ${CONCURRENT_USERS} -k ${TEST_URL}/ >> ${TEST_RESULTS} 2>&1

echo "" >> ${TEST_RESULTS}
echo "WRK Results:" >> ${TEST_RESULTS}
wrk -t4 -c${CONCURRENT_USERS} -d${TEST_DURATION}s --latency ${TEST_URL}/ >> ${TEST_RESULTS}

# Capture HAProxy stats during test
echo "" >> ${TEST_RESULTS}
echo "HAProxy Statistics During Test:" >> ${TEST_RESULTS}
echo "show info" | socat stdio /run/haproxy/admin.sock >> ${TEST_RESULTS}
echo "show stat" | socat stdio /run/haproxy/admin.sock >> ${TEST_RESULTS}

echo "" >> ${TEST_RESULTS}
echo "Load test completed at: $(date)" >> ${TEST_RESULTS}

echo "Load test completed. Results: ${TEST_RESULTS}"
EOF

sudo chmod +x /usr/local/bin/haproxy-load-test.sh
```

## Firewall Configuration (Cross-Platform)

### Security Rules
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS' 
sudo ufw allow from 192.168.1.0/24 to any port 8404 comment 'Stats interface - internal only'
sudo ufw allow from 192.168.1.0/24 to any port 9101 comment 'Prometheus exporter - internal only'
sudo ufw deny 8404 comment 'Block stats from public'
sudo ufw enable

# Firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --new-zone=haproxy-mgmt
sudo firewall-cmd --permanent --zone=haproxy-mgmt --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=haproxy-mgmt --add-port=8404/tcp
sudo firewall-cmd --permanent --zone=haproxy-mgmt --add-port=9101/tcp
sudo firewall-cmd --reload

# iptables (Universal)
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 8404 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 9101 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8404 -j DROP
sudo iptables -A INPUT -p tcp --dport 9101 -j DROP

# Save iptables rules
# Ubuntu/Debian
sudo apt install -y iptables-persistent
sudo netfilter-persistent save

# RHEL/CentOS
sudo service iptables save
```

### DDoS Protection Configuration
```bash
sudo tee /etc/haproxy/ddos-protection.cfg > /dev/null <<EOF
# DDoS Protection Configuration

global
    # Stick tables for tracking
    tune.stick-table.enable 1

frontend ddos_protection
    bind *:80
    bind *:443 ssl crt /etc/haproxy/ssl/
    
    # Track client behavior
    stick-table type ip size 1m expire 5m store gpc0,gpc1,http_req_rate(10s),http_err_rate(10s),conn_rate(10s),bytes_out_rate(10s)
    
    # Track requests
    http-request track-sc0 src
    
    # Rate limiting rules
    acl abuse_request_rate sc_http_req_rate(0) gt 100
    acl abuse_connection_rate sc_conn_rate(0) gt 20
    acl abuse_error_rate sc_http_err_rate(0) gt 10
    acl abuse_bandwidth sc_bytes_out_rate(0) gt 10000000  # 10MB/s
    
    # Geographic blocking (requires GeoIP)
    # acl blocked_countries src,map_ip(/etc/haproxy/geoip-country.map) -i CN RU
    
    # User-Agent filtering
    acl bad_user_agent hdr_sub(User-Agent) -i "sqlmap" "nikto" "nmap" "masscan" "zmap"
    acl empty_user_agent hdr_cnt(User-Agent) eq 0
    
    # HTTP method filtering
    acl allowed_methods method GET POST PUT DELETE HEAD OPTIONS PATCH
    
    # Deny rules
    http-request deny if abuse_request_rate
    http-request deny if abuse_connection_rate
    http-request deny if abuse_error_rate
    http-request deny if abuse_bandwidth
    http-request deny if bad_user_agent
    http-request deny if empty_user_agent
    http-request deny if !allowed_methods
    # http-request deny if blocked_countries
    
    # Tarpit suspicious clients
    http-request tarpit if { sc_http_req_rate(0) gt 50 }
    
    default_backend web_servers

# Clean backend
backend web_servers
    balance leastconn
    option httpchk GET /health
    
    server web1 192.168.1.10:8080 check
    server web2 192.168.1.11:8080 check
    server web3 192.168.1.12:8080 check
EOF
```

## Runtime Management and Monitoring

### Advanced Runtime Commands
```bash
# Create HAProxy management script
sudo tee /usr/local/bin/haproxy-manage.sh > /dev/null <<'EOF'
#!/bin/bash
HAPROXY_SOCKET="/run/haproxy/admin.sock"

case "$1" in
    "status")
        echo "=== HAProxy Status ==="
        echo "show info" | socat stdio ${HAPROXY_SOCKET}
        echo ""
        echo "=== Server Status ==="
        echo "show stat" | socat stdio ${HAPROXY_SOCKET} | column -t -s ","
        ;;
    
    "enable")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 enable <backend> <server>"
            exit 1
        fi
        echo "enable server $2/$3" | socat stdio ${HAPROXY_SOCKET}
        echo "Server $2/$3 enabled"
        ;;
    
    "disable")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 disable <backend> <server>"
            exit 1
        fi
        echo "disable server $2/$3" | socat stdio ${HAPROXY_SOCKET}
        echo "Server $2/$3 disabled"
        ;;
    
    "weight")
        if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
            echo "Usage: $0 weight <backend> <server> <weight>"
            exit 1
        fi
        echo "set weight $2/$3 $4" | socat stdio ${HAPROXY_SOCKET}
        echo "Weight for $2/$3 set to $4"
        ;;
    
    "sessions")
        echo "=== Active Sessions ==="
        echo "show sess" | socat stdio ${HAPROXY_SOCKET}
        ;;
    
    "errors")
        echo "=== Recent Errors ==="
        echo "show errors" | socat stdio ${HAPROXY_SOCKET}
        ;;
    
    "reload")
        echo "Reloading HAProxy configuration..."
        if haproxy -c -f /etc/haproxy/haproxy.cfg; then
            systemctl reload haproxy
            echo "Configuration reloaded successfully"
        else
            echo "Configuration has errors, reload aborted"
            exit 1
        fi
        ;;
    
    "drain")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 drain <backend> <server>"
            exit 1
        fi
        echo "set server $2/$3 state drain" | socat stdio ${HAPROXY_SOCKET}
        echo "Server $2/$3 is being drained"
        
        # Wait for connections to finish
        while [ $(echo "show stat" | socat stdio ${HAPROXY_SOCKET} | grep "$2,$3" | cut -d, -f5) -gt 0 ]; do
            echo "Waiting for connections to finish..."
            sleep 5
        done
        echo "Server $2/$3 has been drained"
        ;;
    
    *)
        echo "Usage: $0 {status|enable|disable|weight|sessions|errors|reload|drain} [options]"
        echo ""
        echo "Examples:"
        echo "  $0 status"
        echo "  $0 enable web_servers web1"
        echo "  $0 disable web_servers web1"
        echo "  $0 weight web_servers web1 50"
        echo "  $0 drain web_servers web1"
        echo "  $0 sessions"
        echo "  $0 errors"
        echo "  $0 reload"
        exit 1
        ;;
esac
EOF

sudo chmod +x /usr/local/bin/haproxy-manage.sh
```

### Automated Log Analysis
```bash
sudo tee /usr/local/bin/haproxy-log-analysis.sh > /dev/null <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/haproxy/haproxy.log"
ANALYSIS_DIR="/var/log/haproxy-analysis"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p ${ANALYSIS_DIR}

# Top client IPs
echo "Top Client IPs - ${DATE}" > ${ANALYSIS_DIR}/top-clients-${DATE}.txt
awk '{print $6}' ${LOG_FILE} | sort | uniq -c | sort -nr | head -20 >> ${ANALYSIS_DIR}/top-clients-${DATE}.txt

# Response time analysis
echo "Response Time Analysis - ${DATE}" > ${ANALYSIS_DIR}/response-times-${DATE}.txt
awk '{print $11}' ${LOG_FILE} | grep -v '^-$' | sort -n | tail -100 >> ${ANALYSIS_DIR}/response-times-${DATE}.txt

# Error analysis
echo "Error Analysis - ${DATE}" > ${ANALYSIS_DIR}/errors-${DATE}.txt
awk '$10 >= 400 {print $0}' ${LOG_FILE} | tail -100 >> ${ANALYSIS_DIR}/errors-${DATE}.txt

# Backend server analysis
echo "Backend Server Performance - ${DATE}" > ${ANALYSIS_DIR}/backend-performance-${DATE}.txt
awk '{print $8}' ${LOG_FILE} | sort | uniq -c | sort -nr >> ${ANALYSIS_DIR}/backend-performance-${DATE}.txt

# SSL/TLS analysis
echo "SSL/TLS Analysis - ${DATE}" > ${ANALYSIS_DIR}/ssl-analysis-${DATE}.txt
grep "SSL" ${LOG_FILE} | tail -50 >> ${ANALYSIS_DIR}/ssl-analysis-${DATE}.txt

# Generate summary report
cat > ${ANALYSIS_DIR}/summary-${DATE}.txt <<EOL
HAProxy Log Analysis Summary - ${DATE}
=====================================

Total Requests: $(wc -l < ${LOG_FILE})
Unique IPs: $(awk '{print $6}' ${LOG_FILE} | sort -u | wc -l)
4xx Errors: $(awk '$10 >= 400 && $10 < 500 {print $0}' ${LOG_FILE} | wc -l)
5xx Errors: $(awk '$10 >= 500 {print $0}' ${LOG_FILE} | wc -l)

Average Response Time: $(awk '{sum += $11; count++} END {print sum/count}' ${LOG_FILE})ms

Top 5 Requested URLs:
$(awk '{print $12}' ${LOG_FILE} | sort | uniq -c | sort -nr | head -5)

Analysis completed at: $(date)
EOL

echo "Log analysis completed. Reports in: ${ANALYSIS_DIR}/"
EOF

sudo chmod +x /usr/local/bin/haproxy-log-analysis.sh

# Schedule daily log analysis
echo "0 6 * * * root /usr/local/bin/haproxy-log-analysis.sh" | sudo tee -a /etc/crontab
```

## 6. Troubleshooting (Cross-Platform)

### Common Issues and Solutions
```bash
# Check HAProxy process status
ps aux | grep haproxy
systemctl status haproxy

# Configuration validation
haproxy -c -f /etc/haproxy/haproxy.cfg
haproxy -c -V -f /etc/haproxy/haproxy.cfg

# Socket connectivity test
socat - /run/haproxy/admin.sock
echo "show info" | socat stdio /run/haproxy/admin.sock

# Backend server connectivity test
for server in 192.168.1.10 192.168.1.11 192.168.1.12; do
    echo "Testing $server..."
    nc -zv $server 8080
    curl -I http://$server:8080/health
done

# SSL certificate issues
openssl x509 -in /etc/haproxy/ssl/example.com.pem -text -noout
openssl verify -CAfile /etc/haproxy/ssl/ca.crt /etc/haproxy/ssl/example.com.pem

# Memory usage debugging
pmap -x $(pgrep haproxy)
cat /proc/$(pgrep haproxy)/status | grep -E "(VmSize|VmRSS|VmData|VmStk)"

# Network debugging
ss -tulpn | grep haproxy
netstat -tulpn | grep haproxy
lsof -i :80,443,8404

# Log debugging
tail -f /var/log/haproxy/haproxy.log
journalctl -u haproxy -f

# Performance debugging
echo "show stat" | socat stdio /run/haproxy/admin.sock | grep -v "^#"
echo "show sess" | socat stdio /run/haproxy/admin.sock
echo "show pools" | socat stdio /run/haproxy/admin.sock

# Configuration debugging
haproxy -vv
haproxy -dM -f /etc/haproxy/haproxy.cfg  # Don't use in production

# Check for core dumps
find /var/crash -name "haproxy*" 2>/dev/null
find /var/lib/systemd/coredump -name "*haproxy*" 2>/dev/null
```

### Advanced Debugging
```bash
# Enable debug logging
sudo systemctl edit haproxy.service
# Add:
[Service]
ExecStart=
ExecStart=/usr/sbin/haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock -d

sudo systemctl daemon-reload
sudo systemctl restart haproxy

# Real-time connection monitoring
watch -n 1 'echo "show stat" | socat stdio /run/haproxy/admin.sock | grep -E "FRONTEND|BACKEND" | column -t -s ","'

# TCP dump for network analysis
tcpdump -i any -w haproxy-traffic.pcap port 80 or port 443
tcpdump -i any -w backend-traffic.pcap host 192.168.1.10

# Strace HAProxy process
strace -p $(pgrep haproxy) -e trace=network

# Monitor file descriptors
lsof -p $(pgrep haproxy) | wc -l
cat /proc/$(pgrep haproxy)/limits | grep "Max open files"

# Check shared memory segments
ipcs -m | grep haproxy

# Monitor syscalls
perf trace -p $(pgrep haproxy)
```

## Additional Resources

- [Official Documentation](https://docs.haproxy.org/)
- [HAProxy Configuration Manual](https://cbonte.github.io/haproxy-dconv/)
- [Best Practices Guide](https://www.haproxy.com/documentation/hapee/latest/configuration/best-practices/)
- [Performance Tuning Guide](https://www.haproxy.com/blog/haproxy-performance-tuning/)
- [Security Guide](https://www.haproxy.com/solutions/security/)
- [Community Forum](https://discourse.haproxy.org/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection.