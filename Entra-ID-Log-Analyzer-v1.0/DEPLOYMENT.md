# Deployment Guide

This guide covers various deployment options for the Entra ID Log Analyzer.

## GitHub Pages

1. **Enable GitHub Pages** in repository settings
2. **Add deployment workflow** (create `.github/workflows/deploy.yml`):

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Build
      run: npm run build
    
    - name: Deploy to GitHub Pages
      uses: peaceiris/actions-gh-pages@v3
      if: github.ref == 'refs/heads/main'
      with:
        github_token: ${{ secrets.GITHUB_TOKEN }}
        publish_dir: ./dist
```

## 🖥️ Self-Hosted Deployment

### Docker Deployment

1. **Create Dockerfile**:

```dockerfile
# Build stage
FROM node:18-alpine as build

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

2. **Create nginx.conf**:

```nginx
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server {
        listen 80;
        server_name localhost;

        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
            try_files $uri $uri/ /index.html;
        }

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Referrer-Policy strict-origin-when-cross-origin;
    }
}
```

3. **Build and run**:

```bash
# Build the image
docker build -t entra-id-analyzer .

# Run the container
docker run -p 80:80 entra-id-analyzer
```

### Traditional Web Server

1. **Build the application**:
```bash
npm install
npm run build
```

2. **Deploy the `dist` folder** to your web server
3. **Configure server** to serve `index.html` for all routes

#### Apache (.htaccess)
```apache
Options -MultiViews
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^ index.html [QSA,L]
```

#### Nginx
```nginx
location / {
    try_files $uri $uri/ /index.html;
}
```

## ☁️ Cloud Platform Deployment

### AWS S3 + CloudFront

1. **Build the application**:
```bash
npm run build
```

2. **Create S3 bucket** with static website hosting
3. **Upload `dist` folder** contents to S3
4. **Configure CloudFront** distribution
5. **Set up custom domain** (optional)

### Azure Static Web Apps

1. **Fork the repository**
2. **Create Static Web App** in Azure Portal
3. **Connect to GitHub** repository
4. **Configure build**:
   - App location: `/`
   - Build location: `dist`
   - Build command: `npm run build`

### Google Cloud Storage

1. **Build the application**
2. **Create Cloud Storage bucket**
3. **Upload files** and configure for static hosting
4. **Set up Cloud CDN** (optional)

## 🔧 Environment Configuration

### Build Configuration

The application supports build-time configuration through environment variables:

```bash
# Example .env file
VITE_APP_TITLE="Custom Entra ID Analyzer"
VITE_APP_VERSION="1.0.0"
```

### Runtime Configuration

For runtime configuration, modify the appropriate files:

- **Theme**: Edit `src/index.css`
- **Branding**: Update `index.html` and component files
- **Features**: Configure in component files

## 📱 PWA Deployment

To enable Progressive Web App features:

1. **Add service worker** configuration
2. **Configure manifest.json**
3. **Enable offline capabilities**

## 🔒 Security Considerations

### Production Checklist

- [ ] Enable HTTPS
- [ ] Configure security headers
- [ ] Set up proper CORS policies
- [ ] Enable gzip compression
- [ ] Configure caching headers
- [ ] Remove development dependencies
- [ ] Validate all environment variables

### Security Headers

```nginx
# Nginx example
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; img-src 'self' data:;" always;
```

## 🚨 Troubleshooting

### Common Issues

1. **Build fails**: Check Node.js version (requires 18+)
2. **Routing issues**: Ensure server redirects all routes to `index.html`
3. **Asset loading**: Verify base URL configuration for subdirectory deployment
4. **CORS errors**: Configure proper CORS headers if using API

### Performance Optimization

- Enable gzip/brotli compression
- Configure proper cache headers
- Use CDN for static assets
- Enable HTTP/2
- Optimize images and assets

## 📞 Support

For deployment issues:
- Check [GitHub Issues](https://github.com/your-username/entra-id-log-analyzer/issues)
- Review [Troubleshooting Guide](https://github.com/your-username/entra-id-log-analyzer/wiki/Troubleshooting)
- Contact support: support@guardz.com
