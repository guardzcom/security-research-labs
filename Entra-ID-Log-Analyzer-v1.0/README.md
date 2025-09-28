# Entra ID Log Analyzer

An advanced open-source security analytics platform for Azure Active Directory (Entra ID) authentication logs. Built with AI-powered threat detection and behavioral analytics to help security teams identify suspicious activities, unusual patterns, and potential security risks.

![Entra ID Log Analyzer](https://img.shields.io/badge/Security-Analytics-green)
![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)
![React](https://img.shields.io/badge/React-19.0-blue)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)

## Features

### Advanced Log Analysis
- **AI-Powered Threat Detection**: Intelligent analysis of authentication patterns and anomalies
- **Real-time Risk Assessment**: Dynamic scoring based on user behavior, locations, devices, and applications
- **Interactive Visualizations**: Comprehensive charts and graphs for threat distribution, authentication timelines, and geographic analysis

### Security Intelligence
- **Behavioral Analytics**: User behavior profiling with geo-clustering and risk analysis
- **Threat Correlations**: Advanced correlation analysis to identify connected security events
- **Infrastructure Monitoring**: Detailed insights into authentication infrastructure and patterns

### Comprehensive Reporting
- **Clickable Dashboards**: Interactive elements provide detailed drill-down capabilities
- **Recent Activity Tracking**: Grouped user activities with detailed event logs
- **Geographic Distribution**: Visual mapping of authentication sources and risk indicators

### User Experience
- **Drag & Drop Upload**: Simple log file upload with support for multiple formats
- **Responsive Design**: Modern, mobile-friendly interface
- **Export Capabilities**: Generate reports and export analysis results

## Quick Start

### Prerequisites
- Node.js 18+ 
- npm or yarn package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/entra-id-log-analyzer.git
   cd entra-id-log-analyzer
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm run dev
   ```

4. **Open your browser**
   Navigate to `http://localhost:5173` to start using the application.

### Production Build

```bash
npm run build
npm run preview
```

## Usage Guide

### 1. Log Upload
- Drag and drop your Entra ID authentication log files
- Supported formats: JSON, CSV, TXT
- The system will automatically parse and analyze the logs

### 2. Analysis Dashboard
Once analysis is complete, explore:
- **Overview Tab**: High-level metrics and visualizations
- **Threat Correlations**: Advanced correlation analysis
- **Behavioral Analysis**: User behavior patterns and risk assessment
- **Detailed Logs**: Raw log data with filtering capabilities

### 3. Interactive Elements
- Click on any chart element for detailed information
- Explore threat distributions, authentication timelines, and geographic data
- View user-specific behavior analysis and risk indicators

## Configuration

### Environment Setup
The application works out of the box with default settings. For custom configurations:

1. **Modify theme colors** in `src/index.css`
2. **Adjust analysis parameters** in component files
3. **Configure API endpoints** if using external threat intelligence

### Customization
- **Color Scheme**: Edit CSS variables in `src/index.css`
- **Component Styling**: Modify Tailwind classes throughout the application
- **Analysis Logic**: Update threat detection algorithms in analysis components

## Technology Stack

- **Frontend**: React 19, TypeScript
- **Styling**: Tailwind CSS 4, Radix UI Components
- **Charts**: Recharts, D3.js
- **Icons**: Phosphor Icons
- **Animations**: Framer Motion
- **Build Tool**: Vite
- **Package Manager**: npm

## Project Structure

```
entra-id-log-analyzer/
├── src/
│   ├── components/          # React components
│   │   ├── ui/             # Shadcn UI components
│   │   ├── LogUpload.tsx   # File upload component
│   │   ├── ThreatSummary.tsx
│   │   ├── AnalysisCharts.tsx
│   │   └── ...
│   ├── types/              # TypeScript type definitions
│   ├── lib/                # Utility functions
│   ├── hooks/              # Custom React hooks
│   └── styles/             # CSS styles
├── public/                 # Static assets
├── package.json
├── tailwind.config.js
├── tsconfig.json
└── vite.config.ts
```

## Contributing

We welcome contributions from the community! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Bug Reports
Please use the [GitHub Issues](https://github.com/your-username/entra-id-log-analyzer/issues) page to report bugs or request features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## Support

- **Documentation**: Check the [Wiki](https://github.com/your-username/entra-id-log-analyzer/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-username/entra-id-log-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/entra-id-log-analyzer/discussions)

---

**Made with 💚 by Guardz**

*Empowering security teams with intelligent log analysis and threat detection.*
