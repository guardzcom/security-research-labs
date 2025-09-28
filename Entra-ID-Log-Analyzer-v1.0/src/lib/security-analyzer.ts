import type { 
  LogEntry, 
  AnalysisResults, 
  UserProfile, 
  ThreatIndicator,
  ImpossibleTravel,
  BehavioralCluster,
  CorrelationData,
  RiskAssessment,
  UserRiskProfile,
  GeoCluster
} from '@/types/security'

export async function analyzeSecurityLogs(logs: LogEntry[]): Promise<AnalysisResults> {
  const startTime = Date.now()
  
  // Simulate processing time for demo
  await new Promise(resolve => setTimeout(resolve, 2000))
  
  // Build user profiles
  const userProfiles = buildUserProfiles(logs)
  
  // Perform threat analysis
  const threats = detectThreats(logs, userProfiles)
  
  // Perform correlation analysis
  const correlations = performCorrelationAnalysis(logs, userProfiles)
  
  // Calculate risk assessment
  const riskAssessment = calculateRiskAssessment(threats, correlations)
  
  // Build summary statistics
  const summary = buildSummaryStats(logs, userProfiles)
  
  // Generate user risk profiles
  const userRiskProfiles = generateUserRiskProfiles(userProfiles, correlations, threats)
  
  // Generate geo clusters
  const geoClusters = generateGeoClusters(logs, userProfiles)
  
  // Generate behavioral analysis
  const behavioralAnalysis = generateBehavioralAnalysis(userProfiles, correlations)
  
  const processingTime = Date.now() - startTime

  return {
    timestamp: new Date().toISOString(),
    summary,
    threats,
    correlations,
    userProfiles: Object.fromEntries(
      Object.entries(userProfiles).map(([user, profile]) => [
        user,
        {
          ...profile,
          ipAddresses: new Set(profile.ipAddresses),
          locations: new Set(profile.locations),
          countries: new Set(profile.countries),
          devices: new Set(profile.devices),
          browsers: new Set(profile.browsers),
          applications: new Set(profile.applications),
          hours: new Set(profile.hours)
        }
      ])
    ),
    riskAssessment,
    userRiskProfiles,
    geoClusters,
    behavioralAnalysis,
    rawLogs: logs,
    processingStats: {
      totalProcessingTime: processingTime,
      parsedEntries: logs.length,
      skippedEntries: 0,
      errorCount: 0,
      warnings: []
    }
  }
}

function buildUserProfiles(logs: LogEntry[]): Record<string, UserProfile> {
  const profiles: Record<string, UserProfile> = {}
  
  logs.forEach(log => {
    const user = log.userPrincipalName || log.userId || 'Unknown'
    const timestamp = new Date(log.time || log.createdDateTime || log.timestamp || Date.now())
    const isSuccess = log.status?.errorCode === 0 || log.status?.errorCode === '0'
    
    if (!profiles[user]) {
      profiles[user] = {
        user,
        events: [],
        ipAddresses: new Set(),
        locations: new Set(),
        countries: new Set(),
        devices: new Set(),
        browsers: new Set(),
        applications: new Set(),
        hours: new Set(),
        userAgents: new Set(),
        operationTypes: new Set(),
        userType: log.userType || 'Unknown',
        userRoles: new Set(),
        privilegeLevel: 'Standard',
        firstSeen: timestamp,
        lastSeen: timestamp,
        totalEvents: 0,
        successfulEvents: 0,
        failedEvents: 0,
        successRate: 0
      }
    }
    
    const profile = profiles[user]
    profile.events.push(log)
    profile.totalEvents++
    
    if (isSuccess) {
      profile.successfulEvents++
    } else {
      profile.failedEvents++
    }
    
    profile.successRate = profile.successfulEvents / profile.totalEvents
    
    if (log.ipAddress) profile.ipAddresses.add(log.ipAddress)
    if (log.location?.city) profile.locations.add(`${log.location.city}, ${log.location.countryOrRegion}`)
    if (log.location?.countryOrRegion) profile.countries.add(log.location.countryOrRegion)
    if (log.deviceDetail?.operatingSystem) profile.devices.add(log.deviceDetail.operatingSystem)
    if (log.deviceDetail?.browser) profile.browsers.add(log.deviceDetail.browser)
    if (log.appDisplayName) profile.applications.add(log.appDisplayName)
    if (log.userAgent) profile.userAgents.add(log.userAgent)
    if (log.operationType) profile.operationTypes.add(log.operationType)
    if (log.userRoles) log.userRoles.forEach(role => profile.userRoles.add(role))
    
    // Update privilege level based on roles and applications
    if (log.userRoles?.some(role => role.includes('Global') || role.includes('Company Administrator'))) {
      profile.privilegeLevel = 'GlobalAdmin'
    } else if (log.userRoles?.some(role => role.includes('Admin')) || 
               Array.from(profile.applications).some(app => 
                 app.includes('PowerShell') || app.includes('Graph') || app.includes('Admin Portal')
               )) {
      profile.privilegeLevel = 'Admin'
    } else if (profile.userRoles.size > 0) {
      profile.privilegeLevel = 'Elevated'
    }
    
    profile.hours.add(timestamp.getHours())
    
    if (timestamp < profile.firstSeen) profile.firstSeen = timestamp
    if (timestamp > profile.lastSeen) profile.lastSeen = timestamp
  })
  
  return profiles
}

function detectThreats(logs: LogEntry[], userProfiles: Record<string, UserProfile>): ThreatIndicator[] {
  const threats: ThreatIndicator[] = []
  
  // Detect brute force attacks
  Object.entries(userProfiles).forEach(([user, profile]) => {
    if (profile.failedEvents > 10 && profile.successRate < 0.3) {
      threats.push({
        type: 'Brute Force Attack',
        user,
        description: `${profile.failedEvents} failed login attempts with ${(profile.successRate * 100).toFixed(1)}% success rate`,
        severity: profile.failedEvents > 50 ? 'critical' : 'high',
        confidence: 0.85
      })
    }
  })
  
  // Detect impossible travel
  const impossibleTravel = detectImpossibleTravel(logs, userProfiles)
  impossibleTravel.forEach(travel => {
    threats.push({
      type: 'Impossible Travel',
      user: travel.user,
      description: `Travel from ${travel.fromLocation} to ${travel.toLocation} (${travel.distance}km in ${travel.timeWindow}h)`,
      severity: travel.riskLevel,
      confidence: 0.9,
      details: travel
    })
  })
  
  // Detect suspicious IP patterns
  Object.entries(userProfiles).forEach(([user, profile]) => {
    if (profile.ipAddresses.size > 5) {
      const hasPublicIPs = Array.from(profile.ipAddresses).some(ip => 
        !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.16.')
      )
      
      if (hasPublicIPs && profile.ipAddresses.size > 8) {
        threats.push({
          type: 'Suspicious IP Pattern',
          user,
          description: `User accessed from ${profile.ipAddresses.size} different IP addresses including public IPs`,
          severity: 'medium',
          confidence: 0.7
        })
      }
    }
  })
  
  // Detect privilege escalation attempts
  logs.forEach(log => {
    const appName = (log.appDisplayName || '').toLowerCase()
    const isPrivileged = appName.includes('admin') || appName.includes('portal') || appName.includes('management')
    const isFailure = log.status?.errorCode !== 0 && log.status?.errorCode !== '0'
    
    if (isPrivileged && isFailure) {
      threats.push({
        type: 'Privilege Escalation Attempt',
        user: log.userPrincipalName || log.userId || 'Unknown',
        description: `Failed access attempt to privileged application: ${log.appDisplayName}`,
        severity: 'high',
        confidence: 0.8,
        timestamp: log.time || log.createdDateTime || log.timestamp
      })
    }
  })
  
  return threats
}

function detectImpossibleTravel(logs: LogEntry[], userProfiles: Record<string, UserProfile>): ImpossibleTravel[] {
  const impossibleTravel: ImpossibleTravel[] = []
  
  // Simplified distance calculation between major cities
  const cityDistances: Record<string, Record<string, number>> = {
    'New York': { 'London': 5585, 'Moscow': 7510, 'Tokyo': 10838, 'Sydney': 15993 },
    'London': { 'New York': 5585, 'Moscow': 2500, 'Tokyo': 9650, 'Sydney': 17000 },
    'Moscow': { 'New York': 7510, 'London': 2500, 'Tokyo': 7500, 'Sydney': 14000 },
    'Tokyo': { 'New York': 10838, 'London': 9650, 'Moscow': 7500, 'Sydney': 7800 },
    'Sydney': { 'New York': 15993, 'London': 17000, 'Moscow': 14000, 'Tokyo': 7800 }
  }
  
  Object.entries(userProfiles).forEach(([user, profile]) => {
    const locationEvents = profile.events
      .filter(log => log.location?.city && log.time)
      .map(log => ({
        timestamp: new Date(log.time || log.createdDateTime || log.timestamp || Date.now()),
        city: log.location!.city!,
        country: log.location!.countryOrRegion || 'Unknown',
        log
      }))
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime())
    
    for (let i = 1; i < locationEvents.length; i++) {
      const prev = locationEvents[i - 1]
      const curr = locationEvents[i]
      
      if (prev.city !== curr.city) {
        const distance = cityDistances[prev.city]?.[curr.city] || 1000 // Default 1000km
        const timeWindow = (curr.timestamp.getTime() - prev.timestamp.getTime()) / (1000 * 60 * 60) // hours
        const velocity = distance / timeWindow
        
        // Impossible if faster than commercial flight (900 km/h) and significant distance
        if (velocity > 900 && distance > 500) {
          impossibleTravel.push({
            user,
            fromLocation: prev.city,
            toLocation: curr.city,
            fromCountry: prev.country,
            toCountry: curr.country,
            distance,
            timeWindow,
            velocity: Math.round(velocity),
            riskLevel: velocity > 2000 ? 'critical' : 'high',
            events: [prev.log, curr.log]
          })
        }
      }
    }
  })
  
  return impossibleTravel
}

function performCorrelationAnalysis(logs: LogEntry[], userProfiles: Record<string, UserProfile>): CorrelationData {
  // Temporal Analysis
  const rapidSequences: any[] = []
  const failedToSuccessPatterns: any[] = []
  const bruteForceAttempts: any[] = []
  
  Object.entries(userProfiles).forEach(([user, profile]) => {
    const sortedEvents = profile.events.sort((a, b) => 
      new Date(a.time || a.createdDateTime || a.timestamp || 0).getTime() - 
      new Date(b.time || b.createdDateTime || b.timestamp || 0).getTime()
    )
    
    for (let i = 1; i < sortedEvents.length; i++) {
      const prev = sortedEvents[i - 1]
      const curr = sortedEvents[i]
      const prevTime = new Date(prev.time || prev.createdDateTime || prev.timestamp || 0)
      const currTime = new Date(curr.time || curr.createdDateTime || curr.timestamp || 0)
      const timeDiff = (currTime.getTime() - prevTime.getTime()) / 1000 // seconds
      
      // Detect rapid sequences (< 5 seconds)
      if (timeDiff < 5 && timeDiff > 0) {
        rapidSequences.push({
          user,
          events: [prev, curr],
          interval: timeDiff,
          riskLevel: timeDiff < 1 ? 'critical' : timeDiff < 2 ? 'high' : 'medium'
        })
      }
      
      // Detect failed-to-success patterns
      const prevFailed = prev.status?.errorCode !== 0 && prev.status?.errorCode !== '0'
      const currSuccess = curr.status?.errorCode === 0 || curr.status?.errorCode === '0'
      
      if (prevFailed && currSuccess && timeDiff < 30) {
        failedToSuccessPatterns.push({
          user,
          failedEvent: prev,
          successEvent: curr,
          interval: timeDiff
        })
      }
    }
    
    // Detect brute force patterns
    if (profile.failedEvents > 5) {
      const uniqueIPs = new Set(
        profile.events
          .filter(e => e.status?.errorCode !== 0 && e.status?.errorCode !== '0')
          .map(e => e.ipAddress)
          .filter(Boolean)
      ).size
      
      if (profile.failedEvents > 10) {
        bruteForceAttempts.push({
          user,
          attempts: profile.failedEvents,
          timespan: (profile.lastSeen.getTime() - profile.firstSeen.getTime()) / (1000 * 60 * 60), // hours
          uniqueIPs
        })
      }
    }
  })
  
  // Geographic Analysis
  const impossibleTravel = detectImpossibleTravel(logs, userProfiles)
  const velocityAnomalies: any[] = []
  const countryTransitions: Record<string, number> = {}
  
  // Infrastructure Analysis
  const sharedIPs: Record<string, any> = {}
  const deviceFingerprints: Record<string, any> = {}
  const proxyIndicators: any[] = []
  const deviceTypes: Record<string, any> = {}
  const browserTypes: Record<string, any> = {}
  const operatingSystems: Record<string, any> = {}
  
  // Analyze shared IPs
  const ipUserMap: Record<string, Set<string>> = {}
  logs.forEach(log => {
    if (log.ipAddress) {
      if (!ipUserMap[log.ipAddress]) {
        ipUserMap[log.ipAddress] = new Set()
      }
      ipUserMap[log.ipAddress].add(log.userPrincipalName || log.userId || 'Unknown')
    }
  })
  
  Object.entries(ipUserMap).forEach(([ip, users]) => {
    if (users.size > 1) {
      const isPrivate = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.')
      sharedIPs[ip] = {
        users: Array.from(users),
        count: users.size,
        isPrivate,
        riskLevel: users.size > 5 ? 'high' : users.size > 2 ? 'medium' : 'low',
        suspiciousActivity: !isPrivate && users.size > 3
      }
    }
  })

  // Analyze device types, browsers, and operating systems
  const deviceTypeMap: Record<string, Set<string>> = {}
  const browserTypeMap: Record<string, Set<string>> = {}
  const osTypeMap: Record<string, Set<string>> = {}

  logs.forEach(log => {
    const user = log.userPrincipalName || log.userId || 'Unknown'
    
    // Extract device type from deviceDetail or userAgent
    let deviceType = 'Unknown'
    if (log.deviceDetail?.displayName) {
      if (log.deviceDetail.displayName.toLowerCase().includes('mobile') || 
          log.deviceDetail.displayName.toLowerCase().includes('phone')) {
        deviceType = 'Mobile'
      } else if (log.deviceDetail.displayName.toLowerCase().includes('tablet')) {
        deviceType = 'Tablet'
      } else {
        deviceType = 'Desktop'
      }
    } else if (log.userAgent) {
      const ua = log.userAgent.toLowerCase()
      if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
        deviceType = 'Mobile'
      } else if (ua.includes('tablet') || ua.includes('ipad')) {
        deviceType = 'Tablet'
      } else {
        deviceType = 'Desktop'
      }
    }

    // Extract browser from deviceDetail or userAgent
    let browser = log.deviceDetail?.browser || 'Unknown'
    if (!browser || browser === 'Unknown') {
      if (log.userAgent) {
        const ua = log.userAgent.toLowerCase()
        if (ua.includes('chrome')) browser = 'Chrome'
        else if (ua.includes('firefox')) browser = 'Firefox'
        else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari'
        else if (ua.includes('edge')) browser = 'Edge'
        else if (ua.includes('opera')) browser = 'Opera'
        else browser = 'Other'
      }
    }

    // Extract OS from deviceDetail or userAgent
    let os = log.deviceDetail?.operatingSystem || 'Unknown'
    if (!os || os === 'Unknown') {
      if (log.userAgent) {
        const ua = log.userAgent.toLowerCase()
        if (ua.includes('windows')) os = 'Windows'
        else if (ua.includes('mac os')) os = 'macOS'
        else if (ua.includes('linux')) os = 'Linux'
        else if (ua.includes('android')) os = 'Android'
        else if (ua.includes('ios') || ua.includes('iphone') || ua.includes('ipad')) os = 'iOS'
        else os = 'Other'
      }
    }

    // Track users per device type
    if (!deviceTypeMap[deviceType]) deviceTypeMap[deviceType] = new Set()
    deviceTypeMap[deviceType].add(user)

    // Track users per browser
    if (!browserTypeMap[browser]) browserTypeMap[browser] = new Set()
    browserTypeMap[browser].add(user)

    // Track users per OS
    if (!osTypeMap[os]) osTypeMap[os] = new Set()
    osTypeMap[os].add(user)
  })

  // Build device types analysis
  Object.entries(deviceTypeMap).forEach(([type, users]) => {
    deviceTypes[type] = {
      count: users.size,
      users: Array.from(users),
      suspicious: false, // Could add logic to detect suspicious device patterns
      riskLevel: 'low'
    }
  })

  // Build browser types analysis
  Object.entries(browserTypeMap).forEach(([browser, users]) => {
    const isSuspiciousBrowser = browser === 'Other' || browser === 'Unknown'
    browserTypes[browser] = {
      count: users.size,
      users: Array.from(users),
      suspicious: isSuspiciousBrowser,
      riskLevel: isSuspiciousBrowser ? 'medium' : 'low'
    }
  })

  // Build OS analysis
  Object.entries(osTypeMap).forEach(([os, users]) => {
    const isOutdated = os.includes('XP') || os.includes('Vista') || os.includes('7') // Simple outdated detection
    operatingSystems[os] = {
      count: users.size,
      users: Array.from(users),
      outdated: isOutdated,
      riskLevel: isOutdated ? 'high' : 'low'
    }
  })
  
  // Behavioral Analysis - simplified clustering
  const clusters: BehavioralCluster[] = []
  const anomalies: any[] = []
  const privilegeEscalation: any[] = []
  
  // Simple clustering based on failure rates and IP diversity
  const behaviorGroups: Record<string, string[]> = {
    'high-risk': [],
    'medium-risk': [],
    'low-risk': []
  }
  
  Object.entries(userProfiles).forEach(([user, profile]) => {
    const riskScore = calculateUserRiskScore(profile)
    
    if (riskScore > 70) {
      behaviorGroups['high-risk'].push(user)
    } else if (riskScore > 40) {
      behaviorGroups['medium-risk'].push(user)
    } else {
      behaviorGroups['low-risk'].push(user)
    }
    
    // Check for privilege escalation
    const privilegedEvents = profile.events.filter(e => {
      const app = (e.appDisplayName || '').toLowerCase()
      return app.includes('admin') || app.includes('portal') || app.includes('management')
    })
    
    if (privilegedEvents.length > 0) {
      const escalationRatio = privilegedEvents.length / profile.totalEvents
      if (escalationRatio > 0.3) {
        privilegeEscalation.push({
          user,
          escalationType: 'High Privilege Access Ratio',
          attempts: privilegedEvents.length,
          successRate: privilegedEvents.filter(e => e.status?.errorCode === 0 || e.status?.errorCode === '0').length / privilegedEvents.length,
          riskLevel: escalationRatio > 0.7 ? 'high' : 'medium'
        })
      }
    }
  })
  
  // Create clusters
  Object.entries(behaviorGroups).forEach(([riskLevel, users], index) => {
    if (users.length > 0) {
      clusters.push({
        id: `cluster-${index}`,
        users,
        threatType: riskLevel === 'high-risk' ? 'Coordinated Attack' : 
                   riskLevel === 'medium-risk' ? 'Suspicious Activity' : 'Normal Activity',
        riskScore: riskLevel === 'high-risk' ? 85 : riskLevel === 'medium-risk' ? 55 : 25,
        features: {},
        centroid: [],
        anomalies: [],
        ttps: riskLevel === 'high-risk' ? ['T1110.004', 'T1078'] : [],
        confidence: 0.7
      })
    }
  })
  
  return {
    temporal: {
      rapidSequences,
      failedToSuccessPatterns,
      bruteForceAttempts
    },
    geographic: {
      impossibleTravel,
      velocityAnomalies,
      countryTransitions
    },
    infrastructure: {
      sharedIPs,
      deviceFingerprints,
      proxyIndicators,
      deviceTypes,
      browserTypes,
      operatingSystems
    },
    behavioral: {
      clusters,
      anomalies,
      privilegeEscalation
    }
  }
}

function calculateUserRiskScore(profile: UserProfile): number {
  let score = 0
  
  // High failure rate
  if (profile.successRate < 0.5) score += 30
  else if (profile.successRate < 0.8) score += 15
  
  // High IP diversity
  if (profile.ipAddresses.size > 8) score += 25
  else if (profile.ipAddresses.size > 4) score += 15
  
  // Geographic diversity
  if (profile.countries.size > 3) score += 20
  else if (profile.countries.size > 1) score += 10
  
  // High activity volume
  if (profile.totalEvents > 100) score += 10
  else if (profile.totalEvents > 50) score += 5
  
  // Time pattern anomalies
  if (profile.hours.size > 16) score += 15 // Active across too many hours
  
  return Math.min(score, 100)
}

function calculateRiskAssessment(threats: ThreatIndicator[], correlations: CorrelationData): RiskAssessment {
  const criticalThreats = threats.filter(t => t.severity === 'critical').length
  const highThreats = threats.filter(t => t.severity === 'high').length
  const mediumThreats = threats.filter(t => t.severity === 'medium').length
  
  const baseScore = criticalThreats * 25 + highThreats * 15 + mediumThreats * 8
  const correlationBonus = correlations.temporal.rapidSequences.length * 5 + 
                          correlations.geographic.impossibleTravel.length * 10
  
  const overallRiskScore = Math.min(baseScore + correlationBonus, 100)
  
  let riskLevel: 'critical' | 'high' | 'medium' | 'low' = 'low'
  if (overallRiskScore > 75) riskLevel = 'critical'
  else if (overallRiskScore > 50) riskLevel = 'high'
  else if (overallRiskScore > 25) riskLevel = 'medium'
  
  const recommendations = [
    {
      priority: 'critical' as const,
      action: 'Implement MFA for all privileged accounts',
      description: 'Multi-factor authentication prevents most credential-based attacks',
      timeline: 'Immediate'
    },
    {
      priority: 'high' as const,
      action: 'Review and investigate flagged user accounts',
      description: 'Manually verify suspicious authentication patterns',
      timeline: '24-48 hours'
    },
    {
      priority: 'medium' as const,
      action: 'Configure conditional access policies',
      description: 'Block access from suspicious locations and devices',
      timeline: '1-2 weeks'
    }
  ]
  
  return {
    overallRiskScore,
    riskLevel,
    riskFactors: [
      { factor: 'Critical Threats', impact: criticalThreats * 25, description: `${criticalThreats} critical threats detected` },
      { factor: 'High Threats', impact: highThreats * 15, description: `${highThreats} high-severity threats` },
      { factor: 'Correlations', impact: correlationBonus, description: 'Multi-vector attack indicators' }
    ],
    recommendations
  }
}

function buildSummaryStats(logs: LogEntry[], userProfiles: Record<string, UserProfile>) {
  const totalEvents = logs.length
  const uniqueUsers = Object.keys(userProfiles).length
  const successfulSignins = logs.filter(log => 
    log.status?.errorCode === 0 || log.status?.errorCode === '0'
  ).length
  const failedSignins = totalEvents - successfulSignins
  const successRate = totalEvents > 0 ? successfulSignins / totalEvents : 0
  
  // Get time range
  const timestamps = logs
    .map(log => new Date(log.time || log.createdDateTime || log.timestamp || Date.now()))
    .sort((a, b) => a.getTime() - b.getTime())
  
  const timeRange = {
    start: timestamps[0]?.toISOString() || new Date().toISOString(),
    end: timestamps[timestamps.length - 1]?.toISOString() || new Date().toISOString()
  }
  
  // Top countries
  const countryStats: Record<string, number> = {}
  logs.forEach(log => {
    if (log.location?.countryOrRegion) {
      countryStats[log.location.countryOrRegion] = (countryStats[log.location.countryOrRegion] || 0) + 1
    }
  })
  
  const topCountries = Object.entries(countryStats)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5)
    .map(([country, count]) => ({ country, count }))
  
  // Top applications
  const appStats: Record<string, { count: number; successes: number }> = {}
  logs.forEach(log => {
    const app = log.appDisplayName || 'Unknown'
    if (!appStats[app]) {
      appStats[app] = { count: 0, successes: 0 }
    }
    appStats[app].count++
    if (log.status?.errorCode === 0 || log.status?.errorCode === '0') {
      appStats[app].successes++
    }
  })
  
  const topApplications = Object.entries(appStats)
    .sort(([,a], [,b]) => b.count - a.count)
    .slice(0, 8)
    .map(([app, stats]) => ({
      app,
      count: stats.count,
      successRate: stats.count > 0 ? stats.successes / stats.count : 0
    }))
  
  // Top users
  const topUsers = Object.entries(userProfiles)
    .sort(([,a], [,b]) => b.totalEvents - a.totalEvents)
    .slice(0, 10)
    .map(([user, profile]) => ({
      user,
      count: profile.totalEvents,
      successRate: profile.successRate
    }))
  
  return {
    totalEvents,
    uniqueUsers,
    successfulSignins,
    failedSignins,
    successRate,
    timeRange,
    topCountries,
    topApplications,
    topUsers
  }
}

function generateUserRiskProfiles(
  userProfiles: Record<string, UserProfile>,
  correlations: CorrelationData,
  threats: ThreatIndicator[]
): Record<string, UserRiskProfile> {
  const riskProfiles: Record<string, UserRiskProfile> = {}

  Object.entries(userProfiles).forEach(([user, profile]) => {
    // Calculate geographic risk factors
    const geographicRisk = calculateGeographicRisk(profile, correlations)
    
    // Calculate temporal risk factors  
    const temporalRisk = calculateTemporalRisk(profile, threats)
    
    // Calculate application risk factors
    const applicationRisk = calculateApplicationRisk(profile)
    
    // Calculate device risk factors
    const deviceRisk = calculateDeviceRisk(profile)
    
    // Calculate behavioral risk factors
    const behavioralRisk = calculateBehavioralRisk(profile, correlations)
    
    // Calculate privilege risk factors
    const privilegeRisk = calculatePrivilegeRisk(profile, threats)
    
    // Calculate user agent risk factors
    const userAgentRisk = calculateUserAgentRisk(profile)
    
    // Calculate operation risk factors
    const operationRisk = calculateOperationRisk(profile, threats)
    
    // Enhanced overall risk calculation with more factors
    const overallRiskScore = Math.round(
      (geographicRisk * 0.18 + temporalRisk * 0.15 + applicationRisk * 0.18 + 
       deviceRisk * 0.12 + behavioralRisk * 0.15 + privilegeRisk * 0.12 + 
       userAgentRisk * 0.05 + operationRisk * 0.05) * 100
    ) / 100

    const riskLevel = overallRiskScore >= 0.8 ? 'critical' : 
                     overallRiskScore >= 0.6 ? 'high' :
                     overallRiskScore >= 0.4 ? 'medium' : 'low'

    // Extract threat-related information for this user
    const userThreats = threats.filter(t => t.user === user || t.users?.includes(user))
    const impossibleTravelEvents = correlations.geographic.impossibleTravel.filter(t => t.user === user)

    // Analyze operations
    const riskOperations = Array.from(profile.operationTypes).filter(op => 
      ['PasswordReset', 'RoleAssignment', 'UserCreation', 'PolicyChange'].some(risk => op.includes(risk))
    )
    
    const privilegedOperations = profile.events.filter(e => 
      e.appDisplayName?.includes('Admin') || 
      e.appDisplayName?.includes('PowerShell') ||
      e.appDisplayName?.includes('Graph')
    ).length

    // Analyze browsers and user agents
    const riskBrowsers = Array.from(profile.browsers).filter(browser => 
      ['Unknown', 'Other', 'Custom'].some(risk => browser.includes(risk))
    )
    
    const unusualUserAgents = Array.from(profile.userAgents).filter(ua => 
      ua.includes('bot') || ua.includes('curl') || ua.includes('wget') || 
      ua.length < 10 || ua.length > 500
    )

    riskProfiles[user] = {
      user,
      overallRiskScore,
      riskLevel,
      riskFactors: {
        geographic: geographicRisk,
        temporal: temporalRisk,
        application: applicationRisk,
        device: deviceRisk,
        behavioral: behavioralRisk,
        privilege: privilegeRisk,
        userAgent: userAgentRisk,
        operation: operationRisk
      },
      locations: {
        countries: Array.from(profile.countries),
        cities: Array.from(profile.locations),
        suspiciousLocations: userThreats.filter(t => t.type.includes('location')).length,
        impossibleTravelEvents: impossibleTravelEvents.length
      },
      applications: {
        totalApps: profile.applications.size,
        riskApps: Array.from(profile.applications).filter(app => 
          ['PowerShell', 'Admin', 'Graph', 'Exchange'].some(risk => app.includes(risk))
        ),
        privilegedAccess: Array.from(profile.applications).some(app => 
          ['Admin', 'Graph', 'PowerShell'].some(priv => app.includes(priv))
        ),
        newApplications: userThreats.filter(t => t.type.includes('application')).length
      },
      operations: {
        totalOperations: profile.totalEvents,
        failedOperations: profile.failedEvents,
        suspiciousOperations: userThreats.filter(t => t.type.includes('operation')).map(t => t.type),
        timeAnomalies: userThreats.filter(t => t.type.includes('time')).length,
        riskOperations,
        privilegedOperations
      },
      devices: {
        totalDevices: profile.devices.size,
        unmangedDevices: profile.events.filter(e => 
          e.deviceDetail && !e.deviceDetail.isManaged
        ).length,
        suspiciousDevices: Array.from(profile.devices).filter(device => 
          userThreats.some(t => t.details?.device === device)
        ),
        newDevices: userThreats.filter(t => t.type.includes('device')).length,
        riskBrowsers,
        unusualUserAgents
      },
      privilegeProfile: {
        level: profile.privilegeLevel,
        roles: Array.from(profile.userRoles),
        privilegedAccess: profile.privilegeLevel !== 'Standard',
        escalationAttempts: userThreats.filter(t => t.type.includes('escalation')).length,
        adminOperations: privilegedOperations
      },
      behaviorProfile: {
        clusterId: correlations.behavioral.clusters.find(c => c.users.includes(user))?.id,
        isAnomaly: correlations.behavioral.anomalies.some(a => a.user === user),
        anomalyScore: correlations.behavioral.anomalies.find(a => a.user === user)?.score || 0,
        normalBehaviorBaseline: {
          avgHourlyActivity: profile.totalEvents / 24,
          avgDailyLocations: profile.locations.size / Math.max(1, 
            (profile.lastSeen.getTime() - profile.firstSeen.getTime()) / (1000 * 60 * 60 * 24)
          ),
          successRate: profile.successRate
        },
        deviations: {
          locationVariance: profile.countries.size > 3 ? 0.8 : 0.2,
          timeVariance: profile.hours.size > 16 ? 0.9 : 0.1,
          failureRate: 1 - profile.successRate
        }
      }
    }
  })

  return riskProfiles
}

function calculateGeographicRisk(profile: UserProfile, correlations: CorrelationData): number {
  let risk = 0
  
  // Multiple countries increase risk
  if (profile.countries.size > 3) risk += 0.3
  else if (profile.countries.size > 1) risk += 0.1
  
  // Many locations increase risk
  if (profile.locations.size > 10) risk += 0.2
  else if (profile.locations.size > 5) risk += 0.1
  
  // Impossible travel increases risk significantly
  const userImpossibleTravel = correlations.geographic.impossibleTravel.filter(t => t.user === profile.user)
  risk += Math.min(userImpossibleTravel.length * 0.3, 0.5)
  
  return Math.min(risk, 1)
}

function calculateTemporalRisk(profile: UserProfile, threats: ThreatIndicator[]): number {
  let risk = 0
  
  // Activity across many hours suggests automated behavior
  if (profile.hours.size > 20) risk += 0.4
  else if (profile.hours.size > 16) risk += 0.2
  
  // Recent threats increase temporal risk
  const recentThreats = threats.filter(t => 
    (t.user === profile.user || t.users?.includes(profile.user)) &&
    t.timestamp && new Date(t.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
  )
  risk += Math.min(recentThreats.length * 0.1, 0.3)
  
  return Math.min(risk, 1)
}

function calculateApplicationRisk(profile: UserProfile): number {
  let risk = 0
  
  const riskApps = Array.from(profile.applications).filter(app =>
    ['PowerShell', 'Admin', 'Graph', 'Exchange', 'SharePoint Admin'].some(risky => app.includes(risky))
  )
  
  // More risky applications increase risk
  risk += Math.min(riskApps.length * 0.15, 0.6)
  
  // Too many applications might indicate compromise
  if (profile.applications.size > 15) risk += 0.3
  else if (profile.applications.size > 10) risk += 0.1
  
  return Math.min(risk, 1)
}

function calculateDeviceRisk(profile: UserProfile): number {
  let risk = 0
  
  // Multiple devices increase risk
  if (profile.devices.size > 5) risk += 0.3
  else if (profile.devices.size > 3) risk += 0.1
  
  // Check for unmanaged devices
  const unmanagedDevices = profile.events.filter(e => 
    e.deviceDetail && e.deviceDetail.isManaged === false
  ).length
  
  if (unmanagedDevices > 0) {
    risk += Math.min(unmanagedDevices * 0.2, 0.4)
  }
  
  return Math.min(risk, 1)
}

function calculateBehavioralRisk(profile: UserProfile, correlations: CorrelationData): number {
  let risk = 0
  
  // Low success rate indicates potential issues
  if (profile.successRate < 0.7) risk += 0.3
  else if (profile.successRate < 0.9) risk += 0.1
  
  // Check if user is in high-risk behavioral cluster
  const userCluster = correlations.behavioral.clusters.find(c => c.users.includes(profile.user))
  if (userCluster && userCluster.riskScore > 0.7) {
    risk += 0.4
  }
  
  // Check for behavioral anomalies
  const userAnomaly = correlations.behavioral.anomalies.find(a => a.user === profile.user)
  if (userAnomaly) {
    risk += Math.min(userAnomaly.score, 0.5)
  }
  
  return Math.min(risk, 1)
}

function calculatePrivilegeRisk(profile: UserProfile, threats: ThreatIndicator[]): number {
  let risk = 0
  
  // Base risk by privilege level
  switch (profile.privilegeLevel) {
    case 'GlobalAdmin':
      risk += 0.6 // High baseline risk for global admins
      break
    case 'Admin':
      risk += 0.4
      break
    case 'Elevated':
      risk += 0.2
      break
    case 'Standard':
      risk += 0.0
      break
  }
  
  // Additional risk for privilege escalation attempts
  const escalationThreats = threats.filter(t => 
    (t.user === profile.user || t.users?.includes(profile.user)) &&
    t.type.includes('escalation')
  )
  risk += Math.min(escalationThreats.length * 0.3, 0.4)
  
  // Risk from admin applications usage
  const adminApps = Array.from(profile.applications).filter(app =>
    app.includes('PowerShell') || app.includes('Admin Portal') || app.includes('Graph')
  ).length
  risk += Math.min(adminApps * 0.1, 0.3)
  
  return Math.min(risk, 1)
}

function calculateUserAgentRisk(profile: UserProfile): number {
  let risk = 0
  
  const userAgents = Array.from(profile.userAgents)
  
  // Risk from suspicious user agents
  const suspiciousAgents = userAgents.filter(ua => 
    ua.includes('bot') || ua.includes('curl') || ua.includes('wget') ||
    ua.includes('python') || ua.includes('script') || ua.length < 10
  ).length
  
  risk += Math.min(suspiciousAgents * 0.2, 0.5)
  
  // Risk from too many different user agents (potential automation)
  if (userAgents.length > 10) risk += 0.3
  else if (userAgents.length > 5) risk += 0.1
  
  // Risk from empty or generic user agents
  const genericAgents = userAgents.filter(ua => 
    ua === 'Unknown' || ua === '' || ua.length < 5
  ).length
  
  risk += Math.min(genericAgents * 0.15, 0.3)
  
  return Math.min(risk, 1)
}

function calculateOperationRisk(profile: UserProfile, threats: ThreatIndicator[]): number {
  let risk = 0
  
  const operations = Array.from(profile.operationTypes)
  
  // Risk from high-risk operations
  const riskOperations = operations.filter(op =>
    op.includes('PasswordReset') || op.includes('RoleAssignment') ||
    op.includes('UserCreation') || op.includes('PolicyChange') ||
    op.includes('PermissionGrant') || op.includes('DeviceDelete')
  ).length
  
  risk += Math.min(riskOperations * 0.2, 0.6)
  
  // Risk from failed operations
  const failureRate = profile.totalEvents > 0 ? profile.failedEvents / profile.totalEvents : 0
  if (failureRate > 0.3) risk += 0.4
  else if (failureRate > 0.1) risk += 0.2
  
  // Risk from operation-related threats
  const opThreats = threats.filter(t => 
    (t.user === profile.user || t.users?.includes(profile.user)) &&
    t.type.includes('operation')
  )
  risk += Math.min(opThreats.length * 0.1, 0.3)
  
  return Math.min(risk, 1)
}

function generateGeoClusters(logs: LogEntry[], userProfiles: Record<string, UserProfile>): GeoCluster[] {
  const clusters: GeoCluster[] = []
  const locationMap = new Map<string, {
    users: Set<string>
    coordinates: { lat: number, lon: number }[]
    activities: number
    riskEvents: string[]
  }>()

  // Group activities by location
  logs.forEach(log => {
    const user = log.userPrincipalName || log.userId || 'Unknown'
    const location = log.location
    
    if (location?.countryOrRegion && location?.geoCoordinates) {
      const key = `${location.city || 'Unknown'}, ${location.countryOrRegion}`
      
      if (!locationMap.has(key)) {
        locationMap.set(key, {
          users: new Set(),
          coordinates: [],
          activities: 0,
          riskEvents: []
        })
      }
      
      const locationData = locationMap.get(key)!
      locationData.users.add(user)
      locationData.coordinates.push({
        lat: location.geoCoordinates.latitude,
        lon: location.geoCoordinates.longitude
      })
      locationData.activities++
      
      // Track risk indicators
      if (log.status?.errorCode !== 0 && log.status?.errorCode !== '0') {
        locationData.riskEvents.push('failed_signin')
      }
      if (log.riskDetail?.riskLevel === 'high' || log.riskDetail?.riskLevel === 'medium') {
        locationData.riskEvents.push('risky_signin')
      }
    }
  })

  // Convert to clusters
  let clusterId = 1
  locationMap.forEach((data, location) => {
    const [city, country] = location.split(', ')
    
    // Calculate centroid
    const avgLat = data.coordinates.reduce((sum, coord) => sum + coord.lat, 0) / data.coordinates.length
    const avgLon = data.coordinates.reduce((sum, coord) => sum + coord.lon, 0) / data.coordinates.length
    
    // Calculate risk score
    const riskScore = Math.min(
      (data.riskEvents.length / data.activities) * 2 + 
      (data.users.size > 10 ? 0.3 : 0), 
      1
    )
    
    // Determine peak activity hours (simplified)
    const peakHours = [9, 10, 11, 14, 15, 16] // Business hours as default
    
    clusters.push({
      id: `geo-cluster-${clusterId++}`,
      centroid: {
        latitude: avgLat,
        longitude: avgLon,
        city: city !== 'Unknown' ? city : undefined,
        country
      },
      users: Array.from(data.users),
      radius: Math.max(50, Math.min(data.coordinates.length * 10, 500)), // km
      activityCount: data.activities,
      riskScore,
      suspiciousActivities: [...new Set(data.riskEvents)],
      timePattern: {
        peakHours,
        timezone: 'UTC' // Would need to derive from location in real implementation
      }
    })
  })

  return clusters.sort((a, b) => b.riskScore - a.riskScore)
}

function generateBehavioralAnalysis(
  userProfiles: Record<string, UserProfile>,
  correlations: CorrelationData
) {
  const users = Object.values(userProfiles)
  
  // Risk distribution
  const riskDistribution = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  }
  
  users.forEach(user => {
    const riskScore = calculateOverallUserRisk(user, correlations)
    if (riskScore >= 0.8) riskDistribution.critical++
    else if (riskScore >= 0.6) riskDistribution.high++
    else if (riskScore >= 0.4) riskDistribution.medium++
    else riskDistribution.low++
  })
  
  // Anomaly detection summary
  const anomalyDetection = {
    totalAnomalies: correlations.behavioral.anomalies.length,
    userAnomalies: correlations.behavioral.anomalies.reduce((acc, anomaly) => {
      acc[anomaly.user] = (acc[anomaly.user] || 0) + 1
      return acc
    }, {} as Record<string, number>),
    anomalyTypes: correlations.behavioral.anomalies.reduce((acc, anomaly) => {
      acc[anomaly.anomalyType] = (acc[anomaly.anomalyType] || 0) + 1
      return acc
    }, {} as Record<string, number>)
  }
  
  // Cluster analysis
  const clusterAnalysis = {
    totalClusters: correlations.behavioral.clusters.length,
    clusterSizes: correlations.behavioral.clusters.map(c => c.users.length),
    riskClusters: correlations.behavioral.clusters
      .filter(c => c.riskScore > 0.6)
      .map(c => c.id)
  }
  
  return {
    riskDistribution,
    anomalyDetection,
    clusterAnalysis
  }
}

function calculateOverallUserRisk(profile: UserProfile, correlations: CorrelationData): number {
  let risk = 0
  
  // Success rate impact
  risk += (1 - profile.successRate) * 0.3
  
  // Geographic factors
  if (profile.countries.size > 2) risk += 0.2
  if (profile.locations.size > 8) risk += 0.1
  
  // Temporal factors
  if (profile.hours.size > 18) risk += 0.2
  
  // Behavioral anomalies
  const userAnomaly = correlations.behavioral.anomalies.find(a => a.user === profile.user)
  if (userAnomaly) risk += userAnomaly.score * 0.3
  
  return Math.min(risk, 1)
}