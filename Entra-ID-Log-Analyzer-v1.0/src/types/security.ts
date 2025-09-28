export interface LogEntry {
  time: string
  createdDateTime?: string
  timestamp?: string
  userPrincipalName?: string
  userId?: string
  appDisplayName?: string
  resourceDisplayName?: string
  status?: {
    errorCode: number | string
    failureReason?: string
  }
  location?: {
    city?: string
    countryOrRegion?: string
    state?: string
    geoCoordinates?: {
      latitude: number
      longitude: number
    }
  }
  ipAddress?: string
  deviceDetail?: {
    deviceId?: string
    displayName?: string
    operatingSystem?: string
    browser?: string
    isCompliant?: boolean
    isManaged?: boolean
    trustType?: string
  }
  riskDetail?: {
    riskLevel: string
    riskState: string
    riskEventTypes: string[]
  }
  conditionalAccessStatus?: string
  appliedConditionalAccessPolicies?: Array<{
    id: string
    displayName: string
    enforcedGrantControls: string[]
    enforcedSessionControls: string[]
    result: string
  }>
  userAgent?: string
  userType?: 'Member' | 'Guest'
  userRoles?: string[]
  isInteractive?: boolean
  operationType?: string
  workloadIdentity?: string
}

export interface UserProfile {
  user: string
  events: LogEntry[]
  ipAddresses: Set<string>
  locations: Set<string>
  countries: Set<string>
  devices: Set<string>
  browsers: Set<string>
  applications: Set<string>
  hours: Set<number>
  firstSeen: Date
  lastSeen: Date
  totalEvents: number
  successfulEvents: number
  failedEvents: number
  successRate: number
  userAgents: Set<string>
  operationTypes: Set<string>
  userType: 'Member' | 'Guest' | 'Unknown'
  userRoles: Set<string>
  privilegeLevel: 'Standard' | 'Elevated' | 'Admin' | 'GlobalAdmin'
}

export interface ThreatIndicator {
  type: string
  user?: string
  users?: string[]
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  timestamp?: string
  details?: Record<string, any>
  confidence?: number
  mitreAttack?: string[]
}

export interface ImpossibleTravel {
  user: string
  fromLocation: string
  toLocation: string
  fromCountry: string
  toCountry: string
  distance: number
  timeWindow: number
  velocity: number
  riskLevel: 'critical' | 'high' | 'medium'
  events: LogEntry[]
}

export interface BehavioralCluster {
  id: string
  users: string[]
  threatType: string
  riskScore: number
  features: Record<string, number>
  centroid: number[]
  anomalies: string[]
  ttps: string[]
  confidence: number
}

export interface CorrelationData {
  temporal: {
    rapidSequences: Array<{
      user: string
      events: LogEntry[]
      interval: number
      riskLevel: string
    }>
    failedToSuccessPatterns: Array<{
      user: string
      failedEvent: LogEntry
      successEvent: LogEntry
      interval: number
    }>
    bruteForceAttempts: Array<{
      user: string
      attempts: number
      timespan: number
      uniqueIPs: number
    }>
  }
  geographic: {
    impossibleTravel: ImpossibleTravel[]
    velocityAnomalies: Array<{
      user: string
      avgVelocity: number
      maxVelocity: number
      suspiciousTransitions: number
    }>
    countryTransitions: Record<string, number>
  }
  infrastructure: {
    sharedIPs: Record<string, {
      users: string[]
      count: number
      isPrivate: boolean
      riskLevel: string
      suspiciousActivity: boolean
    }>
    deviceFingerprints: Record<string, {
      users: string[]
      count: number
      riskLevel: string
    }>
    proxyIndicators: Array<{
      ip: string
      users: string[]
      indicators: string[]
    }>
    deviceTypes?: Record<string, {
      count: number
      users: string[]
      suspicious: boolean
      riskLevel: string
    }>
    browserTypes?: Record<string, {
      count: number
      users: string[]
      suspicious: boolean
      riskLevel: string
    }>
    operatingSystems?: Record<string, {
      count: number
      users: string[]
      outdated: boolean
      riskLevel: string
    }>
  }
  behavioral: {
    clusters: BehavioralCluster[]
    anomalies: Array<{
      user: string
      clusterId?: string
      anomalyType: string
      score: number
      description: string
    }>
    privilegeEscalation: Array<{
      user: string
      escalationType: string
      attempts: number
      successRate: number
      riskLevel: string
    }>
  }
}

export interface RiskAssessment {
  overallRiskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  riskFactors: Array<{
    factor: string
    impact: number
    description: string
  }>
  recommendations: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low'
    action: string
    description: string
    timeline: string
  }>
}

export interface AnalysisResults {
  timestamp: string
  summary: {
    totalEvents: number
    uniqueUsers: number
    successfulSignins: number
    failedSignins: number
    successRate: number
    timeRange: {
      start: string
      end: string
    }
    topCountries: Array<{ country: string; count: number }>
    topApplications: Array<{ app: string; count: number; successRate: number }>
    topUsers: Array<{ user: string; count: number; successRate: number }>
  }
  threats: ThreatIndicator[]
  correlations: CorrelationData
  userProfiles: Record<string, UserProfile>
  riskAssessment: RiskAssessment
  userRiskProfiles: Record<string, UserRiskProfile>
  geoClusters: GeoCluster[]
  behavioralAnalysis: {
    riskDistribution: Record<string, number>
    anomalyDetection: {
      totalAnomalies: number
      userAnomalies: Record<string, number>
      anomalyTypes: Record<string, number>
    }
    clusterAnalysis: {
      totalClusters: number
      clusterSizes: number[]
      riskClusters: string[]
    }
  }
  rawLogs: LogEntry[]
  processingStats: {
    totalProcessingTime: number
    parsedEntries: number
    skippedEntries: number
    errorCount: number
    warnings: string[]
  }
}

export interface ChartDataPoint {
  name: string
  value: number
  timestamp?: string
  color?: string
  metadata?: Record<string, any>
}

export interface TimeSeriesData {
  timestamp: string
  events: number
  successes: number
  failures: number
  uniqueUsers: number
}

export interface GeographicData {
  country: string
  city?: string
  count: number
  successRate: number
  riskLevel: string
  users: string[]
}

export interface DeviceData {
  deviceType: string
  browser: string
  os: string
  count: number
  users: string[]
  riskIndicators: string[]
}

export interface UserRiskProfile {
  user: string
  overallRiskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  riskFactors: {
    geographic: number
    temporal: number
    application: number
    device: number
    behavioral: number
    privilege: number
    userAgent: number
    operation: number
  }
  locations: {
    countries: string[]
    cities: string[]
    suspiciousLocations: number
    impossibleTravelEvents: number
  }
  applications: {
    totalApps: number
    riskApps: string[]
    privilegedAccess: boolean
    newApplications: number
  }
  operations: {
    totalOperations: number
    failedOperations: number
    suspiciousOperations: string[]
    timeAnomalies: number
    riskOperations: string[]
    privilegedOperations: number
  }
  devices: {
    totalDevices: number
    unmangedDevices: number
    suspiciousDevices: string[]
    newDevices: number
    riskBrowsers: string[]
    unusualUserAgents: string[]
  }
  privilegeProfile: {
    level: 'Standard' | 'Elevated' | 'Admin' | 'GlobalAdmin'
    roles: string[]
    privilegedAccess: boolean
    escalationAttempts: number
    adminOperations: number
  }
  behaviorProfile: {
    clusterId?: string
    isAnomaly: boolean
    anomalyScore: number
    normalBehaviorBaseline: Record<string, number>
    deviations: Record<string, number>
  }
}

export interface GeoCluster {
  id: string
  centroid: {
    latitude: number
    longitude: number
    city?: string
    country: string
  }
  users: string[]
  radius: number
  activityCount: number
  riskScore: number
  suspiciousActivities: string[]
  timePattern: {
    peakHours: number[]
    timezone: string
  }
}