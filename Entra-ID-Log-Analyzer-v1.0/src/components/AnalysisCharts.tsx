import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend, Area, AreaChart
} from 'recharts'
import { 
  ChartBar, 
  Clock, 
  GlobeHemisphereWest, 
  DeviceMobile,
  TrendUp,
  Warning,
  Eye,
  Calendar,
  Users,
  Activity
} from '@phosphor-icons/react'
import type { AnalysisResults } from '@/types/security'

interface AnalysisChartsProps {
  results: AnalysisResults
}

export function AnalysisCharts({ results }: AnalysisChartsProps) {
  const { summary, userProfiles, rawLogs } = results
  const [selectedTimelineData, setSelectedTimelineData] = useState<any>(null)
  const [selectedStatusData, setSelectedStatusData] = useState<any>(null)
  const [selectedHourData, setSelectedHourData] = useState<any>(null)
  const [selectedCountryData, setSelectedCountryData] = useState<any>(null)
  const [selectedRiskData, setSelectedRiskData] = useState<any>(null)

  // Prepare success/failure pie chart data
  const statusData = [
    { name: 'Successful', value: summary.successfulSignins, color: '#10B981' },
    { name: 'Failed', value: summary.failedSignins, color: '#EF4444' }
  ]

  // Prepare hourly activity data
  const hourlyData = Array.from({ length: 24 }, (_, hour) => {
    const events = rawLogs.filter(log => {
      const logHour = new Date(log.time || log.createdDateTime || log.timestamp || 0).getHours()
      return logHour === hour
    })
    return {
      hour: `${hour.toString().padStart(2, '0')}:00`,
      events: events.length,
      successes: events.filter(log => log.status?.errorCode === 0 || log.status?.errorCode === '0').length,
      failures: events.filter(log => log.status?.errorCode !== 0 && log.status?.errorCode !== '0').length
    }
  })

  // Prepare top users data
  const topUsersData = summary.topUsers.slice(0, 8).map(user => ({
    user: user.user.split('@')[0] || user.user,
    events: user.count,
    successRate: Math.round(user.successRate * 100)
  }))

  // Prepare country data for bar chart
  const countryData = summary.topCountries.map(country => ({
    country: country.country,
    count: country.count,
    percentage: Math.round((country.count / summary.totalEvents) * 100)
  }))

  // Prepare daily timeline data
  const dailyData: Record<string, { successes: number; failures: number; total: number }> = {}
  rawLogs.forEach(log => {
    const date = new Date(log.time || log.createdDateTime || log.timestamp || 0).toISOString().split('T')[0]
    if (!dailyData[date]) {
      dailyData[date] = { successes: 0, failures: 0, total: 0 }
    }
    dailyData[date].total++
    if (log.status?.errorCode === 0 || log.status?.errorCode === '0') {
      dailyData[date].successes++
    } else {
      dailyData[date].failures++
    }
  })

  const timelineData = Object.entries(dailyData)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, data]) => ({
      date: new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      fullDate: date,
      total: data.total,
      successes: data.successes,
      failures: data.failures,
      successRate: data.total > 0 ? (data.successes / data.total * 100).toFixed(1) : '0',
      // Get events for this date for detailed view
      events: rawLogs.filter(log => {
        const logDate = new Date(log.time || log.createdDateTime || log.timestamp || 0).toISOString().split('T')[0]
        return logDate === date
      }).slice(0, 50) // Limit to 50 events for performance
    }))

  // Custom click handlers
  const handleTimelineClick = (data: any) => {
    if (data && data.activePayload && data.activePayload[0]) {
      const clickedData = data.activePayload[0].payload
      setSelectedTimelineData(clickedData)
    }
  }

  const handleStatusClick = () => {
    const statusDetails = {
      successful: rawLogs.filter(log => log.status?.errorCode === 0 || log.status?.errorCode === '0').slice(0, 100),
      failed: rawLogs.filter(log => log.status?.errorCode !== 0 && log.status?.errorCode !== '0').slice(0, 100),
      failureReasons: rawLogs
        .filter(log => log.status?.failureReason)
        .reduce((acc: any, log) => {
          const reason = log.status?.failureReason || 'Unknown'
          acc[reason] = (acc[reason] || 0) + 1
          return acc
        }, {})
    }
    setSelectedStatusData(statusDetails)
  }

  const handleHourClick = (data: any) => {
    if (data && data.activePayload && data.activePayload[0]) {
      const hourData = data.activePayload[0].payload
      const hourNumber = parseInt(hourData.hour.split(':')[0])
      const eventsInHour = rawLogs.filter(log => {
        const logHour = new Date(log.time || log.createdDateTime || log.timestamp || 0).getHours()
        return logHour === hourNumber
      }).slice(0, 100)
      
      setSelectedHourData({
        ...hourData,
        events: eventsInHour,
        hourNumber
      })
    }
  }

  const handleCountryClick = (data: any) => {
    if (data && data.activePayload && data.activePayload[0]) {
      const countryData = data.activePayload[0].payload
      const eventsInCountry = rawLogs.filter(log => 
        log.location?.countryOrRegion === countryData.country
      ).slice(0, 100)
      
      setSelectedCountryData({
        ...countryData,
        events: eventsInCountry
      })
    }
  }

  const handleRiskClick = () => {
    const riskDetails = {
      highRiskThreats: results.threats.filter(t => t.severity === 'critical' || t.severity === 'high'),
      compromisedAccounts: Object.entries(userProfiles)
        .filter(([_, profile]) => profile.successRate < 0.5)
        .map(([user, profile]) => ({ user, profile })),
      impossibleTravel: results.correlations.geographic.impossibleTravel,
      suspiciousActivity: rawLogs.filter(log => 
        log.status?.failureReason?.includes('suspicious') ||
        log.riskDetail?.riskLevel === 'high' ||
        log.riskDetail?.riskLevel === 'medium'
      ).slice(0, 50)
    }
    setSelectedRiskData(riskDetails)
  }

  // Custom tooltip for charts
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border border-border rounded-lg shadow-lg p-3 text-sm">
          <p className="font-medium">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} style={{ color: entry.color }}>
              {entry.name}: {entry.value?.toLocaleString()}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <div className="space-y-6">
      {/* Authentication Timeline */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <TrendUp className="w-5 h-5" />
              <span>Authentication Timeline</span>
            </div>
            <Badge variant="outline" className="text-xs">Click data points for details</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} onClick={handleTimelineClick}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis 
                  dataKey="date" 
                  className="text-muted-foreground text-xs"
                  tick={{ fontSize: 12 }}
                />
                <YAxis 
                  className="text-muted-foreground text-xs"
                  tick={{ fontSize: 12 }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="successes"
                  stackId="1"
                  stroke="#10B981"
                  fill="#10B981"
                  fillOpacity={0.6}
                  name="Successful Logins"
                  style={{ cursor: 'pointer' }}
                />
                <Area
                  type="monotone"
                  dataKey="failures"
                  stackId="1"
                  stroke="#EF4444"
                  fill="#EF4444"
                  fillOpacity={0.6}
                  name="Failed Logins"
                  style={{ cursor: 'pointer' }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Timeline Detail Modal */}
      <Dialog open={!!selectedTimelineData} onOpenChange={() => setSelectedTimelineData(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <Calendar className="w-5 h-5" />
              <span>Authentication Details - {selectedTimelineData?.fullDate}</span>
            </DialogTitle>
            <DialogDescription>
              Detailed authentication events and analysis for {selectedTimelineData?.date}
            </DialogDescription>
          </DialogHeader>
          {selectedTimelineData && (
            <div className="space-y-6">
              {/* Summary Stats */}
              <div className="grid grid-cols-4 gap-4">
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{selectedTimelineData.total}</div>
                  <div className="text-sm text-blue-800">Total Events</div>
                </div>
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{selectedTimelineData.successes}</div>
                  <div className="text-sm text-green-800">Successful</div>
                </div>
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{selectedTimelineData.failures}</div>
                  <div className="text-sm text-red-800">Failed</div>
                </div>
                <div className="text-center p-4 bg-purple-50 rounded-lg">
                  <div className="text-2xl font-bold text-purple-600">{selectedTimelineData.successRate}%</div>
                  <div className="text-sm text-purple-800">Success Rate</div>
                </div>
              </div>

              {/* Event Details */}
              <div>
                <h4 className="font-medium text-sm mb-3 flex items-center space-x-2">
                  <Activity className="w-4 h-4" />
                  <span>Recent Events ({selectedTimelineData.events.length} shown)</span>
                </h4>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {selectedTimelineData.events.map((event: any, index: number) => (
                    <div key={index} className={`p-3 rounded-lg border text-sm ${
                      event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 
                      'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">
                          {event.userPrincipalName || event.userId || 'Unknown User'}
                        </span>
                        <Badge className={
                          event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 
                          'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }>
                          {event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 'Success' : 'Failed'}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
                        <div>
                          <span className="font-medium">Application:</span> {event.appDisplayName || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">Location:</span> {event.location?.city || 'Unknown'}, {event.location?.countryOrRegion || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">IP Address:</span> {event.ipAddress || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">Time:</span> {new Date(event.time || event.createdDateTime || event.timestamp || 0).toLocaleTimeString()}
                        </div>
                      </div>
                      {event.status?.failureReason && (
                        <div className="mt-2 text-xs text-red-600">
                          <span className="font-medium">Failure Reason:</span> {event.status.failureReason}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Authentication Status Detail Modal */}
      <Dialog open={!!selectedStatusData} onOpenChange={() => setSelectedStatusData(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <ChartBar className="w-5 h-5" />
              <span>Authentication Status Analysis</span>
            </DialogTitle>
            <DialogDescription>
              Detailed breakdown of successful and failed authentication attempts
            </DialogDescription>
          </DialogHeader>
          {selectedStatusData && (
            <div className="space-y-6">
              {/* Summary Stats */}
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{selectedStatusData.successful.length}</div>
                  <div className="text-sm text-green-800">Successful Attempts (Sample)</div>
                </div>
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{selectedStatusData.failed.length}</div>
                  <div className="text-sm text-red-800">Failed Attempts (Sample)</div>
                </div>
              </div>

              {/* Failure Reasons */}
              {Object.keys(selectedStatusData.failureReasons).length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-3">Top Failure Reasons</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {Object.entries(selectedStatusData.failureReasons)
                      .sort(([,a], [,b]) => (b as number) - (a as number))
                      .slice(0, 6)
                      .map(([reason, count]) => (
                        <div key={reason} className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                          <span className="text-sm text-red-800 truncate flex-1">{reason}</span>
                          <Badge className="bg-red-100 text-red-800 ml-2">{count as number}</Badge>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Recent Failed Attempts */}
              <div>
                <h4 className="font-medium text-sm mb-3">Recent Failed Attempts</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {selectedStatusData.failed.slice(0, 20).map((event: any, index: number) => (
                    <div key={index} className="p-3 rounded-lg border bg-red-50 border-red-200 text-sm">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">
                          {event.userPrincipalName || event.userId || 'Unknown User'}
                        </span>
                        <span className="text-xs text-red-600">
                          {new Date(event.time || event.createdDateTime || event.timestamp || 0).toLocaleString()}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
                        <div>
                          <span className="font-medium">Application:</span> {event.appDisplayName || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">IP:</span> {event.ipAddress || 'Unknown'}
                        </div>
                      </div>
                      {event.status?.failureReason && (
                        <div className="mt-2 text-xs text-red-600">
                          <span className="font-medium">Reason:</span> {event.status.failureReason}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Hourly Activity Detail Modal */}
      <Dialog open={!!selectedHourData} onOpenChange={() => setSelectedHourData(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <Clock className="w-5 h-5" />
              <span>Hourly Activity Details - {selectedHourData?.hour}</span>
            </DialogTitle>
            <DialogDescription>
              Authentication events during {selectedHourData?.hour} hour
            </DialogDescription>
          </DialogHeader>
          {selectedHourData && (
            <div className="space-y-6">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{selectedHourData.events.length}</div>
                  <div className="text-sm text-blue-800">Total Events</div>
                </div>
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{selectedHourData.successes}</div>
                  <div className="text-sm text-green-800">Successful</div>
                </div>
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{selectedHourData.failures}</div>
                  <div className="text-sm text-red-800">Failed</div>
                </div>
              </div>

              {/* Top Users in this Hour */}
              <div>
                <h4 className="font-medium text-sm mb-3">Most Active Users</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {Object.entries(
                    selectedHourData.events.reduce((acc: any, event: any) => {
                      const user = event.userPrincipalName || event.userId || 'Unknown'
                      acc[user] = (acc[user] || 0) + 1
                      return acc
                    }, {})
                  )
                    .sort(([,a], [,b]) => (b as number) - (a as number))
                    .slice(0, 6)
                    .map(([user, count]) => (
                      <div key={user} className="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                        <span className="text-sm text-blue-800 truncate flex-1">{user}</span>
                        <Badge className="bg-blue-100 text-blue-800 ml-2">{count as number}</Badge>
                      </div>
                    ))}
                </div>
              </div>

              {/* Event Details */}
              <div>
                <h4 className="font-medium text-sm mb-3">Events in {selectedHourData.hour}</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {selectedHourData.events.slice(0, 30).map((event: any, index: number) => (
                    <div key={index} className={`p-3 rounded-lg border text-sm ${
                      event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 
                      'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">
                          {event.userPrincipalName || event.userId || 'Unknown User'}
                        </span>
                        <span className="text-xs">
                          {new Date(event.time || event.createdDateTime || event.timestamp || 0).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
                        <div>
                          <span className="font-medium">Application:</span> {event.appDisplayName || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">Location:</span> {event.location?.city || 'Unknown'}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Geographic Distribution Detail Modal */}
      <Dialog open={!!selectedCountryData} onOpenChange={() => setSelectedCountryData(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <GlobeHemisphereWest className="w-5 h-5" />
              <span>Geographic Analysis - {selectedCountryData?.country}</span>
            </DialogTitle>
            <DialogDescription>
              Authentication events from {selectedCountryData?.country}
            </DialogDescription>
          </DialogHeader>
          {selectedCountryData && (
            <div className="space-y-6">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-4 bg-orange-50 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">{selectedCountryData.count}</div>
                  <div className="text-sm text-orange-800">Total Events</div>
                </div>
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{selectedCountryData.percentage}%</div>
                  <div className="text-sm text-blue-800">Of All Events</div>
                </div>
                <div className="text-center p-4 bg-purple-50 rounded-lg">
                  <div className="text-2xl font-bold text-purple-600">
                    {new Set(selectedCountryData.events.map((e: any) => e.userPrincipalName || e.userId)).size}
                  </div>
                  <div className="text-sm text-purple-800">Unique Users</div>
                </div>
              </div>

              {/* Top Cities */}
              <div>
                <h4 className="font-medium text-sm mb-3">Top Cities</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {Object.entries(
                    selectedCountryData.events.reduce((acc: any, event: any) => {
                      const city = event.location?.city || 'Unknown City'
                      acc[city] = (acc[city] || 0) + 1
                      return acc
                    }, {})
                  )
                    .sort(([,a], [,b]) => (b as number) - (a as number))
                    .slice(0, 6)
                    .map(([city, count]) => (
                      <div key={city} className="flex items-center justify-between p-3 bg-orange-50 rounded-lg">
                        <span className="text-sm text-orange-800 truncate flex-1">{city}</span>
                        <Badge className="bg-orange-100 text-orange-800 ml-2">{count as number}</Badge>
                      </div>
                    ))}
                </div>
              </div>

              {/* Recent Events from Country */}
              <div>
                <h4 className="font-medium text-sm mb-3">Recent Events from {selectedCountryData.country}</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {selectedCountryData.events.slice(0, 30).map((event: any, index: number) => (
                    <div key={index} className={`p-3 rounded-lg border text-sm ${
                      event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 
                      'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">
                          {event.userPrincipalName || event.userId || 'Unknown User'}
                        </span>
                        <Badge className={
                          event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 
                          'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }>
                          {event.status?.errorCode === 0 || event.status?.errorCode === '0' ? 'Success' : 'Failed'}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
                        <div>
                          <span className="font-medium">City:</span> {event.location?.city || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">IP:</span> {event.ipAddress || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">Application:</span> {event.appDisplayName || 'Unknown'}
                        </div>
                        <div>
                          <span className="font-medium">Time:</span> {new Date(event.time || event.createdDateTime || event.timestamp || 0).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Risk Indicators Detail Modal */}
      <Dialog open={!!selectedRiskData} onOpenChange={() => setSelectedRiskData(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              <Warning className="w-5 h-5" />
              <span>Risk Indicators Analysis</span>
            </DialogTitle>
            <DialogDescription>
              Detailed security risk analysis and threat indicators
            </DialogDescription>
          </DialogHeader>
          {selectedRiskData && (
            <div className="space-y-6">
              {/* High-Risk Threats */}
              {selectedRiskData.highRiskThreats.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-3 text-red-800">High-Risk Threats</h4>
                  <div className="space-y-2">
                    {selectedRiskData.highRiskThreats.map((threat: any, index: number) => (
                      <div key={index} className="p-3 rounded-lg border bg-red-50 border-red-200">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-red-800">{threat.type}</span>
                          <Badge className={`${
                            threat.severity === 'critical' ? 'bg-red-600 text-white' : 'bg-orange-600 text-white'
                          }`}>
                            {threat.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-red-700">{threat.description}</p>
                        <div className="mt-2 text-xs text-red-600">
                          <span className="font-medium">User:</span> {threat.user} | 
                          <span className="font-medium ml-2">Count:</span> {threat.count}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Compromised Accounts */}
              {selectedRiskData.compromisedAccounts.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-3 text-orange-800">Potentially Compromised Accounts</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {selectedRiskData.compromisedAccounts.map(({ user, profile }: any, index: number) => (
                      <div key={index} className="p-3 rounded-lg border bg-orange-50 border-orange-200">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-orange-800 truncate flex-1">{user}</span>
                          <Badge className="bg-orange-100 text-orange-800 ml-2">
                            {(profile.successRate * 100).toFixed(1)}% Success
                          </Badge>
                        </div>
                        <div className="text-xs text-orange-600">
                          <div>Total Events: {profile.totalSignins}</div>
                          <div>Failed: {profile.totalSignins - Math.round(profile.totalSignins * profile.successRate)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Impossible Travel */}
              {selectedRiskData.impossibleTravel.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-3 text-purple-800">Impossible Travel Detected</h4>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {selectedRiskData.impossibleTravel.map((travel: any, index: number) => (
                      <div key={index} className="p-3 rounded-lg border bg-purple-50 border-purple-200 text-sm">
                        <div className="font-medium text-purple-800 mb-1">{travel.user}</div>
                        <div className="text-xs text-purple-600">
                          {travel.location1} → {travel.location2} in {travel.timeDifference}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Suspicious Activity */}
              {selectedRiskData.suspiciousActivity.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-3 text-amber-800">Suspicious Activity</h4>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {selectedRiskData.suspiciousActivity.slice(0, 20).map((event: any, index: number) => (
                      <div key={index} className="p-3 rounded-lg border bg-amber-50 border-amber-200 text-sm">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium text-amber-800">
                            {event.userPrincipalName || event.userId || 'Unknown User'}
                          </span>
                          <Badge className="bg-amber-100 text-amber-800">
                            {event.riskDetail?.riskLevel || 'Suspicious'}
                          </Badge>
                        </div>
                        <div className="text-xs text-amber-600">
                          <div>IP: {event.ipAddress} | Location: {event.location?.city || 'Unknown'}</div>
                          {event.status?.failureReason && (
                            <div>Reason: {event.status.failureReason}</div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Success/Failure Distribution */}
        <Card className="cursor-pointer hover:shadow-lg transition-shadow" onClick={handleStatusClick}>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ChartBar className="w-5 h-5" />
                <span>Authentication Status</span>
              </div>
              <div className="flex items-center space-x-2">
                <Badge variant="outline">
                  {(summary.successRate * 100).toFixed(1)}% Success Rate
                </Badge>
                <Eye className="w-4 h-4 text-muted-foreground" />
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={statusData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                    style={{ cursor: 'pointer' }}
                  >
                    {statusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    formatter={(value: number) => [value.toLocaleString(), '']}
                    labelFormatter={(label) => `${label} Sign-ins`}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-4 mt-4">
              <div className="text-center p-3 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">
                  {summary.successfulSignins.toLocaleString()}
                </div>
                <div className="text-sm text-green-800">Successful</div>
              </div>
              <div className="text-center p-3 bg-red-50 rounded-lg">
                <div className="text-2xl font-bold text-red-600">
                  {summary.failedSignins.toLocaleString()}
                </div>
                <div className="text-sm text-red-800">Failed</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Hourly Activity Pattern */}
        <Card className="cursor-pointer hover:shadow-lg transition-shadow" onClick={() => {
          // Trigger click on the most active hour for demo
          const maxHour = hourlyData.reduce((max, hour) => hour.events > max.events ? hour : max, hourlyData[0])
          if (maxHour) {
            const mockPayload = { activePayload: [{ payload: maxHour }] }
            handleHourClick(mockPayload)
          }
        }}>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Clock className="w-5 h-5" />
                <span>Hourly Activity Pattern</span>
              </div>
              <Badge variant="outline" className="text-xs">
                <Eye className="w-3 h-3 mr-1" />
                Click for details
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={hourlyData} onClick={handleHourClick}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis 
                    dataKey="hour" 
                    className="text-muted-foreground text-xs"
                    tick={{ fontSize: 10 }}
                    interval={1}
                  />
                  <YAxis 
                    className="text-muted-foreground text-xs"
                    tick={{ fontSize: 12 }}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar 
                    dataKey="events" 
                    fill="#3B82F6" 
                    radius={[2, 2, 0, 0]} 
                    style={{ cursor: 'pointer' }}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-4 text-center">
              <p className="text-sm text-muted-foreground">
                Peak activity: {hourlyData.reduce((peak, current) => 
                  current.events > peak.events ? current : peak
                ).hour}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Additional Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Users by Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <DeviceMobile className="w-5 h-5" />
              <span>Most Active Users</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topUsersData} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis 
                    type="number"
                    className="text-muted-foreground text-xs"
                    tick={{ fontSize: 12 }}
                  />
                  <YAxis 
                    type="category"
                    dataKey="user" 
                    className="text-muted-foreground text-xs"
                    tick={{ fontSize: 10 }}
                    width={80}
                  />
                  <Tooltip 
                    formatter={(value: number, name: string) => [
                      name === 'events' ? `${value.toLocaleString()} events` : `${value}% success rate`,
                      name === 'events' ? 'Total Events' : 'Success Rate'
                    ]}
                  />
                  <Bar dataKey="events" fill="#6366F1" radius={[0, 2, 2, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Geographic Distribution */}
        <Card className="cursor-pointer hover:shadow-lg transition-shadow" onClick={() => {
          // Trigger click on the top country for demo
          const topCountry = countryData[0]
          if (topCountry) {
            const mockPayload = { activePayload: [{ payload: topCountry }] }
            handleCountryClick(mockPayload)
          }
        }}>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <GlobeHemisphereWest className="w-5 h-5" />
                <span>Geographic Distribution</span>
              </div>
              <Badge variant="outline" className="text-xs">
                <Eye className="w-3 h-3 mr-1" />
                Click for details
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={countryData} onClick={handleCountryClick}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis 
                    dataKey="country" 
                    className="text-muted-foreground text-xs"
                    tick={{ fontSize: 12 }}
                  />
                  <YAxis 
                    className="text-muted-foreground text-xs"
                    tick={{ fontSize: 12 }}
                  />
                  <Tooltip 
                    formatter={(value: number) => [`${value.toLocaleString()} events`, 'Events']}
                    labelFormatter={(label) => `Country: ${label}`}
                  />
                  <Bar 
                    dataKey="count" 
                    fill="#F59E0B" 
                    radius={[2, 2, 0, 0]} 
                    style={{ cursor: 'pointer' }}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-4">
              <div className="flex flex-wrap gap-2">
                {summary.topCountries.slice(0, 3).map((country, index) => (
                  <Badge key={country.country} variant="outline">
                    {country.country}: {((country.count / summary.totalEvents) * 100).toFixed(1)}%
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Indicators */}
      {(results.threats.length > 0 || Object.keys(userProfiles).some(user => 
        userProfiles[user].successRate < 0.5
      )) && (
        <Card className="border-amber-200 bg-amber-50 cursor-pointer hover:shadow-lg transition-shadow" onClick={handleRiskClick}>
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-amber-800">
              <div className="flex items-center space-x-2">
                <Warning className="w-5 h-5" />
                <span>Risk Indicators Detected</span>
              </div>
              <Eye className="w-4 h-4 text-amber-600" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-white rounded-lg border border-amber-200">
                <div className="text-2xl font-bold text-amber-600">
                  {results.threats.filter(t => t.severity === 'critical' || t.severity === 'high').length}
                </div>
                <div className="text-sm text-amber-800">High-Risk Threats</div>
              </div>
              <div className="text-center p-4 bg-white rounded-lg border border-amber-200">
                <div className="text-2xl font-bold text-amber-600">
                  {Object.values(userProfiles).filter(p => p.successRate < 0.5).length}
                </div>
                <div className="text-sm text-amber-800">Compromised Accounts</div>
              </div>
              <div className="text-center p-4 bg-white rounded-lg border border-amber-200">
                <div className="text-2xl font-bold text-amber-600">
                  {results.correlations.geographic.impossibleTravel.length}
                </div>
                <div className="text-sm text-amber-800">Impossible Travel</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}