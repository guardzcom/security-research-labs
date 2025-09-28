import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription } from '@/components/ui/alert'
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
  Clock, 
  MapPin, 
  NetworkX, 
  Brain,
  Warning,
  Info,
  Eye,
  Shield,
  Activity,
  Globe
} from '@phosphor-icons/react'
import { 
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell
} from 'recharts'
import type { AnalysisResults, ThreatIndicator, ImpossibleTravel } from '@/types/security'

interface CorrelationAnalysisProps {
  results: AnalysisResults
}

export function CorrelationAnalysis({ results }: CorrelationAnalysisProps) {
  const [selectedThreat, setSelectedThreat] = useState<ThreatIndicator | null>(null)
  const { correlations, threats, userProfiles } = results

  // Calculate correlation statistics
  const criticalThreats = threats.filter(t => t.severity === 'critical').length
  const suspiciousActivity = correlations.temporal.rapidSequences.length + 
                           correlations.geographic.impossibleTravel.length
  const impossibleTravelCount = correlations.geographic.impossibleTravel.length
  const correlationScore = Math.min(
    (criticalThreats * 25) + (suspiciousActivity * 10) + (impossibleTravelCount * 15), 
    100
  )

  // Prepare temporal analysis data
  const rapidSequenceData = correlations.temporal.rapidSequences.map((seq, index) => ({
    id: index,
    user: seq.user.split('@')[0] || seq.user,
    interval: seq.interval,
    riskLevel: seq.riskLevel,
    x: index,
    y: seq.interval
  }))

  // Prepare geographic data
  const impossibleTravelData = correlations.geographic.impossibleTravel.map((travel, index) => ({
    id: index,
    user: travel.user.split('@')[0] || travel.user,
    velocity: travel.velocity,
    distance: travel.distance,
    riskLevel: travel.riskLevel
  }))

  // Prepare infrastructure sharing data
  const sharedIPData = Object.entries(correlations.infrastructure.sharedIPs)
    .filter(([, data]) => data.count > 1)
    .map(([ip, data]) => ({
      ip: ip.endsWith('.0') ? ip.slice(0, -2) + '.*' : ip, // Mask last octet for privacy
      userCount: data.count,
      isPrivate: data.isPrivate,
      suspicious: data.suspiciousActivity
    }))
    .sort((a, b) => b.userCount - a.userCount)
    .slice(0, 10)

  // Prepare behavioral cluster data
  const clusterData = correlations.behavioral.clusters.map(cluster => ({
    id: cluster.id,
    threatType: cluster.threatType,
    userCount: cluster.users.length,
    users: cluster.users,
    riskScore: cluster.riskScore,
    ttps: cluster.ttps
  }))

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border border-border rounded-lg shadow-lg p-3 text-sm">
          <p className="font-medium">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  const ThreatDetailDialog = ({ threat }: { threat: ThreatIndicator }) => (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <Eye className="w-4 h-4 mr-1" />
          Details
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>{threat.type}</span>
          </DialogTitle>
          <DialogDescription>
            Threat analysis and correlation details
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium text-sm">Severity Level</h4>
              <Badge className={`mt-1 ${
                threat.severity === 'critical' ? 'bg-red-100 text-red-800' :
                threat.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                'bg-blue-100 text-blue-800'
              }`}>
                {threat.severity.toUpperCase()}
              </Badge>
            </div>
            <div>
              <h4 className="font-medium text-sm">Confidence</h4>
              <div className="mt-1 text-lg font-bold">
                {threat.confidence ? Math.round(threat.confidence * 100) : 'N/A'}%
              </div>
            </div>
          </div>
          
          <div>
            <h4 className="font-medium text-sm mb-2">Description</h4>
            <p className="text-sm text-muted-foreground bg-muted p-3 rounded-lg">
              {threat.description}
            </p>
          </div>

          {threat.user && (
            <div>
              <h4 className="font-medium text-sm mb-2">Affected User</h4>
              <Badge variant="outline">{threat.user}</Badge>
            </div>
          )}

          {threat.mitreAttack && threat.mitreAttack.length > 0 && (
            <div>
              <h4 className="font-medium text-sm mb-2">MITRE ATT&CK TTPs</h4>
              <div className="flex flex-wrap gap-2">
                {threat.mitreAttack.map(ttp => (
                  <Badge key={ttp} variant="secondary">{ttp}</Badge>
                ))}
              </div>
            </div>
          )}

          <div className="pt-4 border-t">
            <h4 className="font-medium text-sm mb-2">Recommended Actions</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Investigate user activity and verify legitimacy</li>
              <li>• Review authentication logs for similar patterns</li>
              <li>• Consider implementing additional security controls</li>
              <li>• Monitor for continued suspicious activity</li>
            </ul>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )

  return (
    <div className="space-y-6">
      {/* Correlation Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-red-800">Critical Threats</p>
                <p className="text-3xl font-bold text-red-600">{criticalThreats}</p>
                <p className="text-xs text-red-700 mt-1">Multi-vector attacks</p>
              </div>
              <Warning className="w-8 h-8 text-red-600" weight="fill" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-orange-200 bg-orange-50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-orange-800">Suspicious Activity</p>
                <p className="text-3xl font-bold text-orange-600">{suspiciousActivity}</p>
                <p className="text-xs text-orange-700 mt-1">Anomalous patterns</p>
              </div>
              <Activity className="w-8 h-8 text-orange-600" weight="fill" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-blue-200 bg-blue-50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-blue-800">Impossible Travel</p>
                <p className="text-3xl font-bold text-blue-600">{impossibleTravelCount}</p>
                <p className="text-xs text-blue-700 mt-1">Geographic anomalies</p>
              </div>
              <Globe className="w-8 h-8 text-blue-600" weight="fill" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-purple-200 bg-purple-50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-purple-800">Correlation Score</p>
                <p className="text-3xl font-bold text-purple-600">{correlationScore}</p>
                <p className="text-xs text-purple-700 mt-1">Risk multiplier</p>
              </div>
              <Brain className="w-8 h-8 text-purple-600" weight="fill" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Correlation Analysis Tabs */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <NetworkX className="w-5 h-5" />
            <span>Advanced Correlation Analysis</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="temporal" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="temporal" className="flex items-center space-x-2">
                <Clock className="w-4 h-4" />
                <span>Temporal</span>
              </TabsTrigger>
              <TabsTrigger value="geographic" className="flex items-center space-x-2">
                <MapPin className="w-4 h-4" />
                <span>Geographic</span>
              </TabsTrigger>
              <TabsTrigger value="infrastructure" className="flex items-center space-x-2">
                <NetworkX className="w-4 h-4" />
                <span>Infrastructure</span>
              </TabsTrigger>
              <TabsTrigger value="behavioral" className="flex items-center space-x-2">
                <Brain className="w-4 h-4" />
                <span>Behavioral</span>
              </TabsTrigger>
            </TabsList>

            {/* Temporal Analysis */}
            <TabsContent value="temporal" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Rapid Authentication Sequences</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {rapidSequenceData.length > 0 ? (
                      <div className="space-y-3">
                        {rapidSequenceData.slice(0, 5).map((seq) => (
                          <Dialog key={seq.id}>
                            <DialogTrigger asChild>
                              <div className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${
                                seq.riskLevel === 'critical' ? 'bg-red-50 border-red-200 hover:bg-red-100' :
                                seq.riskLevel === 'high' ? 'bg-orange-50 border-orange-200 hover:bg-orange-100' :
                                'bg-yellow-50 border-yellow-200 hover:bg-yellow-100'
                              }`}>
                                <div>
                                  <div className="font-medium text-sm">{seq.user}</div>
                                  <div className="text-xs text-muted-foreground">
                                    {seq.interval.toFixed(1)}s between attempts
                                  </div>
                                </div>
                                <Badge className={
                                  seq.riskLevel === 'critical' ? 'bg-red-100 text-red-800' :
                                  seq.riskLevel === 'high' ? 'bg-orange-100 text-orange-800' :
                                  'bg-yellow-100 text-yellow-800'
                                }>
                                  {seq.riskLevel.toUpperCase()}
                                </Badge>
                              </div>
                            </DialogTrigger>
                            <DialogContent className="max-w-3xl">
                              <DialogHeader>
                                <DialogTitle className="flex items-center space-x-2">
                                  <Clock className="w-5 h-5" />
                                  <span>Rapid Authentication Sequence - {seq.user}</span>
                                </DialogTitle>
                                <DialogDescription>
                                  Detailed analysis of suspicious rapid authentication attempts
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-3 gap-4">
                                  <div className="text-center p-4 bg-blue-50 rounded-lg">
                                    <div className="text-2xl font-bold text-blue-600">{seq.interval.toFixed(1)}s</div>
                                    <div className="text-sm text-blue-800">Avg Interval</div>
                                  </div>
                                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                                    <div className="text-2xl font-bold text-orange-600">{seq.riskLevel.toUpperCase()}</div>
                                    <div className="text-sm text-orange-800">Risk Level</div>
                                  </div>
                                  <div className="text-center p-4 bg-purple-50 rounded-lg">
                                    <div className="text-2xl font-bold text-purple-600">#{seq.id + 1}</div>
                                    <div className="text-sm text-purple-800">Sequence ID</div>
                                  </div>
                                </div>

                                <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg">
                                  <h4 className="font-medium text-amber-800 mb-2">Risk Analysis</h4>
                                  <p className="text-sm text-amber-700">
                                    This user shows abnormally rapid authentication attempts ({seq.interval.toFixed(1)} seconds between attempts), 
                                    which may indicate automated tools, brute force attacks, or credential stuffing attempts.
                                  </p>
                                </div>

                                <div className="pt-4 border-t">
                                  <h4 className="font-medium text-sm mb-2">Recommended Actions</h4>
                                  <ul className="text-sm text-muted-foreground space-y-1">
                                    <li>• Investigate user account for signs of compromise</li>
                                    <li>• Review authentication logs for this user</li>
                                    <li>• Consider implementing rate limiting or account lockout policies</li>
                                    <li>• Verify user identity and force password reset if necessary</li>
                                  </ul>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        ))}
                        {rapidSequenceData.length === 0 && (
                          <p className="text-sm text-muted-foreground text-center py-4">
                            No rapid sequences detected
                          </p>
                        )}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No rapid authentication sequences detected
                      </p>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Brute Force Patterns</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {correlations.temporal.bruteForceAttempts.length > 0 ? (
                      <div className="space-y-3">
                        {correlations.temporal.bruteForceAttempts.slice(0, 5).map((attempt, index) => (
                          <Dialog key={index}>
                            <DialogTrigger asChild>
                              <div className="flex items-center justify-between p-3 bg-red-50 border border-red-200 rounded-lg cursor-pointer hover:shadow-md transition-all hover:bg-red-100">
                                <div>
                                  <div className="font-medium text-sm text-red-800">
                                    {attempt.user.split('@')[0] || attempt.user}
                                  </div>
                                  <div className="text-xs text-red-600">
                                    {attempt.attempts} attempts over {attempt.timespan.toFixed(1)}h
                                  </div>
                                </div>
                                <Badge variant="destructive">{attempt.uniqueIPs} IPs</Badge>
                              </div>
                            </DialogTrigger>
                            <DialogContent className="max-w-3xl">
                              <DialogHeader>
                                <DialogTitle className="flex items-center space-x-2">
                                  <Warning className="w-5 h-5 text-red-600" />
                                  <span>Brute Force Attack - {attempt.user}</span>
                                </DialogTitle>
                                <DialogDescription>
                                  Detailed analysis of suspected brute force authentication attempts
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-3 gap-4">
                                  <div className="text-center p-4 bg-red-50 rounded-lg">
                                    <div className="text-2xl font-bold text-red-600">{attempt.attempts}</div>
                                    <div className="text-sm text-red-800">Total Attempts</div>
                                  </div>
                                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                                    <div className="text-2xl font-bold text-orange-600">{attempt.timespan.toFixed(1)}h</div>
                                    <div className="text-sm text-orange-800">Time Span</div>
                                  </div>
                                  <div className="text-center p-4 bg-purple-50 rounded-lg">
                                    <div className="text-2xl font-bold text-purple-600">{attempt.uniqueIPs}</div>
                                    <div className="text-sm text-purple-800">Unique IPs</div>
                                  </div>
                                </div>

                                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                                  <h4 className="font-medium text-red-800 mb-2">Critical Alert</h4>
                                  <p className="text-sm text-red-700">
                                    This user account has experienced {attempt.attempts} authentication attempts from {attempt.uniqueIPs} different 
                                    IP addresses over {attempt.timespan.toFixed(1)} hours. This pattern is highly indicative of a brute force attack.
                                  </p>
                                </div>

                                <div className="pt-4 border-t">
                                  <h4 className="font-medium text-sm mb-2">Immediate Actions Required</h4>
                                  <ul className="text-sm text-muted-foreground space-y-1">
                                    <li>• <strong>Immediately lock the affected user account</strong></li>
                                    <li>• Block the attacking IP addresses at firewall level</li>
                                    <li>• Force password reset for the user</li>
                                    <li>• Enable MFA if not already configured</li>
                                    <li>• Review account for signs of successful compromise</li>
                                    <li>• Investigate other accounts for similar patterns</li>
                                  </ul>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No brute force patterns detected
                      </p>
                    )}
                  </CardContent>
                </Card>
              </div>

              {rapidSequenceData.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Authentication Velocity Analysis</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <ScatterChart data={rapidSequenceData}>
                          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                          <XAxis 
                            type="number"
                            dataKey="x"
                            name="Sequence"
                            className="text-muted-foreground text-xs"
                          />
                          <YAxis 
                            type="number"
                            dataKey="y"
                            name="Interval (seconds)"
                            className="text-muted-foreground text-xs"
                          />
                          <Tooltip content={<CustomTooltip />} />
                          <Scatter 
                            name="Rapid Sequences" 
                            data={rapidSequenceData} 
                            fill="#EF4444"
                          />
                        </ScatterChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            {/* Geographic Analysis */}
            <TabsContent value="geographic" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Impossible Travel Incidents</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {impossibleTravelData.length > 0 ? (
                      <div className="space-y-3">
                        {impossibleTravelData.map((travel, index) => (
                          <Dialog key={index}>
                            <DialogTrigger asChild>
                              <div className={`p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${
                                travel.riskLevel === 'critical' ? 'bg-red-50 border-red-200 hover:bg-red-100' :
                                'bg-orange-50 border-orange-200 hover:bg-orange-100'
                              }`}>
                                <div className="flex items-center justify-between mb-2">
                                  <div className="font-medium text-sm">{travel.user}</div>
                                  <Badge className={
                                    travel.riskLevel === 'critical' ? 'bg-red-100 text-red-800' :
                                    'bg-orange-100 text-orange-800'
                                  }>
                                    {travel.riskLevel.toUpperCase()}
                                  </Badge>
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {travel.distance}km in {travel.velocity} km/h
                                </div>
                              </div>
                            </DialogTrigger>
                            <DialogContent className="max-w-3xl">
                              <DialogHeader>
                                <DialogTitle className="flex items-center space-x-2">
                                  <Globe className="w-5 h-5 text-red-600" />
                                  <span>Impossible Travel Detected - {travel.user}</span>
                                </DialogTitle>
                                <DialogDescription>
                                  Analysis of geographically impossible authentication sequence
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-3 gap-4">
                                  <div className="text-center p-4 bg-blue-50 rounded-lg">
                                    <div className="text-2xl font-bold text-blue-600">{travel.distance}km</div>
                                    <div className="text-sm text-blue-800">Distance</div>
                                  </div>
                                  <div className="text-center p-4 bg-red-50 rounded-lg">
                                    <div className="text-2xl font-bold text-red-600">{travel.velocity} km/h</div>
                                    <div className="text-sm text-red-800">Required Speed</div>
                                  </div>
                                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                                    <div className="text-2xl font-bold text-orange-600">{travel.riskLevel.toUpperCase()}</div>
                                    <div className="text-sm text-orange-800">Risk Level</div>
                                  </div>
                                </div>

                                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                                  <h4 className="font-medium text-red-800 mb-2">Impossible Travel Alert</h4>
                                  <p className="text-sm text-red-700">
                                    User authentication detected {travel.distance}km apart, requiring travel at {travel.velocity} km/h. 
                                    This is physically impossible and indicates potential account compromise or credential sharing.
                                  </p>
                                </div>

                                <div className="pt-4 border-t">
                                  <h4 className="font-medium text-sm mb-2">Immediate Investigation Required</h4>
                                  <ul className="text-sm text-muted-foreground space-y-1">
                                    <li>• Verify user's actual location and travel history</li>
                                    <li>• Check for VPN or proxy usage that might explain the discrepancy</li>
                                    <li>• Force password reset and enable MFA immediately</li>
                                    <li>• Review all recent account activity for other compromise indicators</li>
                                    <li>• Consider temporarily disabling the account pending investigation</li>
                                    <li>• Look for similar patterns in other user accounts</li>
                                  </ul>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No impossible travel detected
                      </p>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Country Transitions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {Object.keys(correlations.geographic.countryTransitions).length > 0 ? (
                      <div className="space-y-2">
                        {Object.entries(correlations.geographic.countryTransitions)
                          .sort(([,a], [,b]) => b - a)
                          .slice(0, 6)
                          .map(([transition, count]) => (
                            <div key={transition} className="flex items-center justify-between p-2 bg-muted rounded">
                              <span className="text-sm font-medium">{transition}</span>
                              <Badge variant="outline">{count}</Badge>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No country transitions detected
                      </p>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            {/* Infrastructure Analysis */}
            <TabsContent value="infrastructure" className="space-y-6">
              {/* Infrastructure Overview Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="border-blue-200 bg-blue-50">
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-blue-800">Unique IPs</p>
                        <p className="text-2xl font-bold text-blue-600">
                          {Object.keys(correlations.infrastructure.sharedIPs).length}
                        </p>
                        <p className="text-xs text-blue-700 mt-1">Network sources</p>
                      </div>
                      <NetworkX className="w-6 h-6 text-blue-600" weight="fill" />
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-purple-200 bg-purple-50">
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-purple-800">Device Types</p>
                        <p className="text-2xl font-bold text-purple-600">
                          {Object.keys(correlations.infrastructure.deviceTypes || {}).length}
                        </p>
                        <p className="text-xs text-purple-700 mt-1">Hardware variety</p>
                      </div>
                      <Activity className="w-6 h-6 text-purple-600" weight="fill" />
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-green-200 bg-green-50">
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-green-800">Browser Types</p>
                        <p className="text-2xl font-bold text-green-600">
                          {Object.keys(correlations.infrastructure.browserTypes || {}).length}
                        </p>
                        <p className="text-xs text-green-700 mt-1">Client diversity</p>
                      </div>
                      <Globe className="w-6 h-6 text-green-600" weight="fill" />
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-orange-200 bg-orange-50">
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-orange-800">Suspicious IPs</p>
                        <p className="text-2xl font-bold text-orange-600">
                          {Object.values(correlations.infrastructure.sharedIPs).filter(ip => ip.suspiciousActivity).length}
                        </p>
                        <p className="text-xs text-orange-700 mt-1">Risk indicators</p>
                      </div>
                      <Warning className="w-6 h-6 text-orange-600" weight="fill" />
                    </div>
                  </CardContent>
                </Card>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Enhanced Shared IP Analysis */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center space-x-2">
                      <NetworkX className="w-4 h-4" />
                      <span>Network Infrastructure Analysis</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {sharedIPData.length > 0 ? (
                      <div className="space-y-3">
                        {sharedIPData.map((ip, index) => (
                          <Dialog key={index}>
                            <DialogTrigger asChild>
                              <div className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${
                                ip.suspicious ? 'bg-red-50 border-red-200 hover:bg-red-100' :
                                ip.isPrivate ? 'bg-green-50 border-green-200 hover:bg-green-100' :
                                'bg-yellow-50 border-yellow-200 hover:bg-yellow-100'
                              }`}>
                                <div className="flex-1">
                                  <div className="font-mono text-sm font-medium">{ip.ip}</div>
                                  <div className="text-xs text-muted-foreground flex items-center space-x-2">
                                    <span>{ip.isPrivate ? 'Private Network' : 'Public IP'}</span>
                                    {ip.suspicious && (
                                      <Badge variant="destructive" className="text-xs px-1 py-0">SUSPICIOUS</Badge>
                                    )}
                                  </div>
                                </div>
                                <div className="text-right">
                                  <Badge className={
                                    ip.suspicious ? 'bg-red-100 text-red-800' :
                                    ip.isPrivate ? 'bg-green-100 text-green-800' :
                                    'bg-yellow-100 text-yellow-800'
                                  }>
                                    {ip.userCount} users
                                  </Badge>
                                </div>
                              </div>
                            </DialogTrigger>
                            <DialogContent className="max-w-3xl">
                              <DialogHeader>
                                <DialogTitle className="flex items-center space-x-2">
                                  <NetworkX className="w-5 h-5" />
                                  <span>Infrastructure Analysis - {ip.ip}</span>
                                </DialogTitle>
                                <DialogDescription>
                                  Detailed network infrastructure and security analysis for this IP address
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-3 gap-4">
                                  <div className="text-center p-4 bg-blue-50 rounded-lg">
                                    <div className="text-2xl font-bold text-blue-600">{ip.userCount}</div>
                                    <div className="text-sm text-blue-800">Connected Users</div>
                                  </div>
                                  <div className="text-center p-4 bg-purple-50 rounded-lg">
                                    <div className="text-2xl font-bold text-purple-600">{ip.isPrivate ? 'Private' : 'Public'}</div>
                                    <div className="text-sm text-purple-800">Network Type</div>
                                  </div>
                                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                                    <div className="text-2xl font-bold text-orange-600">{ip.suspicious ? 'HIGH' : 'LOW'}</div>
                                    <div className="text-sm text-orange-800">Risk Level</div>
                                  </div>
                                </div>

                                <div className={`p-4 rounded-lg border ${
                                  ip.suspicious ? 'bg-red-50 border-red-200' :
                                  ip.isPrivate ? 'bg-green-50 border-green-200' :
                                  'bg-blue-50 border-blue-200'
                                }`}>
                                  <h4 className={`font-medium mb-2 ${
                                    ip.suspicious ? 'text-red-800' :
                                    ip.isPrivate ? 'text-green-800' :
                                    'text-blue-800'
                                  }`}>Network Assessment</h4>
                                  <p className={`text-sm ${
                                    ip.suspicious ? 'text-red-700' :
                                    ip.isPrivate ? 'text-green-700' :
                                    'text-blue-700'
                                  }`}>
                                    {ip.suspicious 
                                      ? `This IP address shows suspicious activity patterns and is used by ${ip.userCount} users. It may be associated with malicious infrastructure, compromised networks, or unauthorized access attempts.`
                                      : ip.isPrivate 
                                        ? `This is a private network IP address (RFC 1918) shared by ${ip.userCount} users, likely indicating a corporate network, VPN, or internal infrastructure. This is generally considered normal behavior.`
                                        : `This public IP address is shared by ${ip.userCount} users, which could indicate a shared internet connection, proxy server, or public WiFi network. Monitor for unusual activity patterns.`
                                    }
                                  </p>
                                </div>

                                <div>
                                  <h4 className="font-medium text-sm mb-2">Infrastructure Characteristics</h4>
                                  <div className="grid grid-cols-2 gap-4">
                                    <div className="space-y-2">
                                      <div className="flex items-center justify-between text-sm">
                                        <span>IP Address:</span>
                                        <code className="bg-muted px-2 py-1 rounded text-xs">{ip.ip}</code>
                                      </div>
                                      <div className="flex items-center justify-between text-sm">
                                        <span>Network Type:</span>
                                        <Badge variant={ip.isPrivate ? 'secondary' : 'outline'}>
                                          {ip.isPrivate ? 'Private' : 'Public'}
                                        </Badge>
                                      </div>
                                      <div className="flex items-center justify-between text-sm">
                                        <span>User Count:</span>
                                        <Badge variant="outline">{ip.userCount}</Badge>
                                      </div>
                                    </div>
                                    <div className="space-y-2">
                                      <div className="flex items-center justify-between text-sm">
                                        <span>Risk Level:</span>
                                        <Badge className={ip.suspicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}>
                                          {ip.suspicious ? 'High Risk' : 'Low Risk'}
                                        </Badge>
                                      </div>
                                      <div className="flex items-center justify-between text-sm">
                                        <span>Suspicious Activity:</span>
                                        <Badge variant={ip.suspicious ? 'destructive' : 'secondary'}>
                                          {ip.suspicious ? 'Detected' : 'None'}
                                        </Badge>
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                <div className="pt-4 border-t">
                                  <h4 className="font-medium text-sm mb-2">Security Recommendations</h4>
                                  <ul className="text-sm text-muted-foreground space-y-1">
                                    {ip.suspicious ? (
                                      <>
                                        <li>• <strong>Immediate:</strong> Block or monitor this IP address closely</li>
                                        <li>• <strong>Investigation:</strong> Review all authentication attempts from this IP</li>
                                        <li>• <strong>User Verification:</strong> Verify legitimacy of all users from this IP</li>
                                        <li>• <strong>Threat Intelligence:</strong> Check IP against threat intelligence feeds</li>
                                        <li>• <strong>Monitoring:</strong> Implement real-time alerting for future activity</li>
                                      </>
                                    ) : ip.isPrivate ? (
                                      <>
                                        <li>• Monitor for unusual activity patterns within the private network</li>
                                        <li>• Verify that network segmentation is properly implemented</li>
                                        <li>• Ensure proper access controls are in place for internal resources</li>
                                        <li>• Regular security audits of the internal network infrastructure</li>
                                      </>
                                    ) : (
                                      <>
                                        <li>• Monitor for unusual spikes in user count or activity</li>
                                        <li>• Implement geolocation checks for this IP address</li>
                                        <li>• Consider additional authentication for shared public IPs</li>
                                        <li>• Regular review of activity patterns from this source</li>
                                      </>
                                    )}
                                  </ul>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No shared IP addresses detected
                      </p>
                    )}
                  </CardContent>
                </Card>

                {/* Device and Browser Analysis */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center space-x-2">
                      <Activity className="w-4 h-4" />
                      <span>Client Environment Analysis</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {/* Device Types */}
                      <div>
                        <h4 className="font-medium text-sm mb-2 flex items-center space-x-2">
                          <Activity className="w-3 h-3" />
                          <span>Device Types Distribution</span>
                        </h4>
                        {Object.keys(correlations.infrastructure.deviceTypes || {}).length > 0 ? (
                          <div className="space-y-2">
                            {Object.entries(correlations.infrastructure.deviceTypes || {})
                              .sort(([,a], [,b]) => (b as any).count - (a as any).count)
                              .slice(0, 5)
                              .map(([device, data]: [string, any]) => (
                                <div key={device} className="flex items-center justify-between p-2 bg-muted rounded-lg">
                                  <div className="flex items-center space-x-2">
                                    <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                                    <span className="text-sm font-medium capitalize">{device}</span>
                                    {data.suspicious && (
                                      <Badge variant="destructive" className="text-xs px-1 py-0">SUSPICIOUS</Badge>
                                    )}
                                  </div>
                                  <div className="flex items-center space-x-2">
                                    <Badge variant="outline">{data.count} users</Badge>
                                    <Badge variant="secondary">{((data.count / results.summary.uniqueUsers) * 100).toFixed(1)}%</Badge>
                                  </div>
                                </div>
                              ))}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground bg-muted p-3 rounded-lg">
                            Device type information not available in current log data
                          </p>
                        )}
                      </div>

                      {/* Browser Types */}
                      <div>
                        <h4 className="font-medium text-sm mb-2 flex items-center space-x-2">
                          <Globe className="w-3 h-3" />
                          <span>Browser Distribution</span>
                        </h4>
                        {Object.keys(correlations.infrastructure.browserTypes || {}).length > 0 ? (
                          <div className="space-y-2">
                            {Object.entries(correlations.infrastructure.browserTypes || {})
                              .sort(([,a], [,b]) => (b as any).count - (a as any).count)
                              .slice(0, 5)
                              .map(([browser, data]: [string, any]) => (
                                <div key={browser} className="flex items-center justify-between p-2 bg-muted rounded-lg">
                                  <div className="flex items-center space-x-2">
                                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                                    <span className="text-sm font-medium">{browser}</span>
                                    {data.suspicious && (
                                      <Badge variant="destructive" className="text-xs px-1 py-0">SUSPICIOUS</Badge>
                                    )}
                                  </div>
                                  <div className="flex items-center space-x-2">
                                    <Badge variant="outline">{data.count} users</Badge>
                                    <Badge variant="secondary">{((data.count / results.summary.uniqueUsers) * 100).toFixed(1)}%</Badge>
                                  </div>
                                </div>
                              ))}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground bg-muted p-3 rounded-lg">
                            Browser information not available in current log data
                          </p>
                        )}
                      </div>

                      {/* Operating Systems */}
                      <div>
                        <h4 className="font-medium text-sm mb-2 flex items-center space-x-2">
                          <Shield className="w-3 h-3" />
                          <span>Operating System Analysis</span>
                        </h4>
                        {Object.keys(correlations.infrastructure.operatingSystems || {}).length > 0 ? (
                          <div className="space-y-2">
                            {Object.entries(correlations.infrastructure.operatingSystems || {})
                              .sort(([,a], [,b]) => (b as any).count - (a as any).count)
                              .slice(0, 5)
                              .map(([os, data]: [string, any]) => (
                                <div key={os} className="flex items-center justify-between p-2 bg-muted rounded-lg">
                                  <div className="flex items-center space-x-2">
                                    <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
                                    <span className="text-sm font-medium">{os}</span>
                                    {data.outdated && (
                                      <Badge variant="destructive" className="text-xs px-1 py-0">OUTDATED</Badge>
                                    )}
                                  </div>
                                  <div className="flex items-center space-x-2">
                                    <Badge variant="outline">{data.count} users</Badge>
                                    <Badge variant="secondary">{((data.count / results.summary.uniqueUsers) * 100).toFixed(1)}%</Badge>
                                  </div>
                                </div>
                              ))}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground bg-muted p-3 rounded-lg">
                            Operating system information not available in current log data
                          </p>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Infrastructure Risk Chart */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center space-x-2">
                    <NetworkX className="w-4 h-4" />
                    <span>Infrastructure Risk Distribution</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={sharedIPData.slice(0, 8)}>
                          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                          <XAxis 
                            dataKey="ip" 
                            className="text-muted-foreground text-xs"
                            tick={{ fontSize: 10 }}
                          />
                          <YAxis 
                            className="text-muted-foreground text-xs"
                            tick={{ fontSize: 12 }}
                          />
                          <Tooltip content={<CustomTooltip />} />
                          <Bar 
                            dataKey="userCount" 
                            fill="#F59E0B" 
                            radius={[2, 2, 0, 0]}
                            name="User Count"
                          />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    
                    <div className="space-y-4">
                      <div className="text-center p-4 border rounded-lg">
                        <h4 className="font-medium text-sm mb-2">Infrastructure Security Summary</h4>
                        <div className="grid grid-cols-2 gap-4 text-xs">
                          <div>
                            <div className="text-2xl font-bold text-blue-600">
                              {Object.keys(correlations.infrastructure.sharedIPs).length}
                            </div>
                            <div className="text-muted-foreground">Total IPs</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-red-600">
                              {Object.values(correlations.infrastructure.sharedIPs).filter(ip => ip.suspiciousActivity).length}
                            </div>
                            <div className="text-muted-foreground">Suspicious</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-green-600">
                              {Object.values(correlations.infrastructure.sharedIPs).filter(ip => ip.isPrivate).length}
                            </div>
                            <div className="text-muted-foreground">Private</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-orange-600">
                              {Math.round((Object.values(correlations.infrastructure.sharedIPs).filter(ip => ip.suspiciousActivity).length / Object.keys(correlations.infrastructure.sharedIPs).length) * 100) || 0}%
                            </div>
                            <div className="text-muted-foreground">Risk Ratio</div>
                          </div>
                        </div>
                      </div>

                      <Alert>
                        <Info className="h-4 w-4" />
                        <AlertDescription className="text-sm">
                          <strong>Infrastructure Analysis:</strong> Based on current log data, 
                          {Object.values(correlations.infrastructure.sharedIPs).filter(ip => ip.suspiciousActivity).length > 0 
                            ? ` ${Object.values(correlations.infrastructure.sharedIPs).filter(ip => ip.suspiciousActivity).length} suspicious IP addresses have been identified requiring immediate attention.`
                            : ' no immediate infrastructure threats have been detected, but continuous monitoring is recommended.'
                          }
                        </AlertDescription>
                      </Alert>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Behavioral Analysis */}
            <TabsContent value="behavioral" className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Behavioral Clusters</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {clusterData.length > 0 ? (
                      <div className="space-y-3">
                        {clusterData.map((cluster) => (
                          <Dialog key={cluster.id}>
                            <DialogTrigger asChild>
                              <div className={`p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${
                                cluster.riskScore > 70 ? 'bg-red-50 border-red-200 hover:bg-red-100' :
                                cluster.riskScore > 40 ? 'bg-orange-50 border-orange-200 hover:bg-orange-100' :
                                'bg-green-50 border-green-200 hover:bg-green-100'
                              }`}>
                                <div className="flex items-center justify-between mb-2">
                                  <div className="font-medium text-sm">{cluster.threatType}</div>
                                  <Badge className={
                                    cluster.riskScore > 70 ? 'bg-red-100 text-red-800' :
                                    cluster.riskScore > 40 ? 'bg-orange-100 text-orange-800' :
                                    'bg-green-100 text-green-800'
                                  }>
                                    Risk: {cluster.riskScore}
                                  </Badge>
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {cluster.userCount} users • {cluster.ttps.length} TTPs identified
                                </div>
                              </div>
                            </DialogTrigger>
                            <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                              <DialogHeader>
                                <DialogTitle className="flex items-center space-x-2">
                                  <Brain className="w-5 h-5" />
                                  <span>Behavioral Cluster Analysis - {cluster.threatType}</span>
                                </DialogTitle>
                                <DialogDescription>
                                  Detailed analysis of behavioral patterns and threat indicators for this cluster
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-3 gap-4">
                                  <div className="text-center p-4 bg-blue-50 rounded-lg">
                                    <div className="text-2xl font-bold text-blue-600">{cluster.userCount}</div>
                                    <div className="text-sm text-blue-800">Affected Users</div>
                                  </div>
                                  <div className="text-center p-4 bg-purple-50 rounded-lg">
                                    <div className="text-2xl font-bold text-purple-600">{cluster.riskScore}</div>
                                    <div className="text-sm text-purple-800">Risk Score</div>
                                  </div>
                                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                                    <div className="text-2xl font-bold text-orange-600">{cluster.ttps.length}</div>
                                    <div className="text-sm text-orange-800">TTPs Identified</div>
                                  </div>
                                </div>

                                <div className={`p-4 rounded-lg border ${
                                  cluster.riskScore > 70 ? 'bg-red-50 border-red-200' :
                                  cluster.riskScore > 40 ? 'bg-orange-50 border-orange-200' :
                                  'bg-green-50 border-green-200'
                                }`}>
                                  <h4 className={`font-medium mb-2 ${
                                    cluster.riskScore > 70 ? 'text-red-800' :
                                    cluster.riskScore > 40 ? 'text-orange-800' :
                                    'text-green-800'
                                  }`}>Cluster Analysis</h4>
                                  <p className={`text-sm ${
                                    cluster.riskScore > 70 ? 'text-red-700' :
                                    cluster.riskScore > 40 ? 'text-orange-700' :
                                    'text-green-700'
                                  }`}>
                                    This behavioral cluster represents a group of {cluster.userCount} users exhibiting similar authentication patterns 
                                    associated with "{cluster.threatType}". The cluster has been assigned a risk score of {cluster.riskScore} based on 
                                    the severity and frequency of suspicious activities.
                                  </p>
                                </div>

                                {cluster.ttps.length > 0 && (
                                  <div>
                                    <h4 className="font-medium text-sm mb-2">MITRE ATT&CK Tactics, Techniques & Procedures</h4>
                                    <div className="grid grid-cols-2 gap-2">
                                      {cluster.ttps.map(ttp => (
                                        <Badge key={ttp} variant="outline" className="justify-center">{ttp}</Badge>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                <div>
                                  <h4 className="font-medium text-sm mb-2">Affected Users</h4>
                                  <div className="grid grid-cols-3 gap-2 max-h-32 overflow-y-auto">
                                    {cluster.users.slice(0, 12).map(user => (
                                      <Badge key={user} variant="secondary" className="text-xs justify-center">
                                        {user.split('@')[0] || user}
                                      </Badge>
                                    ))}
                                    {cluster.users.length > 12 && (
                                      <Badge variant="outline" className="text-xs justify-center">
                                        +{cluster.users.length - 12} more
                                      </Badge>
                                    )}
                                  </div>
                                </div>

                                <div className="pt-4 border-t">
                                  <h4 className="font-medium text-sm mb-2">Risk Assessment & Recommendations</h4>
                                  <div className="space-y-2">
                                    {cluster.riskScore > 70 ? (
                                      <ul className="text-sm text-red-700 space-y-1">
                                        <li>• <strong>High Risk Cluster:</strong> Immediate investigation and containment required</li>
                                        <li>• <strong>User Isolation:</strong> Consider temporarily disabling accounts pending investigation</li>
                                        <li>• <strong>Forensic Analysis:</strong> Conduct detailed log analysis for all cluster members</li>
                                        <li>• <strong>Incident Response:</strong> Activate incident response procedures</li>
                                      </ul>
                                    ) : cluster.riskScore > 40 ? (
                                      <ul className="text-sm text-orange-700 space-y-1">
                                        <li>• <strong>Medium Risk Cluster:</strong> Enhanced monitoring and investigation needed</li>
                                        <li>• <strong>Access Review:</strong> Verify legitimacy of user activities</li>
                                        <li>• <strong>Security Controls:</strong> Implement additional authentication requirements</li>
                                        <li>• <strong>User Training:</strong> Consider security awareness training for affected users</li>
                                      </ul>
                                    ) : (
                                      <ul className="text-sm text-green-700 space-y-1">
                                        <li>• <strong>Low Risk Cluster:</strong> Baseline monitoring recommended</li>
                                        <li>• <strong>Policy Review:</strong> Ensure authentication policies are appropriate</li>
                                        <li>• <strong>Continuous Monitoring:</strong> Track for any escalation in risk score</li>
                                        <li>• <strong>Documentation:</strong> Log findings for trend analysis</li>
                                      </ul>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No behavioral clusters detected
                      </p>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Privilege Escalation</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {correlations.behavioral.privilegeEscalation.length > 0 ? (
                      <div className="space-y-3">
                        {correlations.behavioral.privilegeEscalation.map((escalation, index) => (
                          <Dialog key={index}>
                            <DialogTrigger asChild>
                              <div className={`p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${
                                escalation.riskLevel === 'high' ? 'bg-red-50 border-red-200 hover:bg-red-100' :
                                'bg-orange-50 border-orange-200 hover:bg-orange-100'
                              }`}>
                                <div className="flex items-center justify-between mb-2">
                                  <div className="font-medium text-sm">{escalation.user.split('@')[0] || escalation.user}</div>
                                  <Badge className={
                                    escalation.riskLevel === 'high' ? 'bg-red-100 text-red-800' :
                                    'bg-orange-100 text-orange-800'
                                  }>
                                    {escalation.riskLevel.toUpperCase()}
                                  </Badge>
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {escalation.escalationType} • {escalation.attempts} attempts
                                </div>
                              </div>
                            </DialogTrigger>
                            <DialogContent className="max-w-3xl">
                              <DialogHeader>
                                <DialogTitle className="flex items-center space-x-2">
                                  <Shield className="w-5 h-5 text-orange-600" />
                                  <span>Privilege Escalation Analysis - {escalation.user}</span>
                                </DialogTitle>
                                <DialogDescription>
                                  Detailed analysis of privilege escalation attempts and security implications
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-3 gap-4">
                                  <div className="text-center p-4 bg-red-50 rounded-lg">
                                    <div className="text-2xl font-bold text-red-600">{escalation.attempts}</div>
                                    <div className="text-sm text-red-800">Total Attempts</div>
                                  </div>
                                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                                    <div className="text-2xl font-bold text-orange-600">{(escalation.successRate * 100).toFixed(1)}%</div>
                                    <div className="text-sm text-orange-800">Success Rate</div>
                                  </div>
                                  <div className="text-center p-4 bg-purple-50 rounded-lg">
                                    <div className="text-2xl font-bold text-purple-600">{escalation.riskLevel.toUpperCase()}</div>
                                    <div className="text-sm text-purple-800">Risk Level</div>
                                  </div>
                                </div>

                                <div className={`p-4 rounded-lg border ${
                                  escalation.riskLevel === 'high' ? 'bg-red-50 border-red-200' :
                                  'bg-orange-50 border-orange-200'
                                }`}>
                                  <h4 className={`font-medium mb-2 ${
                                    escalation.riskLevel === 'high' ? 'text-red-800' :
                                    'text-orange-800'
                                  }`}>Privilege Escalation Analysis</h4>
                                  <p className={`text-sm ${
                                    escalation.riskLevel === 'high' ? 'text-red-700' :
                                    'text-orange-700'
                                  }`}>
                                    User {escalation.user} has attempted {escalation.escalationType} privilege escalation {escalation.attempts} times 
                                    with a success rate of {(escalation.successRate * 100).toFixed(1)}%. This pattern indicates potential 
                                    unauthorized attempts to gain elevated access rights.
                                  </p>
                                </div>

                                <div>
                                  <h4 className="font-medium text-sm mb-2">Security Implications</h4>
                                  <div className="space-y-2">
                                    <div className="flex items-start space-x-2">
                                      <Warning className="w-4 h-4 text-orange-500 mt-0.5" />
                                      <div className="text-sm">
                                        <strong>Escalation Type:</strong> {escalation.escalationType}
                                        <p className="text-muted-foreground text-xs mt-1">
                                          This type of escalation could indicate attempts to access higher-privilege resources or administrative functions.
                                        </p>
                                      </div>
                                    </div>
                                    <div className="flex items-start space-x-2">
                                      <Activity className="w-4 h-4 text-blue-500 mt-0.5" />
                                      <div className="text-sm">
                                        <strong>Attempt Pattern:</strong> {escalation.attempts} attempts over recent activity period
                                        <p className="text-muted-foreground text-xs mt-1">
                                          Repeated attempts may indicate automated tools or persistent attacker behavior.
                                        </p>
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                <div className="pt-4 border-t">
                                  <h4 className="font-medium text-sm mb-2">Recommended Security Actions</h4>
                                  <ul className="text-sm text-muted-foreground space-y-1">
                                    {escalation.riskLevel === 'high' ? (
                                      <>
                                        <li>• <strong>Immediate:</strong> Review and restrict user's current permissions</li>
                                        <li>• <strong>Investigation:</strong> Conduct thorough security audit of user account</li>
                                        <li>• <strong>Monitoring:</strong> Implement real-time alerting for privilege changes</li>
                                        <li>• <strong>Access Control:</strong> Verify legitimacy of all privilege requests</li>
                                        <li>• <strong>Incident Response:</strong> Consider activating incident response procedures</li>
                                      </>
                                    ) : (
                                      <>
                                        <li>• Review user's role and permission requirements</li>
                                        <li>• Verify legitimacy of escalation attempts with user manager</li>
                                        <li>• Implement additional approval workflows for privilege changes</li>
                                        <li>• Monitor for continued escalation attempts</li>
                                        <li>• Update privilege access policies if needed</li>
                                      </>
                                    )}
                                  </ul>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No privilege escalation patterns detected
                      </p>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Critical Threats List */}
      {threats.filter(t => t.severity === 'critical' || t.severity === 'high').length > 0 && (
        <Card className="border-red-200 bg-red-50">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2 text-red-800">
              <Warning className="w-5 h-5" />
              <span>High-Priority Threats Requiring Immediate Attention</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {threats
                .filter(t => t.severity === 'critical' || t.severity === 'high')
                .slice(0, 8)
                .map((threat, index) => (
                  <div key={index} className="flex items-center justify-between p-4 bg-white border border-red-200 rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h4 className="font-medium text-red-800">{threat.type}</h4>
                        <Badge className={
                          threat.severity === 'critical' ? 'bg-red-100 text-red-800' :
                          'bg-orange-100 text-orange-800'
                        }>
                          {threat.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm text-red-700 mb-2">{threat.description}</p>
                      {threat.user && (
                        <div className="flex items-center space-x-1">
                          <Info className="w-3 h-3 text-red-600" />
                          <span className="text-xs text-red-600">User: {threat.user}</span>
                        </div>
                      )}
                    </div>
                    <ThreatDetailDialog threat={threat} />
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}