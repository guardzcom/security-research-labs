import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress' 
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
  Shield, 
  Warning, 
  CheckCircle, 
  XCircle, 
  Users,
  Clock,
  MapPin,
  Activity,
  Info
} from '@phosphor-icons/react'
import type { AnalysisResults } from '@/types/security'

interface ThreatSummaryProps {
  results: AnalysisResults
}

export function ThreatSummary({ results }: ThreatSummaryProps) {
  const { summary, threats, riskAssessment } = results
  const [selectedCountry, setSelectedCountry] = useState<{country: string; count: number} | null>(null)
  const [selectedApp, setSelectedApp] = useState<{app: string; count: number; successRate: number} | null>(null)
  
  const criticalThreats = threats.filter(t => t.severity === 'critical').length
  const highThreats = threats.filter(t => t.severity === 'high').length
  const mediumThreats = threats.filter(t => t.severity === 'medium').length
  const lowThreats = threats.filter(t => t.severity === 'low').length

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-600'
      case 'high': return 'text-orange-600' 
      case 'medium': return 'text-yellow-600'
      case 'low': return 'text-green-600'
      default: return 'text-gray-600'
    }
  }

  const getRiskBgColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-50 border-red-200'
      case 'high': return 'bg-orange-50 border-orange-200'
      case 'medium': return 'bg-yellow-50 border-yellow-200'
      case 'low': return 'bg-green-50 border-green-200'
      default: return 'bg-gray-50 border-gray-200'
    }
  }

  const getCountryRiskLevel = (count: number, totalEvents: number) => {
    const percentage = (count / totalEvents) * 100
    if (percentage > 50) return 'high'
    if (percentage > 20) return 'medium'
    return 'low'
  }

  const getAppRiskLevel = (successRate: number) => {
    if (successRate < 0.5) return 'critical'
    if (successRate < 0.7) return 'high'
    if (successRate < 0.9) return 'medium'
    return 'low'
  }

  const getColorByIndex = (index: number) => {
    const colors = [
      { bg: 'bg-blue-50', border: 'border-blue-200', text: 'text-blue-800', dot: 'bg-blue-600' },
      { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-800', dot: 'bg-green-600' },
      { bg: 'bg-purple-50', border: 'border-purple-200', text: 'text-purple-800', dot: 'bg-purple-600' },
      { bg: 'bg-orange-50', border: 'border-orange-200', text: 'text-orange-800', dot: 'bg-orange-600' },
      { bg: 'bg-pink-50', border: 'border-pink-200', text: 'text-pink-800', dot: 'bg-pink-600' },
    ]
    return colors[index % colors.length]
  }

  return (
    <div className="space-y-6">
      {/* Overall Risk Assessment */}
      <Card className={`${getRiskBgColor(riskAssessment.riskLevel)} border-2`}>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className={`flex items-center justify-center w-12 h-12 rounded-full ${
                riskAssessment.riskLevel === 'critical' ? 'bg-red-100' :
                riskAssessment.riskLevel === 'high' ? 'bg-orange-100' :
                riskAssessment.riskLevel === 'medium' ? 'bg-yellow-100' : 'bg-green-100'
              }`}>
                {riskAssessment.riskLevel === 'critical' ? (
                  <XCircle className={`w-6 h-6 ${getRiskColor(riskAssessment.riskLevel)}`} weight="fill" />
                ) : riskAssessment.riskLevel === 'low' ? (
                  <CheckCircle className={`w-6 h-6 ${getRiskColor(riskAssessment.riskLevel)}`} weight="fill" />
                ) : (
                  <Warning className={`w-6 h-6 ${getRiskColor(riskAssessment.riskLevel)}`} weight="fill" />
                )}
              </div>
              <div>
                <CardTitle className="text-xl">
                  Overall Risk Assessment
                </CardTitle>
                <Badge variant="outline" className={`${getRiskColor(riskAssessment.riskLevel)} border-current`}>
                  {riskAssessment.riskLevel.toUpperCase()} RISK
                </Badge>
              </div>
            </div>
            <div className="text-right">
              <div className={`text-4xl font-bold ${getRiskColor(riskAssessment.riskLevel)}`}>
                {riskAssessment.overallRiskScore}
              </div>
              <div className="text-sm text-muted-foreground">Risk Score</div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Risk Level</span>
                <span>{riskAssessment.overallRiskScore}/100</span>
              </div>
              <Progress 
                value={riskAssessment.overallRiskScore} 
                className="h-2"
              />
            </div>
            
            {riskAssessment.riskLevel === 'critical' && (
              <Alert variant="destructive">
                <Warning className="h-4 w-4" />
                <AlertDescription>
                  <strong>Critical threats detected!</strong> Immediate action required to secure your environment.
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Summary Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Total Events */}
        <Card className="chart-hover">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Events</p>
                <p className="text-3xl font-bold text-foreground">
                  {summary.totalEvents.toLocaleString()}
                </p>
                <div className="flex items-center space-x-1 mt-1">
                  <Clock className="w-3 h-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">
                    {new Date(summary.timeRange.start).toLocaleDateString()} - {new Date(summary.timeRange.end).toLocaleDateString()}
                  </span>
                </div>
              </div>
              <Activity className="w-8 h-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>

        {/* Successful Sign-ins */}
        <Card className="chart-hover">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Successful Sign-ins</p>
                <p className="text-3xl font-bold text-green-600">
                  {summary.successfulSignins.toLocaleString()}
                </p>
                <div className="flex items-center space-x-1 mt-1">
                  <CheckCircle className="w-3 h-3 text-green-600" />
                  <span className="text-xs text-green-600">
                    {(summary.successRate * 100).toFixed(1)}% success rate
                  </span>
                </div>
              </div>
              <CheckCircle className="w-8 h-8 text-green-600" weight="fill" />
            </div>
          </CardContent>
        </Card>

        {/* Failed Sign-ins */}
        <Card className="chart-hover">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Failed Sign-ins</p>
                <p className="text-3xl font-bold text-red-600">
                  {summary.failedSignins.toLocaleString()}
                </p>
                <div className="flex items-center space-x-1 mt-1">
                  <XCircle className="w-3 h-3 text-red-600" />
                  <span className="text-xs text-red-600">
                    {((1 - summary.successRate) * 100).toFixed(1)}% failure rate
                  </span>
                </div>
              </div>
              <XCircle className="w-8 h-8 text-red-600" weight="fill" />
            </div>
          </CardContent>
        </Card>

        {/* Unique Users */}
        <Card className="chart-hover">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Unique Users</p>
                <p className="text-3xl font-bold text-blue-600">
                  {summary.uniqueUsers.toLocaleString()}
                </p>
                <div className="flex items-center space-x-1 mt-1">
                  <Users className="w-3 h-3 text-blue-600" />
                  <span className="text-xs text-blue-600">
                    {(summary.totalEvents / summary.uniqueUsers).toFixed(1)} avg events/user
                  </span>
                </div>
              </div>
              <Users className="w-8 h-8 text-blue-600" weight="fill" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Shield className="w-5 h-5" />
              <span>Threat Distribution</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {/* Critical Threats */}
              <Dialog>
                <DialogTrigger asChild>
                  <div className="flex items-center justify-between p-3 bg-red-50 border border-red-200 rounded-lg cursor-pointer hover:shadow-md transition-all hover:bg-red-100">
                    <div className="flex items-center space-x-3">
                      <div className="w-3 h-3 bg-red-600 rounded-full"></div>
                      <span className="font-medium text-red-800">Critical Threats</span>
                    </div>
                    <Badge variant="destructive">{criticalThreats}</Badge>
                  </div>
                </DialogTrigger>
                <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle className="flex items-center space-x-2">
                      <XCircle className="w-5 h-5 text-red-600" />
                      <span>Critical Threats ({criticalThreats})</span>
                    </DialogTitle>
                    <DialogDescription>
                      High-priority threats requiring immediate attention and mitigation
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    {threats.filter(t => t.severity === 'critical').map((threat, index) => (
                      <div key={index} className="p-4 bg-red-50 border border-red-200 rounded-lg">
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="font-semibold text-red-800">{threat.type}</h4>
                          <Badge variant="destructive">CRITICAL</Badge>
                        </div>
                        <p className="text-sm text-red-700 mb-3">{threat.description}</p>
                        {threat.user && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Users className="w-4 h-4 text-red-600" />
                            <span className="text-sm font-medium text-red-600">Affected User: {threat.user}</span>
                          </div>
                        )}
                        {threat.confidence && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Info className="w-4 h-4 text-red-600" />
                            <span className="text-sm text-red-600">Confidence: {Math.round(threat.confidence * 100)}%</span>
                          </div>
                        )}
                        {threat.mitreAttack && threat.mitreAttack.length > 0 && (
                          <div className="mt-3">
                            <h5 className="text-sm font-medium text-red-800 mb-2">MITRE ATT&CK TTPs:</h5>
                            <div className="flex flex-wrap gap-1">
                              {threat.mitreAttack.map(ttp => (
                                <Badge key={ttp} variant="outline" className="text-xs text-red-600 border-red-300">{ttp}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                    {criticalThreats === 0 && (
                      <div className="text-center py-8">
                        <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-2" />
                        <p className="text-green-600 font-medium">No Critical Threats Detected</p>
                      </div>
                    )}
                  </div>
                </DialogContent>
              </Dialog>

              {/* High Threats */}
              <Dialog>
                <DialogTrigger asChild>
                  <div className="flex items-center justify-between p-3 bg-orange-50 border border-orange-200 rounded-lg cursor-pointer hover:shadow-md transition-all hover:bg-orange-100">
                    <div className="flex items-center space-x-3">
                      <div className="w-3 h-3 bg-orange-600 rounded-full"></div>
                      <span className="font-medium text-orange-800">High Severity</span>
                    </div>
                    <Badge variant="outline" className="text-orange-600 border-orange-600">{highThreats}</Badge>
                  </div>
                </DialogTrigger>
                <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle className="flex items-center space-x-2">
                      <Warning className="w-5 h-5 text-orange-600" />
                      <span>High Severity Threats ({highThreats})</span>
                    </DialogTitle>
                    <DialogDescription>
                      Significant threats that require prompt investigation and response
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    {threats.filter(t => t.severity === 'high').map((threat, index) => (
                      <div key={index} className="p-4 bg-orange-50 border border-orange-200 rounded-lg">
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="font-semibold text-orange-800">{threat.type}</h4>
                          <Badge className="bg-orange-100 text-orange-800">HIGH</Badge>
                        </div>
                        <p className="text-sm text-orange-700 mb-3">{threat.description}</p>
                        {threat.user && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Users className="w-4 h-4 text-orange-600" />
                            <span className="text-sm font-medium text-orange-600">Affected User: {threat.user}</span>
                          </div>
                        )}
                        {threat.confidence && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Info className="w-4 h-4 text-orange-600" />
                            <span className="text-sm text-orange-600">Confidence: {Math.round(threat.confidence * 100)}%</span>
                          </div>
                        )}
                        {threat.mitreAttack && threat.mitreAttack.length > 0 && (
                          <div className="mt-3">
                            <h5 className="text-sm font-medium text-orange-800 mb-2">MITRE ATT&CK TTPs:</h5>
                            <div className="flex flex-wrap gap-1">
                              {threat.mitreAttack.map(ttp => (
                                <Badge key={ttp} variant="outline" className="text-xs text-orange-600 border-orange-300">{ttp}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                    {highThreats === 0 && (
                      <div className="text-center py-8">
                        <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-2" />
                        <p className="text-green-600 font-medium">No High Severity Threats Detected</p>
                      </div>
                    )}
                  </div>
                </DialogContent>
              </Dialog>

              {/* Medium Threats */}
              <Dialog>
                <DialogTrigger asChild>
                  <div className="flex items-center justify-between p-3 bg-yellow-50 border border-yellow-200 rounded-lg cursor-pointer hover:shadow-md transition-all hover:bg-yellow-100">
                    <div className="flex items-center space-x-3">
                      <div className="w-3 h-3 bg-yellow-600 rounded-full"></div>
                      <span className="font-medium text-yellow-800">Medium Severity</span>
                    </div>
                    <Badge variant="outline" className="text-yellow-600 border-yellow-600">{mediumThreats}</Badge>
                  </div>
                </DialogTrigger>
                <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle className="flex items-center space-x-2">
                      <Warning className="w-5 h-5 text-yellow-600" />
                      <span>Medium Severity Threats ({mediumThreats})</span>
                    </DialogTitle>
                    <DialogDescription>
                      Moderate threats that should be monitored and addressed in due course
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    {threats.filter(t => t.severity === 'medium').map((threat, index) => (
                      <div key={index} className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="font-semibold text-yellow-800">{threat.type}</h4>
                          <Badge className="bg-yellow-100 text-yellow-800">MEDIUM</Badge>
                        </div>
                        <p className="text-sm text-yellow-700 mb-3">{threat.description}</p>
                        {threat.user && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Users className="w-4 h-4 text-yellow-600" />
                            <span className="text-sm font-medium text-yellow-600">Affected User: {threat.user}</span>
                          </div>
                        )}
                        {threat.confidence && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Info className="w-4 h-4 text-yellow-600" />
                            <span className="text-sm text-yellow-600">Confidence: {Math.round(threat.confidence * 100)}%</span>
                          </div>
                        )}
                        {threat.mitreAttack && threat.mitreAttack.length > 0 && (
                          <div className="mt-3">
                            <h5 className="text-sm font-medium text-yellow-800 mb-2">MITRE ATT&CK TTPs:</h5>
                            <div className="flex flex-wrap gap-1">
                              {threat.mitreAttack.map(ttp => (
                                <Badge key={ttp} variant="outline" className="text-xs text-yellow-600 border-yellow-300">{ttp}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                    {mediumThreats === 0 && (
                      <div className="text-center py-8">
                        <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-2" />
                        <p className="text-green-600 font-medium">No Medium Severity Threats Detected</p>
                      </div>
                    )}
                  </div>
                </DialogContent>
              </Dialog>

              {/* Low Threats */}
              <Dialog>
                <DialogTrigger asChild>
                  <div className="flex items-center justify-between p-3 bg-blue-50 border border-blue-200 rounded-lg cursor-pointer hover:shadow-md transition-all hover:bg-blue-100">
                    <div className="flex items-center space-x-3">
                      <div className="w-3 h-3 bg-blue-600 rounded-full"></div>
                      <span className="font-medium text-blue-800">Low Severity</span>
                    </div>
                    <Badge variant="outline" className="text-blue-600 border-blue-600">{lowThreats}</Badge>
                  </div>
                </DialogTrigger>
                <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle className="flex items-center space-x-2">
                      <Info className="w-5 h-5 text-blue-600" />
                      <span>Low Severity Threats ({lowThreats})</span>
                    </DialogTitle>
                    <DialogDescription>
                      Minor threats and informational alerts for awareness and monitoring
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    {threats.filter(t => t.severity === 'low').map((threat, index) => (
                      <div key={index} className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="font-semibold text-blue-800">{threat.type}</h4>
                          <Badge className="bg-blue-100 text-blue-800">LOW</Badge>
                        </div>
                        <p className="text-sm text-blue-700 mb-3">{threat.description}</p>
                        {threat.user && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Users className="w-4 h-4 text-blue-600" />
                            <span className="text-sm font-medium text-blue-600">Affected User: {threat.user}</span>
                          </div>
                        )}
                        {threat.confidence && (
                          <div className="flex items-center space-x-2 mb-2">
                            <Info className="w-4 h-4 text-blue-600" />
                            <span className="text-sm text-blue-600">Confidence: {Math.round(threat.confidence * 100)}%</span>
                          </div>
                        )}
                        {threat.mitreAttack && threat.mitreAttack.length > 0 && (
                          <div className="mt-3">
                            <h5 className="text-sm font-medium text-blue-800 mb-2">MITRE ATT&CK TTPs:</h5>
                            <div className="flex flex-wrap gap-1">
                              {threat.mitreAttack.map(ttp => (
                                <Badge key={ttp} variant="outline" className="text-xs text-blue-600 border-blue-300">{ttp}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                    {lowThreats === 0 && (
                      <div className="text-center py-8">
                        <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-2" />
                        <p className="text-green-600 font-medium">No Low Severity Threats Detected</p>
                      </div>
                    )}
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </CardContent>
        </Card>

        {/* Top Threat Types */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Warning className="w-5 h-5" />
              <span>Recent Threats</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {threats
                .sort((a, b) => {
                  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
                  return severityOrder[b.severity] - severityOrder[a.severity]
                })
                .slice(0, 5)
                .map((threat, index) => (
                  <Dialog key={index}>
                    <DialogTrigger asChild>
                      <div className="flex items-start space-x-3 p-3 bg-card border rounded-lg cursor-pointer hover:shadow-md transition-all hover:bg-muted/50">
                        <div className={`w-2 h-2 rounded-full mt-2 ${
                          threat.severity === 'critical' ? 'bg-red-600' :
                          threat.severity === 'high' ? 'bg-orange-600' :
                          threat.severity === 'medium' ? 'bg-yellow-600' :
                          'bg-blue-600'
                        }`}></div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h4 className="font-medium text-sm text-foreground truncate">
                              {threat.type}
                            </h4>
                            <Badge 
                              variant="outline" 
                              className={`text-xs ${getRiskColor(threat.severity)} border-current`}
                            >
                              {threat.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                            {threat.description}
                          </p>
                          {threat.user && (
                            <div className="flex items-center space-x-1 mt-2">
                              <Users className="w-3 h-3 text-muted-foreground" />
                              <span className="text-xs text-muted-foreground">
                                {threat.user}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </DialogTrigger>
                    <DialogContent className="max-w-3xl">
                      <DialogHeader>
                        <DialogTitle className="flex items-center space-x-2">
                          {threat.severity === 'critical' ? (
                            <XCircle className="w-5 h-5 text-red-600" />
                          ) : threat.severity === 'high' ? (
                            <Warning className="w-5 h-5 text-orange-600" />
                          ) : threat.severity === 'medium' ? (
                            <Warning className="w-5 h-5 text-yellow-600" />
                          ) : (
                            <Info className="w-5 h-5 text-blue-600" />
                          )}
                          <span>{threat.type}</span>
                        </DialogTitle>
                        <DialogDescription>
                          Detailed threat analysis and security findings
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
                          <h4 className="font-medium text-sm mb-2">Threat Description</h4>
                          <p className={`text-sm p-3 rounded-lg ${
                            threat.severity === 'critical' ? 'bg-red-50 text-red-700 border border-red-200' :
                            threat.severity === 'high' ? 'bg-orange-50 text-orange-700 border border-orange-200' :
                            threat.severity === 'medium' ? 'bg-yellow-50 text-yellow-700 border border-yellow-200' :
                            'bg-blue-50 text-blue-700 border border-blue-200'
                          }`}>
                            {threat.description}
                          </p>
                        </div>

                        {threat.user && (
                          <div>
                            <h4 className="font-medium text-sm mb-2">Affected User</h4>
                            <div className="flex items-center space-x-2">
                              <Users className="w-4 h-4 text-muted-foreground" />
                              <Badge variant="outline">{threat.user}</Badge>
                            </div>
                          </div>
                        )}

                        {threat.mitreAttack && threat.mitreAttack.length > 0 && (
                          <div>
                            <h4 className="font-medium text-sm mb-2">MITRE ATT&CK TTPs</h4>
                            <div className="flex flex-wrap gap-2">
                              {threat.mitreAttack.map(ttp => (
                                <Badge key={ttp} variant="secondary" className="text-xs">{ttp}</Badge>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="pt-4 border-t">
                          <h4 className="font-medium text-sm mb-2">Security Findings & Analysis</h4>
                          <div className={`p-3 rounded-lg ${
                            threat.severity === 'critical' ? 'bg-red-50 border border-red-200' :
                            threat.severity === 'high' ? 'bg-orange-50 border border-orange-200' :
                            threat.severity === 'medium' ? 'bg-yellow-50 border border-yellow-200' :
                            'bg-blue-50 border border-blue-200'
                          }`}>
                            <ul className="text-sm space-y-1">
                              {threat.severity === 'critical' && (
                                <>
                                  <li className="text-red-700">• <strong>Critical Risk:</strong> This threat represents an immediate security risk to your environment</li>
                                  <li className="text-red-700">• <strong>Immediate Action Required:</strong> Block related activities and investigate user account</li>
                                  <li className="text-red-700">• <strong>Potential Impact:</strong> Full account compromise, data exfiltration, lateral movement</li>
                                </>
                              )}
                              {threat.severity === 'high' && (
                                <>
                                  <li className="text-orange-700">• <strong>High Priority:</strong> Significant security concern requiring prompt attention</li>
                                  <li className="text-orange-700">• <strong>Investigation Needed:</strong> Review user activities and authentication patterns</li>
                                  <li className="text-orange-700">• <strong>Potential Impact:</strong> Account compromise, unauthorized access attempts</li>
                                </>
                              )}
                              {threat.severity === 'medium' && (
                                <>
                                  <li className="text-yellow-700">• <strong>Moderate Risk:</strong> Suspicious activity that should be monitored</li>
                                  <li className="text-yellow-700">• <strong>Monitoring Required:</strong> Track user behavior for escalating patterns</li>
                                  <li className="text-yellow-700">• <strong>Potential Impact:</strong> Policy violations, unusual access patterns</li>
                                </>
                              )}
                              {threat.severity === 'low' && (
                                <>
                                  <li className="text-blue-700">• <strong>Informational:</strong> Anomalous behavior worth noting</li>
                                  <li className="text-blue-700">• <strong>Awareness:</strong> Minor deviation from normal authentication patterns</li>
                                  <li className="text-blue-700">• <strong>Potential Impact:</strong> Baseline security awareness, minor policy concerns</li>
                                </>
                              )}
                            </ul>
                          </div>
                        </div>

                        <div className="pt-4 border-t">
                          <h4 className="font-medium text-sm mb-2">Recommended Actions</h4>
                          <ul className="text-sm text-muted-foreground space-y-1">
                            {threat.severity === 'critical' ? (
                              <>
                                <li>• <strong>Immediate:</strong> Disable affected user account and force password reset</li>
                                <li>• <strong>Investigate:</strong> Review all recent activity for signs of compromise</li>
                                <li>• <strong>Secure:</strong> Enable MFA and implement conditional access policies</li>
                                <li>• <strong>Monitor:</strong> Set up real-time alerting for similar patterns</li>
                              </>
                            ) : threat.severity === 'high' ? (
                              <>
                                <li>• Investigate user account for signs of unauthorized access</li>
                                <li>• Review authentication logs and verify user identity</li>
                                <li>• Consider implementing additional security controls</li>
                                <li>• Monitor for continued suspicious activity</li>
                              </>
                            ) : (
                              <>
                                <li>• Monitor user activity for escalating suspicious patterns</li>
                                <li>• Review authentication policies and user training needs</li>
                                <li>• Document findings for trend analysis</li>
                                <li>• Consider user awareness training if needed</li>
                              </>
                            )}
                          </ul>
                        </div>
                      </div>
                    </DialogContent>
                  </Dialog>
                ))}
              
              {threats.length === 0 && (
                <div className="text-center py-6">
                  <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-2" />
                  <p className="text-sm font-medium text-green-600">No Active Threats</p>
                  <p className="text-xs text-muted-foreground">All authentication patterns appear normal</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Geographic and Application Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Countries */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <MapPin className="w-5 h-5" />
              <span>Top Countries</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {summary.topCountries.map((country, index) => {
                const riskLevel = getCountryRiskLevel(country.count, summary.totalEvents)
                const colorScheme = getColorByIndex(index)
                
                return (
                  <Dialog key={country.country}>
                    <DialogTrigger asChild>
                      <div className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${colorScheme.bg} ${colorScheme.border}`}>
                        <div className="flex items-center space-x-3">
                          <div className="text-sm font-medium text-muted-foreground w-4">
                            #{index + 1}
                          </div>
                          <div className={`w-3 h-3 rounded-full ${colorScheme.dot}`}></div>
                          <span className={`font-medium ${colorScheme.text}`}>{country.country}</span>
                        </div>
                        <div className="text-right">
                          <div className={`font-medium ${colorScheme.text}`}>{country.count.toLocaleString()}</div>
                          <div className="text-xs text-muted-foreground">
                            {((country.count / summary.totalEvents) * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle className="flex items-center space-x-2">
                          <MapPin className="w-5 h-5" />
                          <span>{country.country} - Authentication Details</span>
                        </DialogTitle>
                        <DialogDescription>
                          Detailed analysis of authentication activity from {country.country}
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <h4 className="font-medium text-sm">Total Events</h4>
                            <div className="text-2xl font-bold text-blue-600">
                              {country.count.toLocaleString()}
                            </div>
                          </div>
                          <div>
                            <h4 className="font-medium text-sm">Percentage of Total</h4>
                            <div className="text-2xl font-bold text-green-600">
                              {((country.count / summary.totalEvents) * 100).toFixed(1)}%
                            </div>
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="font-medium text-sm mb-2">Risk Assessment</h4>
                          <Badge className={`${getRiskColor(riskLevel)} border-current`} variant="outline">
                            {riskLevel.toUpperCase()} RISK
                          </Badge>
                        </div>

                        <div className="pt-4 border-t">
                          <h4 className="font-medium text-sm mb-2">Security Recommendations</h4>
                          <ul className="text-sm text-muted-foreground space-y-1">
                            <li>• Monitor for unusual access patterns from this region</li>
                            <li>• Verify legitimacy of high-volume authentication attempts</li>
                            <li>• Consider implementing geo-based conditional access policies</li>
                            <li>• Review user activity for potential compromise indicators</li>
                          </ul>
                        </div>
                      </div>
                    </DialogContent>
                  </Dialog>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Top Applications */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="w-5 h-5" />
              <span>Top Applications</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {summary.topApplications.slice(0, 5).map((app, index) => {
                const riskLevel = getAppRiskLevel(app.successRate)
                const colorScheme = getColorByIndex(index)
                
                return (
                  <Dialog key={app.app}>
                    <DialogTrigger asChild>
                      <div className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer hover:shadow-md transition-all ${colorScheme.bg} ${colorScheme.border}`}>
                        <div className="flex items-center space-x-3 flex-1 min-w-0">
                          <div className="text-sm font-medium text-muted-foreground w-4">
                            #{index + 1}
                          </div>
                          <div className={`w-3 h-3 rounded-full ${colorScheme.dot}`}></div>
                          <span className={`font-medium truncate ${colorScheme.text}`}>{app.app}</span>
                        </div>
                        <div className="text-right ml-4">
                          <div className={`font-medium ${colorScheme.text}`}>{app.count.toLocaleString()}</div>
                          <div className={`text-xs ${
                            app.successRate > 0.9 ? 'text-green-600' :
                            app.successRate > 0.7 ? 'text-yellow-600' :
                            'text-red-600'
                          }`}>
                            {(app.successRate * 100).toFixed(1)}% success
                          </div>
                        </div>
                      </div>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle className="flex items-center space-x-2">
                          <Activity className="w-5 h-5" />
                          <span>{app.app} - Application Analysis</span>
                        </DialogTitle>
                        <DialogDescription>
                          Authentication metrics and security analysis for {app.app}
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <h4 className="font-medium text-sm">Total Authentications</h4>
                            <div className="text-2xl font-bold text-blue-600">
                              {app.count.toLocaleString()}
                            </div>
                          </div>
                          <div>
                            <h4 className="font-medium text-sm">Success Rate</h4>
                            <div className={`text-2xl font-bold ${
                              app.successRate > 0.9 ? 'text-green-600' :
                              app.successRate > 0.7 ? 'text-yellow-600' :
                              'text-red-600'
                            }`}>
                              {(app.successRate * 100).toFixed(1)}%
                            </div>
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <h4 className="font-medium text-sm">Successful Sign-ins</h4>
                            <div className="text-lg font-medium text-green-600">
                              {Math.round(app.count * app.successRate).toLocaleString()}
                            </div>
                          </div>
                          <div>
                            <h4 className="font-medium text-sm">Failed Attempts</h4>
                            <div className="text-lg font-medium text-red-600">
                              {Math.round(app.count * (1 - app.successRate)).toLocaleString()}
                            </div>
                          </div>
                        </div>

                        <div>
                          <h4 className="font-medium text-sm mb-2">Risk Level</h4>
                          <Badge className={`${getRiskColor(riskLevel)} border-current`} variant="outline">
                            {riskLevel.toUpperCase()} RISK
                          </Badge>
                        </div>

                        <div className="pt-4 border-t">
                          <h4 className="font-medium text-sm mb-2">Security Recommendations</h4>
                          <ul className="text-sm text-muted-foreground space-y-1">
                            {app.successRate < 0.7 ? (
                              <>
                                <li>• <strong>Critical:</strong> Investigate high failure rate for potential attacks</li>
                                <li>• Implement stronger authentication requirements</li>
                                <li>• Monitor for brute force patterns</li>
                              </>
                            ) : (
                              <>
                                <li>• Monitor application access patterns for anomalies</li>
                                <li>• Review conditional access policies for this application</li>
                                <li>• Ensure proper logging and alerting is configured</li>
                              </>
                            )}
                            <li>• Regular security assessments and access reviews</li>
                          </ul>
                        </div>
                      </div>
                    </DialogContent>
                  </Dialog>
                )
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}