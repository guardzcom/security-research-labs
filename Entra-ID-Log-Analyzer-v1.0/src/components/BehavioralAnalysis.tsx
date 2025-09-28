import { useState } from 'react'
import { 
  Users, MapPin, Shield, TrendUp, Warning, 
  Globe, Clock, DeviceMobile, Monitor, Activity 
} from '@phosphor-icons/react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import type { AnalysisResults, UserRiskProfile, GeoCluster } from '@/types/security'

interface BehavioralAnalysisProps {
  results: AnalysisResults
}

export function BehavioralAnalysis({ results }: BehavioralAnalysisProps) {
  const [selectedUser, setSelectedUser] = useState<string>('')
  const [sortBy, setSortBy] = useState<'risk' | 'activity' | 'anomalies'>('risk')

  // Sort users by selected criteria
  const sortedUsers = Object.entries(results.userRiskProfiles).sort(([, a], [, b]) => {
    switch (sortBy) {
      case 'risk':
        return b.overallRiskScore - a.overallRiskScore
      case 'activity': 
        return (results.userProfiles[b.user]?.totalEvents || 0) - (results.userProfiles[a.user]?.totalEvents || 0)
      case 'anomalies':
        return (b.behaviorProfile.anomalyScore || 0) - (a.behaviorProfile.anomalyScore || 0)
      default:
        return 0
    }
  })

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-l-4 border-l-accent">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Risk Distribution</p>
                <div className="flex items-center space-x-2 mt-1">
                  <Badge variant="destructive" className="text-xs">
                    {results.behavioralAnalysis.riskDistribution.critical} Critical
                  </Badge>
                  <Badge variant="outline" className="text-xs bg-warning/10 text-warning border-warning/20">
                    {results.behavioralAnalysis.riskDistribution.high} High
                  </Badge>
                </div>
              </div>
              <Warning className="h-8 w-8 text-accent" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-info">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Anomaly Detection</p>
                <p className="text-2xl font-bold text-foreground">
                  {results.behavioralAnalysis.anomalyDetection.totalAnomalies}
                </p>
                <p className="text-xs text-muted-foreground">
                  Across {Object.keys(results.behavioralAnalysis.anomalyDetection.userAnomalies).length} users
                </p>
              </div>
              <TrendUp className="h-8 w-8 text-info" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-success">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Geo Clusters</p>
                <p className="text-2xl font-bold text-foreground">{results.geoClusters.length}</p>
                <p className="text-xs text-muted-foreground">
                  {results.geoClusters.filter(c => c.riskScore > 0.5).length} high-risk locations
                </p>
              </div>
              <MapPin className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-primary">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Behavioral Clusters</p>
                <p className="text-2xl font-bold text-foreground">
                  {results.behavioralAnalysis.clusterAnalysis.totalClusters}
                </p>
                <p className="text-xs text-muted-foreground">
                  {results.behavioralAnalysis.clusterAnalysis.riskClusters.length} risk clusters
                </p>
              </div>
              <Users className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Analysis Tabs */}
      <Tabs defaultValue="user-risk" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="user-risk">User Risk Profiles</TabsTrigger>
          <TabsTrigger value="geo-clusters">Geographic Clusters</TabsTrigger>
          <TabsTrigger value="behavior-patterns">Behavior Patterns</TabsTrigger>
          <TabsTrigger value="risk-analysis">Risk Analysis</TabsTrigger>
        </TabsList>

        <TabsContent value="user-risk" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>User Risk Assessment</span>
                </CardTitle>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-muted-foreground">Sort by:</span>
                  <Button
                    variant={sortBy === 'risk' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy('risk')}
                  >
                    Risk Score
                  </Button>
                  <Button
                    variant={sortBy === 'activity' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy('activity')}
                  >
                    Activity
                  </Button>
                  <Button
                    variant={sortBy === 'anomalies' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy('anomalies')}
                  >
                    Anomalies
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {sortedUsers.slice(0, 10).map(([user, profile]) => (
                  <UserRiskCard
                    key={user}
                    user={user}
                    profile={profile}
                    userProfile={results.userProfiles[user]}
                    isSelected={selectedUser === user}
                    onSelect={() => setSelectedUser(selectedUser === user ? '' : user)}
                  />
                ))}
              </div>
            </CardContent>
          </Card>

          {selectedUser && (
            <UserDetailCard 
              user={selectedUser}
              riskProfile={results.userRiskProfiles[selectedUser]}
              userProfile={results.userProfiles[selectedUser]}
            />
          )}
        </TabsContent>

        <TabsContent value="geo-clusters" className="space-y-4">
          <GeographicClusters clusters={results.geoClusters} />
        </TabsContent>

        <TabsContent value="behavior-patterns" className="space-y-4">
          <BehaviorPatterns results={results} />
        </TabsContent>

        <TabsContent value="risk-analysis" className="space-y-4">
          <RiskAnalysis results={results} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function UserRiskCard({ 
  user, 
  profile, 
  userProfile, 
  isSelected, 
  onSelect 
}: {
  user: string
  profile: UserRiskProfile
  userProfile: any
  isSelected: boolean
  onSelect: () => void
}) {
  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-100 border-red-200 text-red-800'
      case 'high': return 'bg-orange-100 border-orange-200 text-orange-800'
      case 'medium': return 'bg-yellow-100 border-yellow-200 text-yellow-800'
      case 'low': return 'bg-green-100 border-green-200 text-green-800'
      default: return 'bg-gray-100 border-gray-200 text-gray-800'
    }
  }

  return (
    <div 
      className={`border rounded-lg p-4 cursor-pointer transition-all hover:shadow-md ${
        isSelected ? 'ring-2 ring-primary bg-primary/5' : 'hover:bg-muted/50'
      }`}
      onClick={onSelect}
    >
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-3">
            <h4 className="font-medium text-foreground">{user}</h4>
            <Badge className={getRiskColor(profile.riskLevel)}>
              {profile.riskLevel.toUpperCase()}
            </Badge>
            <span className="text-sm text-muted-foreground">
              Score: {(profile.overallRiskScore * 100).toFixed(0)}%
            </span>
          </div>
          
          <div className="flex items-center space-x-6 mt-2 text-sm text-muted-foreground">
            <div className="flex items-center space-x-1">
              <Globe className="h-4 w-4" />
              <span>{profile.locations.countries.length} countries</span>
            </div>
            <div className="flex items-center space-x-1">
              <Monitor className="h-4 w-4" />
              <span>{profile.devices.totalDevices} devices</span>
            </div>
            <div className="flex items-center space-x-1">
              <Activity className="h-4 w-4" />
              <span>{userProfile?.totalEvents || 0} events</span>
            </div>
            {profile.behaviorProfile.isAnomaly && (
              <Badge variant="outline" className="bg-warning/10 text-warning border-warning/20">
                Anomaly Detected
              </Badge>
            )}
          </div>
        </div>
        
        <div className="text-right">
          <Progress 
            value={profile.overallRiskScore * 100} 
            className="w-24 h-2"
          />
        </div>
      </div>
    </div>
  )
}

function UserDetailCard({ 
  user, 
  riskProfile, 
  userProfile 
}: {
  user: string
  riskProfile: UserRiskProfile
  userProfile: any
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Detailed Risk Analysis - {user}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Risk Factor Breakdown */}
        <div>
          <h4 className="font-medium mb-3">Risk Factor Breakdown</h4>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            {Object.entries(riskProfile.riskFactors).map(([factor, score]) => (
              <div key={factor} className="text-center">
                <div className="capitalize text-sm font-medium text-muted-foreground mb-1">
                  {factor}
                </div>
                <Progress value={score * 100} className="h-2 mb-1" />
                <div className="text-xs text-muted-foreground">
                  {(score * 100).toFixed(0)}%
                </div>
              </div>
            ))}
          </div>
        </div>

        <Separator />

        {/* Location Analysis */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium mb-3 flex items-center space-x-2">
              <MapPin className="h-4 w-4" />
              <span>Geographic Profile</span>
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Countries:</span>
                <span>{riskProfile.locations.countries.join(', ')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Cities:</span>
                <span>{riskProfile.locations.cities.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Impossible Travel:</span>
                <span className={riskProfile.locations.impossibleTravelEvents > 0 ? 'text-accent' : ''}>
                  {riskProfile.locations.impossibleTravelEvents} events
                </span>
              </div>
            </div>
          </div>

          <div>
            <h4 className="font-medium mb-3 flex items-center space-x-2">
              <DeviceMobile className="h-4 w-4" />
              <span>Device Profile</span>
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total Devices:</span>
                <span>{riskProfile.devices.totalDevices}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Unmanaged:</span>
                <span className={riskProfile.devices.unmangedDevices > 0 ? 'text-warning' : ''}>
                  {riskProfile.devices.unmangedDevices}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">New Devices:</span>
                <span className={riskProfile.devices.newDevices > 0 ? 'text-accent' : ''}>
                  {riskProfile.devices.newDevices}
                </span>
              </div>
            </div>
          </div>
        </div>

        <Separator />

        {/* Application and Operations */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium mb-3">Application Usage</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total Apps:</span>
                <span>{riskProfile.applications.totalApps}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Privileged Access:</span>
                <span className={riskProfile.applications.privilegedAccess ? 'text-warning' : 'text-muted-foreground'}>
                  {riskProfile.applications.privilegedAccess ? 'Yes' : 'No'}
                </span>
              </div>
              {riskProfile.applications.riskApps.length > 0 && (
                <div>
                  <span className="text-muted-foreground">Risk Apps:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {riskProfile.applications.riskApps.slice(0, 3).map(app => (
                      <Badge key={app} variant="outline" className="text-xs">
                        {app}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div>
            <h4 className="font-medium mb-3">Operational Metrics</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Success Rate:</span>
                <span className={userProfile?.successRate < 0.9 ? 'text-warning' : 'text-success'}>
                  {((userProfile?.successRate || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Failed Operations:</span>
                <span className={riskProfile.operations.failedOperations > 0 ? 'text-accent' : ''}>
                  {riskProfile.operations.failedOperations}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Time Anomalies:</span>
                <span className={riskProfile.operations.timeAnomalies > 0 ? 'text-warning' : ''}>
                  {riskProfile.operations.timeAnomalies}
                </span>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function GeographicClusters({ clusters }: { clusters: GeoCluster[] }) {
  return (
    <div className="space-y-4">
      {clusters.map(cluster => (
        <Card key={cluster.id} className="overflow-hidden">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center space-x-2">
                <MapPin className="h-5 w-5" />
                <span>{cluster.centroid.city}, {cluster.centroid.country}</span>
              </CardTitle>
              <Badge 
                variant={cluster.riskScore > 0.7 ? 'destructive' : 
                        cluster.riskScore > 0.4 ? 'outline' : 'secondary'}
              >
                Risk: {(cluster.riskScore * 100).toFixed(0)}%
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-foreground">{cluster.users.length}</div>
                <div className="text-sm text-muted-foreground">Users</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-foreground">{cluster.activityCount}</div>
                <div className="text-sm text-muted-foreground">Activities</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-foreground">{cluster.radius}km</div>
                <div className="text-sm text-muted-foreground">Radius</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-foreground">
                  {cluster.suspiciousActivities.length}
                </div>
                <div className="text-sm text-muted-foreground">Suspicious</div>
              </div>
            </div>
            
            {cluster.suspiciousActivities.length > 0 && (
              <div className="mt-4">
                <h5 className="font-medium mb-2">Suspicious Activities</h5>
                <div className="flex flex-wrap gap-2">
                  {cluster.suspiciousActivities.map(activity => (
                    <Badge key={activity} variant="outline">
                      {activity.replace('_', ' ')}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function BehaviorPatterns({ results }: { results: AnalysisResults }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Anomaly Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {Object.entries(results.behavioralAnalysis.anomalyDetection.anomalyTypes).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="capitalize">{type.replace('_', ' ')}</span>
                <div className="flex items-center space-x-2">
                  <Progress value={(count / results.behavioralAnalysis.anomalyDetection.totalAnomalies) * 100} className="w-32 h-2" />
                  <span className="text-sm font-medium">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>User Anomalies</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {Object.entries(results.behavioralAnalysis.anomalyDetection.userAnomalies)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 10)
              .map(([user, count]) => (
                <div key={user} className="flex items-center justify-between py-2 border-b border-border last:border-0">
                  <span className="font-medium">{user}</span>
                  <Badge variant="outline">{count} anomalies</Badge>
                </div>
              ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function RiskAnalysis({ results }: { results: AnalysisResults }) {
  const totalUsers = Object.keys(results.userRiskProfiles).length
  
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Risk Level Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {Object.entries(results.behavioralAnalysis.riskDistribution).map(([level, count]) => {
                const percentage = totalUsers > 0 ? (count / totalUsers) * 100 : 0
                return (
                  <div key={level} className="space-y-2">
                    <div className="flex justify-between">
                      <span className="capitalize font-medium">{level}</span>
                      <span className="text-sm text-muted-foreground">
                        {count} users ({percentage.toFixed(1)}%)
                      </span>
                    </div>
                    <Progress value={percentage} className="h-2" />
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Cluster Risk Assessment</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="text-center">
                <div className="text-3xl font-bold text-foreground">
                  {results.behavioralAnalysis.clusterAnalysis.riskClusters.length}
                </div>
                <div className="text-sm text-muted-foreground">High-Risk Clusters</div>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Total Clusters:</span>
                  <span>{results.behavioralAnalysis.clusterAnalysis.totalClusters}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Avg Cluster Size:</span>
                  <span>
                    {results.behavioralAnalysis.clusterAnalysis.clusterSizes.length > 0 
                      ? Math.round(results.behavioralAnalysis.clusterAnalysis.clusterSizes.reduce((a, b) => a + b, 0) / results.behavioralAnalysis.clusterAnalysis.clusterSizes.length)
                      : 0
                    } users
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Risk Cluster Rate:</span>
                  <span className="text-accent">
                    {results.behavioralAnalysis.clusterAnalysis.totalClusters > 0 
                      ? ((results.behavioralAnalysis.clusterAnalysis.riskClusters.length / results.behavioralAnalysis.clusterAnalysis.totalClusters) * 100).toFixed(1)
                      : 0
                    }%
                  </span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}