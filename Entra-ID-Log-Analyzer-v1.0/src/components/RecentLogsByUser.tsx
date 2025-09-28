import { useState, useMemo } from 'react'
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
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { 
  Users,
  Clock,
  MapPin,
  Eye,
  CaretDown,
  CaretRight,
  CheckCircle,
  XCircle,
  Shield,
  Warning,
  TrendUp
} from '@phosphor-icons/react'
import type { AnalysisResults, LogEntry } from '@/types/security'

interface RecentLogsByUserProps {
  results: AnalysisResults
  maxUsers?: number
  maxLogsPerUser?: number
}

interface UserLogGroup {
  user: string
  displayName: string
  totalLogs: number
  recentLogs: LogEntry[]
  successCount: number
  failureCount: number
  successRate: number
  lastActivity: Date
  uniqueIPs: number
  uniqueLocations: number
  riskScore: number
}

export function RecentLogsByUser({ 
  results, 
  maxUsers = 10, 
  maxLogsPerUser = 5 
}: RecentLogsByUserProps) {
  const [openUsers, setOpenUsers] = useState<Set<string>>(new Set())

  // Group logs by user and calculate metrics
  const userGroups = useMemo(() => {
    const groupedLogs = new Map<string, LogEntry[]>()
    
    // Group logs by user
    results.rawLogs.forEach(log => {
      const userId = log.userPrincipalName || log.userId || 'Unknown User'
      if (!groupedLogs.has(userId)) {
        groupedLogs.set(userId, [])
      }
      groupedLogs.get(userId)!.push(log)
    })

    // Process each user group
    const userGroupsArray: UserLogGroup[] = Array.from(groupedLogs.entries()).map(([userId, logs]) => {
      // Sort logs by timestamp (most recent first)
      const sortedLogs = logs.sort((a, b) => {
        const timeA = new Date(a.time || a.createdDateTime || a.timestamp || 0).getTime()
        const timeB = new Date(b.time || b.createdDateTime || b.timestamp || 0).getTime()
        return timeB - timeA
      })

      const recentLogs = sortedLogs.slice(0, maxLogsPerUser)
      const successCount = logs.filter(log => 
        log.status?.errorCode === 0 || log.status?.errorCode === '0'
      ).length
      const failureCount = logs.length - successCount
      const successRate = logs.length > 0 ? (successCount / logs.length) * 100 : 0

      // Calculate unique IPs and locations
      const uniqueIPs = new Set(logs.map(log => log.ipAddress).filter(Boolean)).size
      const uniqueLocations = new Set(
        logs.map(log => log.location ? `${log.location.city}, ${log.location.countryOrRegion}` : null)
          .filter(Boolean)
      ).size

      // Calculate risk score based on various factors
      let riskScore = 0
      
      // High failure rate increases risk
      if (successRate < 50) riskScore += 30
      else if (successRate < 80) riskScore += 15
      
      // Many unique IPs increases risk
      if (uniqueIPs > 5) riskScore += 25
      else if (uniqueIPs > 2) riskScore += 10
      
      // Many unique locations increases risk
      if (uniqueLocations > 3) riskScore += 20
      else if (uniqueLocations > 1) riskScore += 5
      
      // Recent failed logins increase risk
      const recentFailures = recentLogs.filter(log => 
        log.status?.errorCode !== 0 && log.status?.errorCode !== '0'
      ).length
      riskScore += recentFailures * 5

      // Admin app access increases risk
      const adminAccess = logs.some(log => 
        log.appDisplayName?.toLowerCase().includes('admin') ||
        log.appDisplayName?.toLowerCase().includes('portal')
      )
      if (adminAccess) riskScore += 15

      const lastActivity = new Date(
        Math.max(...logs.map(log => 
          new Date(log.time || log.createdDateTime || log.timestamp || 0).getTime()
        ))
      )

      return {
        user: userId,
        displayName: userId.split('@')[0] || userId,
        totalLogs: logs.length,
        recentLogs,
        successCount,
        failureCount,
        successRate,
        lastActivity,
        uniqueIPs,
        uniqueLocations,
        riskScore: Math.min(100, riskScore)
      }
    })

    // Sort by last activity (most recent first) and limit to maxUsers
    return userGroupsArray
      .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
      .slice(0, maxUsers)
  }, [results.rawLogs, maxUsers, maxLogsPerUser])

  const toggleUser = (userId: string) => {
    const newOpenUsers = new Set(openUsers)
    if (newOpenUsers.has(userId)) {
      newOpenUsers.delete(userId)
    } else {
      newOpenUsers.add(userId)
    }
    setOpenUsers(newOpenUsers)
  }

  const getRiskBadge = (riskScore: number) => {
    if (riskScore >= 70) {
      return (
        <Badge className="bg-red-100 text-red-800 border-red-200">
          <Warning className="w-3 h-3 mr-1" />
          Critical
        </Badge>
      )
    } else if (riskScore >= 40) {
      return (
        <Badge className="bg-orange-100 text-orange-800 border-orange-200">
          <Warning className="w-3 h-3 mr-1" />
          High
        </Badge>
      )
    } else if (riskScore >= 20) {
      return (
        <Badge className="bg-yellow-100 text-yellow-800 border-yellow-200">
          <Warning className="w-3 h-3 mr-1" />
          Medium
        </Badge>
      )
    } else {
      return (
        <Badge className="bg-green-100 text-green-800 border-green-200">
          <Shield className="w-3 h-3 mr-1" />
          Low
        </Badge>
      )
    }
  }

  const getStatusBadge = (log: LogEntry) => {
    const isSuccess = log.status?.errorCode === 0 || log.status?.errorCode === '0'
    
    if (isSuccess) {
      return (
        <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 text-xs">
          <CheckCircle className="w-3 h-3 mr-1" />
          Success
        </Badge>
      )
    } else {
      return (
        <Badge variant="outline" className="bg-red-50 text-red-700 border-red-200 text-xs">
          <XCircle className="w-3 h-3 mr-1" />
          Failed
        </Badge>
      )
    }
  }

  const LogDetailDialog = ({ log }: { log: LogEntry }) => (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 px-2">
          <Eye className="w-3 h-3" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>Authentication Log Details</span>
          </DialogTitle>
          <DialogDescription>
            Detailed information for authentication event
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {/* User & App Info */}
          <div className="grid grid-cols-2 gap-4 p-4 bg-muted rounded-lg">
            <div>
              <h4 className="font-medium text-sm mb-1">User</h4>
              <p className="text-sm font-mono">{log.userPrincipalName || log.userId || 'N/A'}</p>
            </div>
            <div>
              <h4 className="font-medium text-sm mb-1">Application</h4>
              <p className="text-sm">{log.appDisplayName || log.resourceDisplayName || 'N/A'}</p>
            </div>
          </div>

          {/* Status & Risk */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium text-sm mb-1">Status</h4>
              {getStatusBadge(log)}
            </div>
            <div>
              <h4 className="font-medium text-sm mb-1">Error Code</h4>
              <p className="text-sm font-mono">{log.status?.errorCode || 'N/A'}</p>
            </div>
          </div>

          {/* Location & Device */}
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Location & Device</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">IP Address</h4>
                <p className="text-sm font-mono">{log.ipAddress || 'N/A'}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Location</h4>
                <p className="text-sm">
                  {log.location ? 
                    `${log.location.city || 'Unknown'}, ${log.location.countryOrRegion || 'Unknown'}` : 
                    'N/A'}
                </p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Operating System</h4>
                <p className="text-sm">{log.deviceDetail?.operatingSystem || 'N/A'}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Browser</h4>
                <p className="text-sm">{log.deviceDetail?.browser || 'N/A'}</p>
              </div>
            </div>
          </div>

          {/* Timestamp */}
          <div>
            <h4 className="font-medium text-sm text-muted-foreground mb-1">Timestamp</h4>
            <p className="text-sm font-mono">
              {new Date(log.time || log.createdDateTime || log.timestamp || 0).toLocaleString()}
            </p>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Users className="w-5 h-5" />
          <span>Recent Activity by User</span>
          <Badge variant="outline">{userGroups.length} users</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {userGroups.map((userGroup) => (
          <Collapsible
            key={userGroup.user}
            open={openUsers.has(userGroup.user)}
            onOpenChange={() => toggleUser(userGroup.user)}
          >
            <CollapsibleTrigger asChild>
              <div className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 cursor-pointer transition-colors">
                <div className="flex items-center space-x-3">
                  <div className="flex items-center space-x-2">
                    {openUsers.has(userGroup.user) ? 
                      <CaretDown className="w-4 h-4" /> : 
                      <CaretRight className="w-4 h-4" />
                    }
                    <div className="w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center">
                      <Users className="w-4 h-4 text-primary" />
                    </div>
                  </div>
                  <div>
                    <h4 className="font-medium">{userGroup.displayName}</h4>
                    <p className="text-sm text-muted-foreground">
                      {userGroup.totalLogs} events • Last active {userGroup.lastActivity.toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="text-right text-sm">
                    <div className="flex items-center space-x-1">
                      <TrendUp className="w-3 h-3 text-green-600" />
                      <span className="text-green-600">{userGroup.successRate.toFixed(1)}%</span>
                    </div>
                    <p className="text-muted-foreground">
                      {userGroup.uniqueIPs} IPs • {userGroup.uniqueLocations} locations
                    </p>
                  </div>
                  {getRiskBadge(userGroup.riskScore)}
                </div>
              </div>
            </CollapsibleTrigger>
            <CollapsibleContent className="px-4 pb-4">
              <div className="space-y-3 mt-3 border-l-2 border-muted ml-2 pl-4">
                <div className="text-sm text-muted-foreground mb-3">
                  Recent {userGroup.recentLogs.length} activities (showing most recent first)
                </div>
                {userGroup.recentLogs.map((log, index) => {
                  const timestamp = new Date(log.time || log.createdDateTime || log.timestamp || 0)
                  const location = log.location ? 
                    `${log.location.city || 'Unknown'}, ${log.location.countryOrRegion || 'Unknown'}` : 
                    'Unknown'
                  
                  return (
                    <div key={index} className="flex items-center justify-between p-3 bg-card border rounded-lg">
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center space-x-2">
                          {getStatusBadge(log)}
                          <span className="text-sm font-medium">
                            {log.appDisplayName || log.resourceDisplayName || 'Unknown App'}
                          </span>
                        </div>
                        <div className="flex items-center space-x-4 text-xs text-muted-foreground">
                          <div className="flex items-center space-x-1">
                            <Clock className="w-3 h-3" />
                            <span>{timestamp.toLocaleString()}</span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <MapPin className="w-3 h-3" />
                            <span>{location}</span>
                          </div>
                          <span className="font-mono">{log.ipAddress || 'N/A'}</span>
                        </div>
                      </div>
                      <LogDetailDialog log={log} />
                    </div>
                  )
                })}
                
                {userGroup.totalLogs > maxLogsPerUser && (
                  <div className="text-center pt-2">
                    <p className="text-sm text-muted-foreground">
                      ... and {userGroup.totalLogs - maxLogsPerUser} more events
                    </p>
                  </div>
                )}
              </div>
            </CollapsibleContent>
          </Collapsible>
        ))}
        
        {userGroups.length === 0 && (
          <div className="text-center py-8 text-muted-foreground">
            <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No user activity data available</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}