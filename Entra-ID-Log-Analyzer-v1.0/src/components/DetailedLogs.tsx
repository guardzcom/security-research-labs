import { useState, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { 
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { 
  FileText, 
  MagnifyingGlass, 
  Funnel, 
  Eye,
  MapPin,
  Clock,
  Shield,
  Warning,
  CheckCircle,
  XCircle,
  Download
} from '@phosphor-icons/react'
import type { AnalysisResults, LogEntry } from '@/types/security'

interface DetailedLogsProps {
  results: AnalysisResults
}

export function DetailedLogs({ results }: DetailedLogsProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [userFilter, setUserFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<string>('timestamp')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const logsPerPage = 50

  const { rawLogs, summary } = results

  // Get unique users for filter
  const uniqueUsers = useMemo(() => {
    const users = new Set(rawLogs.map(log => log.userPrincipalName || log.userId || 'Unknown'))
    return Array.from(users).sort()
  }, [rawLogs])

  // Filter and sort logs
  const filteredLogs = useMemo(() => {
    let filtered = rawLogs.filter(log => {
      // Search filter
      if (searchTerm) {
        const searchFields = [
          log.userPrincipalName,
          log.userId,
          log.appDisplayName,
          log.ipAddress,
          log.location?.city,
          log.location?.countryOrRegion
        ].filter(Boolean).join(' ').toLowerCase()
        
        if (!searchFields.includes(searchTerm.toLowerCase())) {
          return false
        }
      }

      // Status filter
      if (statusFilter !== 'all') {
        const isSuccess = log.status?.errorCode === 0 || log.status?.errorCode === '0'
        if (statusFilter === 'success' && !isSuccess) return false
        if (statusFilter === 'failure' && isSuccess) return false
      }

      // User filter
      if (userFilter !== 'all') {
        const user = log.userPrincipalName || log.userId || 'Unknown'
        if (user !== userFilter) return false
      }

      return true
    })

    // Sort logs
    filtered.sort((a, b) => {
      let aValue: any, bValue: any

      switch (sortBy) {
        case 'timestamp':
          aValue = new Date(a.time || a.createdDateTime || a.timestamp || 0)
          bValue = new Date(b.time || b.createdDateTime || b.timestamp || 0)
          break
        case 'user':
          aValue = (a.userPrincipalName || a.userId || 'Unknown').toLowerCase()
          bValue = (b.userPrincipalName || b.userId || 'Unknown').toLowerCase()
          break
        case 'app':
          aValue = (a.appDisplayName || 'Unknown').toLowerCase()
          bValue = (b.appDisplayName || 'Unknown').toLowerCase()
          break
        case 'status':
          aValue = a.status?.errorCode === 0 || a.status?.errorCode === '0' ? 0 : 1
          bValue = b.status?.errorCode === 0 || b.status?.errorCode === '0' ? 0 : 1
          break
        case 'location':
          aValue = (a.location?.city || 'Unknown').toLowerCase()
          bValue = (b.location?.city || 'Unknown').toLowerCase()
          break
        default:
          return 0
      }

      if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1
      if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1
      return 0
    })

    return filtered
  }, [rawLogs, searchTerm, statusFilter, userFilter, sortBy, sortOrder])

  // Paginate logs
  const paginatedLogs = useMemo(() => {
    const startIndex = (currentPage - 1) * logsPerPage
    const endIndex = startIndex + logsPerPage
    return filteredLogs.slice(startIndex, endIndex)
  }, [filteredLogs, currentPage, logsPerPage])

  const totalPages = Math.ceil(filteredLogs.length / logsPerPage)

  const getStatusBadge = (log: LogEntry) => {
    const isSuccess = log.status?.errorCode === 0 || log.status?.errorCode === '0'
    
    if (isSuccess) {
      return (
        <Badge className="bg-green-100 text-green-800 border-green-200">
          <CheckCircle className="w-3 h-3 mr-1" />
          Success
        </Badge>
      )
    } else {
      return (
        <Badge className="bg-red-100 text-red-800 border-red-200">
          <XCircle className="w-3 h-3 mr-1" />
          Failed
        </Badge>
      )
    }
  }

  const getRiskBadge = (log: LogEntry) => {
    // Determine risk level based on various factors
    let riskLevel = 'low'
    const riskFactors: string[] = []

    // Check for suspicious IP
    if (log.ipAddress && !log.ipAddress.startsWith('192.168.') && !log.ipAddress.startsWith('10.')) {
      riskFactors.push('External IP')
    }

    // Check for unusual location
    const commonCountries = ['US', 'GB', 'CA', 'AU', 'DE', 'FR']
    if (log.location?.countryOrRegion && !commonCountries.includes(log.location.countryOrRegion)) {
      riskFactors.push('Uncommon Location')
      riskLevel = 'medium'
    }

    // Check for admin access
    if (log.appDisplayName?.toLowerCase().includes('admin') || 
        log.appDisplayName?.toLowerCase().includes('portal')) {
      riskFactors.push('Admin Access')
      riskLevel = 'medium'
    }

    // Check for failure with external IP
    const isFailure = log.status?.errorCode !== 0 && log.status?.errorCode !== '0'
    if (isFailure && riskFactors.includes('External IP')) {
      riskLevel = 'high'
    }

    if (riskFactors.length === 0) return null

    return (
      <Badge className={`text-xs ${
        riskLevel === 'high' ? 'bg-red-100 text-red-800 border-red-200' :
        riskLevel === 'medium' ? 'bg-yellow-100 text-yellow-800 border-yellow-200' :
        'bg-blue-100 text-blue-800 border-blue-200'
      }`}>
        <Warning className="w-3 h-3 mr-1" />
        {riskLevel.toUpperCase()}
      </Badge>
    )
  }

  const LogDetailDialog = ({ log }: { log: LogEntry }) => (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <Eye className="w-4 h-4" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <FileText className="w-5 h-5" />
            <span>Authentication Log Details</span>
          </DialogTitle>
          <DialogDescription>
            Detailed information for authentication event
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-6">
          {/* Header Info */}
          <div className="grid grid-cols-2 gap-4 p-4 bg-muted rounded-lg">
            <div>
              <h4 className="font-medium text-sm mb-1">Status</h4>
              {getStatusBadge(log)}
            </div>
            <div>
              <h4 className="font-medium text-sm mb-1">Risk Level</h4>
              {getRiskBadge(log) || <Badge variant="outline">Normal</Badge>}
            </div>
          </div>

          {/* User Information */}
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">User Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">User Principal Name</h4>
                <p className="text-sm font-mono">{log.userPrincipalName || 'N/A'}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">User ID</h4>
                <p className="text-sm font-mono">{log.userId || 'N/A'}</p>
              </div>
            </div>
          </div>

          {/* Authentication Details */}
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Authentication Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Application</h4>
                <p className="text-sm">{log.appDisplayName || log.resourceDisplayName || 'N/A'}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Timestamp</h4>
                <p className="text-sm font-mono">
                  {new Date(log.time || log.createdDateTime || log.timestamp || 0).toLocaleString()}
                </p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Error Code</h4>
                <p className="text-sm font-mono">{log.status?.errorCode || 'N/A'}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Conditional Access</h4>
                <p className="text-sm">{log.conditionalAccessStatus || 'N/A'}</p>
              </div>
            </div>
          </div>

          {/* Location & Device */}
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Location & Device Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">IP Address</h4>
                <p className="text-sm font-mono">{log.ipAddress || 'N/A'}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Location</h4>
                <p className="text-sm">
                  {log.location ? `${log.location.city || 'Unknown'}, ${log.location.countryOrRegion || 'Unknown'}` : 'N/A'}
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
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Device Compliant</h4>
                <p className="text-sm">
                  {log.deviceDetail?.isCompliant !== undefined ? 
                    log.deviceDetail.isCompliant ? 'Yes' : 'No' : 'N/A'}
                </p>
              </div>
              <div>
                <h4 className="font-medium text-sm text-muted-foreground">Device Managed</h4>
                <p className="text-sm">
                  {log.deviceDetail?.isManaged !== undefined ? 
                    log.deviceDetail.isManaged ? 'Yes' : 'No' : 'N/A'}
                </p>
              </div>
            </div>
          </div>

          {/* Risk Assessment */}
          {log.riskDetail && (
            <div className="space-y-3">
              <h3 className="text-lg font-semibold">Risk Assessment</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium text-sm text-muted-foreground">Risk Level</h4>
                  <p className="text-sm">{log.riskDetail.riskLevel || 'N/A'}</p>
                </div>
                <div>
                  <h4 className="font-medium text-sm text-muted-foreground">Risk State</h4>
                  <p className="text-sm">{log.riskDetail.riskState || 'N/A'}</p>
                </div>
              </div>
              {log.riskDetail.riskEventTypes && log.riskDetail.riskEventTypes.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm text-muted-foreground mb-2">Risk Event Types</h4>
                  <div className="flex flex-wrap gap-2">
                    {log.riskDetail.riskEventTypes.map((eventType, index) => (
                      <Badge key={index} variant="outline">{eventType}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Raw JSON */}
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Raw Log Data</h3>
            <div className="bg-muted p-4 rounded-lg max-h-64 overflow-y-auto">
              <pre className="text-xs font-mono whitespace-pre-wrap">
                {JSON.stringify(log, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )

  const exportLogs = () => {
    const csvData = filteredLogs.map(log => ({
      Timestamp: new Date(log.time || log.createdDateTime || log.timestamp || 0).toISOString(),
      User: log.userPrincipalName || log.userId || 'Unknown',
      Application: log.appDisplayName || 'Unknown',
      Status: log.status?.errorCode === 0 || log.status?.errorCode === '0' ? 'Success' : 'Failed',
      ErrorCode: log.status?.errorCode || '',
      IPAddress: log.ipAddress || '',
      Location: log.location ? `${log.location.city || ''}, ${log.location.countryOrRegion || ''}` : '',
      Device: log.deviceDetail?.operatingSystem || '',
      Browser: log.deviceDetail?.browser || ''
    }))

    const csvContent = [
      Object.keys(csvData[0]).join(','),
      ...csvData.map(row => Object.values(row).map(val => `"${val}"`).join(','))
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `entra-logs-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <FileText className="w-5 h-5" />
              <span>Authentication Logs</span>
              <Badge variant="outline">
                {filteredLogs.length.toLocaleString()} / {rawLogs.length.toLocaleString()} events
              </Badge>
            </CardTitle>
            <Button onClick={exportLogs} variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export CSV
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4 mb-4">
            {/* Search */}
            <div className="flex-1 min-w-64">
              <div className="relative">
                <MagnifyingGlass className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search users, apps, IPs, locations..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            {/* Status Filter */}
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="All Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="success">Success Only</SelectItem>
                <SelectItem value="failure">Failed Only</SelectItem>
              </SelectContent>
            </Select>

            {/* User Filter */}
            <Select value={userFilter} onValueChange={setUserFilter}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="All Users" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Users</SelectItem>
                {uniqueUsers.slice(0, 20).map(user => (
                  <SelectItem key={user} value={user}>
                    {user.split('@')[0] || user}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Sort */}
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="timestamp">Timestamp</SelectItem>
                <SelectItem value="user">User</SelectItem>
                <SelectItem value="app">Application</SelectItem>
                <SelectItem value="status">Status</SelectItem>
                <SelectItem value="location">Location</SelectItem>
              </SelectContent>
            </Select>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
            >
              {sortOrder === 'asc' ? '↑' : '↓'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Logs Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-40">
                    <div className="flex items-center space-x-1">
                      <Clock className="w-4 h-4" />
                      <span>Timestamp</span>
                    </div>
                  </TableHead>
                  <TableHead className="w-48">User</TableHead>
                  <TableHead className="w-48">Application</TableHead>
                  <TableHead className="w-24">Status</TableHead>
                  <TableHead className="w-32">
                    <div className="flex items-center space-x-1">
                      <MapPin className="w-4 h-4" />
                      <span>Location</span>
                    </div>
                  </TableHead>
                  <TableHead className="w-32">IP Address</TableHead>
                  <TableHead className="w-24">Risk</TableHead>
                  <TableHead className="w-16">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedLogs.map((log, index) => {
                  const timestamp = new Date(log.time || log.createdDateTime || log.timestamp || 0)
                  const user = log.userPrincipalName || log.userId || 'Unknown'
                  const app = log.appDisplayName || log.resourceDisplayName || 'Unknown'
                  const location = log.location ? 
                    `${log.location.city || 'Unknown'}, ${log.location.countryOrRegion || 'Unknown'}` : 
                    'Unknown'

                  return (
                    <TableRow key={index} className="hover:bg-muted/50">
                      <TableCell className="font-mono text-xs">
                        {timestamp.toLocaleString()}
                      </TableCell>
                      <TableCell className="truncate max-w-48">
                        <div className="truncate">{user}</div>
                      </TableCell>
                      <TableCell className="truncate max-w-48">
                        <div className="truncate">{app}</div>
                      </TableCell>
                      <TableCell>
                        {getStatusBadge(log)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {location}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {log.ipAddress || 'N/A'}
                      </TableCell>
                      <TableCell>
                        {getRiskBadge(log)}
                      </TableCell>
                      <TableCell>
                        <LogDetailDialog log={log} />
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-6 py-4 border-t">
              <div className="text-sm text-muted-foreground">
                Showing {((currentPage - 1) * logsPerPage) + 1} to {Math.min(currentPage * logsPerPage, filteredLogs.length)} of {filteredLogs.length} results
              </div>
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </Button>
                <div className="flex items-center space-x-1">
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    const page = i + Math.max(1, currentPage - 2)
                    if (page > totalPages) return null
                    return (
                      <Button
                        key={page}
                        variant={currentPage === page ? "default" : "outline"}
                        size="sm"
                        onClick={() => setCurrentPage(page)}
                        className="w-8 h-8 p-0"
                      >
                        {page}
                      </Button>
                    )
                  })}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}