import { useState, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Upload, FileText, Warning, CheckCircle } from '@phosphor-icons/react'
import { toast } from 'sonner'
import type { LogEntry, AnalysisResults } from '@/types/security'
import { analyzeSecurityLogs } from '@/lib/security-analyzer'

interface LogUploadProps {
  onAnalysisStart: () => void
  onAnalysisComplete: (results: AnalysisResults) => void
}

export function LogUpload({ onAnalysisStart, onAnalysisComplete }: LogUploadProps) {
  const [logData, setLogData] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [validationStatus, setValidationStatus] = useState<'none' | 'valid' | 'invalid'>('none')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileUpload = (file: File) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      const content = e.target?.result as string
      handleTextareaChange(content)
    }
    reader.onerror = () => {
      setError('Error reading file. Please try again.')
      toast.error('Failed to read file')
    }
    reader.readAsText(file)
  }

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    setError(null)

    const files = Array.from(e.dataTransfer.files)
    const jsonFile = files.find(file => 
      file.type === 'application/json' || 
      file.name.endsWith('.json') || 
      file.name.endsWith('.txt')
    )

    if (jsonFile) {
      handleFileUpload(jsonFile)
    } else {
      setError('Please upload a JSON or text file containing log data.')
    }
  }

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setError(null)
      handleFileUpload(file)
    }
  }

  const validateJsonData = (data: string) => {
    if (!data.trim()) {
      setValidationStatus('none')
      return
    }

    try {
      // Try to parse as JSON
      let parsed: any
      
      // Try standard JSON first
      try {
        parsed = JSON.parse(data)
      } catch {
        // Try NDJSON (newline-delimited JSON)
        const lines = data.split('\n').filter(line => line.trim())
        if (lines.length > 1) {
          parsed = lines.map(line => JSON.parse(line.trim()))
        } else {
          throw new Error('Invalid JSON format')
        }
      }

      // Validate it's an array or convert single object to array
      const logArray = Array.isArray(parsed) ? parsed : [parsed]
      
      // Basic validation - check for common log fields
      const hasValidEntries = logArray.some(entry => 
        entry && typeof entry === 'object' && (
          entry.time || entry.createdDateTime || entry.timestamp ||
          entry.userPrincipalName || entry.userId
        )
      )

      if (hasValidEntries) {
        setValidationStatus('valid')
        setError(null)
      } else {
        setValidationStatus('invalid')
        setError('Data appears to be valid JSON but doesn\'t contain expected log fields (time, userPrincipalName, etc.)')
      }
    } catch (parseError) {
      setValidationStatus('invalid')
      setError('Invalid JSON format. Please check your data and try again.')
    }
  }

  const handleTextareaChange = (value: string) => {
    setLogData(value)
    validateJsonData(value)
  }

  const handleAnalyze = async () => {
    if (!logData.trim()) {
      toast.error('Please provide log data to analyze')
      return
    }

    if (validationStatus !== 'valid') {
      toast.error('Please provide valid JSON log data')
      return
    }

    try {
      onAnalysisStart()
      toast.info('Starting security analysis...')
      
      // Parse the log data
      let parsed: any
      try {
        parsed = JSON.parse(logData)
      } catch {
        // Try NDJSON
        const lines = logData.split('\n').filter(line => line.trim())
        parsed = lines.map(line => JSON.parse(line.trim()))
      }

      const logArray: LogEntry[] = Array.isArray(parsed) ? parsed : [parsed]
      
      // Analyze the logs
      const results = await analyzeSecurityLogs(logArray)
      
      toast.success(`Analysis complete! Found ${results.threats.length} threats and ${results.summary.totalEvents} events`)
      onAnalysisComplete(results)
    } catch (error) {
      console.error('Analysis error:', error)
      toast.error('Failed to analyze logs. Please check your data format.')
      setError(`Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const loadSampleData = () => {
    const sampleData = [
      {
        "time": "2024-01-15T08:30:00Z",
        "userPrincipalName": "john.doe@company.com",
        "appDisplayName": "Microsoft Office 365",
        "status": { "errorCode": 0 },
        "location": { "city": "New York", "countryOrRegion": "US" },
        "ipAddress": "192.168.1.100",
        "deviceDetail": { "browser": "Chrome", "operatingSystem": "Windows", "isManaged": true },
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "userType": "Member",
        "userRoles": ["User"],
        "operationType": "SignIn"
      },
      {
        "time": "2024-01-15T08:35:00Z",
        "userPrincipalName": "jane.smith@company.com",
        "appDisplayName": "Azure Portal",
        "status": { "errorCode": 50126 },
        "location": { "city": "London", "countryOrRegion": "GB" },
        "ipAddress": "10.0.1.50",
        "deviceDetail": { "browser": "Edge", "operatingSystem": "Windows", "isManaged": true },
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "userType": "Member",
        "userRoles": ["Security Reader"],
        "operationType": "SignIn"
      },
      {
        "time": "2024-01-15T09:00:00Z",
        "userPrincipalName": "admin@company.com",
        "appDisplayName": "Microsoft Teams",
        "status": { "errorCode": 0 },
        "location": { "city": "Seattle", "countryOrRegion": "US" },
        "ipAddress": "172.16.0.10",
        "deviceDetail": { "browser": "Teams Desktop", "operatingSystem": "Windows", "isManaged": true },
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Teams/1.4.00.26453",
        "userType": "Member",
        "userRoles": ["Global Administrator", "Security Administrator"],
        "operationType": "SignIn"
      },
      {
        "time": "2024-01-15T09:15:00Z",
        "userPrincipalName": "john.doe@company.com",
        "appDisplayName": "SharePoint Online",
        "status": { "errorCode": 0 },
        "location": { "city": "New York", "countryOrRegion": "US" },
        "ipAddress": "192.168.1.100",
        "deviceDetail": { "browser": "Chrome", "operatingSystem": "Windows", "isManaged": true },
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "userType": "Member",
        "userRoles": ["User"],
        "operationType": "FileAccess"
      },
      {
        "time": "2024-01-15T10:00:00Z",
        "userPrincipalName": "test.user@company.com",
        "appDisplayName": "Azure Active Directory PowerShell",
        "status": { "errorCode": 50053 },
        "location": { "city": "Moscow", "countryOrRegion": "RU" },
        "ipAddress": "5.45.123.45",
        "deviceDetail": { "browser": "Unknown", "operatingSystem": "Linux", "isManaged": false },
        "userAgent": "PowerShell/7.2.0",
        "userType": "Guest",
        "userRoles": ["Directory Readers"],
        "operationType": "RoleAssignment"
      },
      {
        "time": "2024-01-15T10:30:00Z",
        "userPrincipalName": "admin@company.com",
        "appDisplayName": "Microsoft Graph PowerShell",
        "status": { "errorCode": 0 },
        "location": { "city": "Tokyo", "countryOrRegion": "JP" },
        "ipAddress": "203.0.113.42",
        "deviceDetail": { "browser": "PowerShell", "operatingSystem": "Windows", "isManaged": true },
        "userAgent": "Microsoft.Graph.PowerShell/1.15.0",
        "userType": "Member",
        "userRoles": ["Global Administrator"],
        "operationType": "UserCreation"
      }
    ]
    
    const sampleJson = JSON.stringify(sampleData, null, 2)
    handleTextareaChange(sampleJson)
    toast.success('Sample data loaded successfully')
  }

  const clearData = () => {
    setLogData('')
    setError(null)
    setValidationStatus('none')
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
    toast.info('Data cleared')
  }

  return (
    <div className="space-y-6">
      {/* File Upload Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Upload className="w-5 h-5" />
            <span>Upload Security Logs</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* File Upload Area */}
          <div className="space-y-4">
            <Label htmlFor="file-upload">Upload JSON Log File</Label>
            <div
              className={`border-2 border-dashed rounded-lg p-6 transition-colors ${
                dragActive 
                  ? 'border-primary bg-primary/5' 
                  : 'border-muted-foreground/25 hover:border-muted-foreground/50'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              <div className="flex flex-col items-center justify-center text-center space-y-4">
                <Upload className="w-12 h-12 text-muted-foreground" />
                <div className="space-y-2">
                  <p className="text-lg font-medium">
                    Drop your JSON log file here, or click to browse
                  </p>
                  <p className="text-sm text-muted-foreground">
                    Supports .json and .txt files containing Entra ID authentication logs
                  </p>
                </div>
                <div className="flex items-center space-x-4">
                  {validationStatus !== 'none' && (
                    <Badge variant={validationStatus === 'valid' ? 'default' : 'destructive'}>
                      {validationStatus === 'valid' ? (
                        <>
                          <CheckCircle className="w-3 h-3 mr-1" />
                          Valid JSON
                        </>
                      ) : (
                        <>
                          <Warning className="w-3 h-3 mr-1" />
                          Invalid Format
                        </>
                      )}
                    </Badge>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <FileText className="w-4 h-4 mr-2" />
                    Select File
                  </Button>
                </div>
              </div>
              <input
                ref={fileInputRef}
                id="file-upload"
                type="file"
                accept=".json,.txt"
                onChange={handleFileInputChange}
                className="hidden"
              />
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <Alert variant="destructive">
              <Warning className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3">
            <Button 
              onClick={handleAnalyze}
              disabled={validationStatus !== 'valid' || !logData.trim()}
              className="flex items-center space-x-2"
            >
              <CheckCircle className="w-4 h-4" />
              <span>Analyze Logs</span>
            </Button>
            <Button variant="outline" onClick={loadSampleData}>
              <FileText className="w-4 h-4 mr-2" />
              Load Sample Data
            </Button>
            <Button 
              variant="outline" 
              onClick={clearData}
              disabled={!logData.trim()}
            >
              Clear
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}