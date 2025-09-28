import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  GlobeHemisphereWest, 
  Terminal, 
  Clock, 
  ShieldCheck, 
  ChartBar,
  Info
} from '@phosphor-icons/react'

export function InstructionsPanel() {
  const [isExpanded, setIsExpanded] = useState(false)

  return (
    <Card className="border-info/20 bg-gradient-to-r from-info/5 to-primary/5">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-10 h-10 bg-info/10 rounded-lg">
              <Info className="w-5 h-5 text-info" />
            </div>
            <div>
              <CardTitle className="text-lg">How to Download Entra ID Sign-in Logs</CardTitle>
              <p className="text-sm text-muted-foreground">
                Get your authentication logs for comprehensive security analysis
              </p>
            </div>
          </div>
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-info hover:text-info/80"
          >
            {isExpanded ? 'Hide Instructions' : 'Show Instructions'}
          </Button>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="pt-0">
          <Tabs defaultValue="portal" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="portal" className="flex items-center space-x-2">
                <GlobeHemisphereWest className="w-4 h-4" />
                <span>Admin Center</span>
              </TabsTrigger>
              <TabsTrigger value="powershell" className="flex items-center space-x-2">
                <Terminal className="w-4 h-4" />
                <span>PowerShell</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="portal" className="mt-6">
              <div className="space-y-4">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h3 className="font-semibold text-base flex items-center space-x-2">
                      <GlobeHemisphereWest className="w-5 h-5 text-primary" />
                      <span>Interactive Download</span>
                    </h3>
                    <ol className="list-decimal list-inside space-y-3 text-sm leading-relaxed">
                      <li>Navigate to <strong>entra.microsoft.com</strong></li>
                      <li>Go to <strong>Users</strong> → <strong>Sign-in logs</strong></li>
                      <li>Set date range: <Badge variant="outline">Last 7 days</Badge></li>
                      <li>Apply filters for users, apps, or status if needed</li>
                      <li>Click <strong>Download</strong> button</li>
                      <li>Select <Badge variant="secondary">JSON</Badge> format</li>
                      <li>Choose date range (max 250,000 records)</li>
                      <li>Confirm download and wait for file generation</li>
                    </ol>
                  </div>
                  
                  <div className="space-y-4">
                    <h3 className="font-semibold text-base flex items-center space-x-2">
                      <ShieldCheck className="w-5 h-5 text-success" />
                      <span>Best Practices</span>
                    </h3>
                    <div className="space-y-3">
                      <div className="p-3 bg-success/10 border border-success/20 rounded-lg">
                        <div className="flex items-center space-x-2 mb-1">
                          <Clock className="w-4 h-4 text-success" />
                          <span className="font-medium text-success text-sm">Recommended Timeframe</span>
                        </div>
                        <p className="text-xs text-success/80">
                          Download 7-30 days for comprehensive analysis
                        </p>
                      </div>
                      
                      <div className="p-3 bg-warning/10 border border-warning/20 rounded-lg">
                        <div className="flex items-center space-x-2 mb-1">
                          <ChartBar className="w-4 h-4 text-warning" />
                          <span className="font-medium text-warning text-sm">Performance</span>
                        </div>
                        <p className="text-xs text-warning/80">
                          Large datasets over 50MB may take longer to process
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="powershell" className="mt-6">
              <div className="space-y-4">
                <h3 className="font-semibold text-base flex items-center space-x-2">
                  <Terminal className="w-5 h-5 text-primary" />
                  <span>Automated PowerShell Download</span>
                </h3>
                
                <div className="bg-card border rounded-lg p-4 font-mono text-sm space-y-3">
                  <div className="text-muted-foreground"># Install required module</div>
                  <div className="text-foreground">Install-Module Microsoft.Graph</div>
                  
                  <div className="h-2"></div>
                  <div className="text-muted-foreground"># Connect with required permissions</div>
                  <div className="text-foreground">Connect-MgGraph -Scopes "AuditLog.Read.All"</div>
                  
                  <div className="h-2"></div>
                  <div className="text-muted-foreground"># Export sign-in logs to JSON</div>
                  <div className="text-foreground">Get-MgAuditLogSignIn -All | ConvertTo-Json -Depth 10</div>
                  
                  <div className="h-2"></div>
                  <div className="text-muted-foreground"># Save to file</div>
                  <div className="text-foreground">Get-MgAuditLogSignIn -All | ConvertTo-Json -Depth 10 | Out-File "signin-logs.json"</div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                  <div className="text-center p-4 bg-info/10 border border-info/20 rounded-lg">
                    <h4 className="font-semibold text-info mb-1 text-sm">Data Quality</h4>
                    <p className="text-xs text-info/80">
                      Include both interactive and non-interactive sign-ins
                    </p>
                  </div>
                  <div className="text-center p-4 bg-warning/10 border border-warning/20 rounded-lg">
                    <h4 className="font-semibold text-warning mb-1 text-sm">Rate Limits</h4>
                    <p className="text-xs text-warning/80">
                      Graph API has throttling - use pagination for large datasets
                    </p>
                  </div>
                  <div className="text-center p-4 bg-success/10 border border-success/20 rounded-lg">
                    <h4 className="font-semibold text-success mb-1 text-sm">Permissions</h4>
                    <p className="text-xs text-success/80">
                      Requires AuditLog.Read.All scope for comprehensive data
                    </p>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      )}
    </Card>
  )
}