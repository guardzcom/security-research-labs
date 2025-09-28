import { useState } from 'react'
import { Shield, Upload, FileText, Warning, TrendUp } from '@phosphor-icons/react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { LogUpload } from '@/components/LogUpload'
import { ThreatSummary } from '@/components/ThreatSummary'
import { AnalysisCharts } from '@/components/AnalysisCharts'
import { CorrelationAnalysis } from '@/components/CorrelationAnalysis'
import { DetailedLogs } from '@/components/DetailedLogs'
import { InstructionsPanel } from '@/components/InstructionsPanel'
import { RecentLogsByUser } from '@/components/RecentLogsByUser'
import { BehavioralAnalysis } from '@/components/BehavioralAnalysis'
import { useKV } from '@github/spark/hooks'
import type { LogEntry, AnalysisResults } from '@/types/security'

function App() {
  const [analysisResults, setAnalysisResults, deleteAnalysisResults] = useKV<AnalysisResults | null>('analysis-results', null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const handleAnalysisComplete = (results: AnalysisResults) => {
    setAnalysisResults(results)
    setIsAnalyzing(false)
  }

  const handleClearData = () => {
    deleteAnalysisResults()
    setIsAnalyzing(false)
  }

  const handleStartAnalysis = () => {
    setIsAnalyzing(true)
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-12 h-12 bg-primary rounded-lg">
                <Shield className="w-6 h-6 text-primary-foreground" weight="fill" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Entra ID Log Analyzer</h1>
                <p className="text-sm text-muted-foreground">
                  Advanced threat detection and behavioral analytics for Azure AD authentication logs
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="outline" className="bg-success/10 text-success border-success/20">
                <TrendUp className="w-3 h-3 mr-1" />
                AI-Powered Analysis
              </Badge>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 max-w-7xl">
        {!analysisResults && !isAnalyzing ? (
          <div className="space-y-8">
            {/* Instructions Panel */}
            <InstructionsPanel />
            
            {/* Upload Section */}
            <LogUpload 
              onAnalysisStart={handleStartAnalysis}
              onAnalysisComplete={handleAnalysisComplete}
            />
          </div>
        ) : isAnalyzing ? (
          <div className="flex items-center justify-center py-16">
            <Card className="w-full max-w-md">
              <CardContent className="pt-6">
                <div className="text-center space-y-4">
                  <div className="w-16 h-16 mx-auto bg-primary/10 rounded-full flex items-center justify-center">
                    <div className="loading-security">
                      <Shield className="w-8 h-8 text-primary" />
                    </div>
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">Analyzing Security Logs</h3>
                    <p className="text-muted-foreground">Processing authentication data and detecting threats...</p>
                  </div>
                  <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
                    <div className="flex space-x-1">
                      <div className="w-2 h-2 bg-primary rounded-full animate-bounce"></div>
                      <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                      <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                    </div>
                    <span>Running behavioral analysis</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : (
          <div className="space-y-8">
            {/* Analysis Results Header with Clear Button */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-foreground">Security Analysis Results</h2>
                <p className="text-muted-foreground">
                  Analyzed {analysisResults!.summary.totalEvents.toLocaleString()} events • 
                  {analysisResults!.summary.uniqueUsers} unique users • 
                  Generated {new Date(analysisResults!.timestamp).toLocaleString()}
                </p>
              </div>
              <Button 
                variant="outline" 
                onClick={handleClearData}
                className="text-muted-foreground hover:text-foreground"
              >
                <FileText className="w-4 h-4 mr-2" />
                New Analysis
              </Button>
            </div>

            {/* Threat Summary Cards */}
            <ThreatSummary results={analysisResults!} />

            {/* Main Analysis Tabs */}
            <Tabs defaultValue="overview" className="space-y-6">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="overview" className="flex items-center space-x-2">
                  <TrendUp className="w-4 h-4" />
                  <span>Overview</span>
                </TabsTrigger>
                <TabsTrigger value="correlations" className="flex items-center space-x-2">
                  <Warning className="w-4 h-4" />
                  <span>Threat Correlations</span>
                </TabsTrigger>
                <TabsTrigger value="behavior" className="flex items-center space-x-2">
                  <Shield className="w-4 h-4" />
                  <span>Behavioral Analysis</span>
                </TabsTrigger>
                <TabsTrigger value="logs" className="flex items-center space-x-2">
                  <FileText className="w-4 h-4" />
                  <span>Detailed Logs</span>
                </TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-6">
                <AnalysisCharts results={analysisResults!} />
                <RecentLogsByUser results={analysisResults!} />
              </TabsContent>

              <TabsContent value="correlations" className="space-y-6">
                <CorrelationAnalysis results={analysisResults!} />
              </TabsContent>

              <TabsContent value="behavior" className="space-y-6">
                <BehavioralAnalysis results={analysisResults!} />
              </TabsContent>

              <TabsContent value="logs" className="space-y-6">
                <DetailedLogs results={analysisResults!} />
              </TabsContent>
            </Tabs>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="border-t bg-card mt-16">
        <div className="container mx-auto px-4 py-6">
          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Made with 💚 by Guardz
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App