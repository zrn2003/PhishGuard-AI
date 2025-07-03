'use client';

import { useState } from 'react';
import type { AnalysisResult } from '@/types/analysis';
import UrlInputForm from '@/components/phishhunter/UrlInputForm';
import AnalysisResultDisplay from '@/components/phishhunter/AnalysisResult';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from "@/hooks/use-toast"

export default function PhishGuardPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const { toast } = useToast();

  const handleAnalysis = async (data: { url: string }) => {
    setIsLoading(true);
    setAnalysisResult(null);

    try {
      console.log('Attempting to analyze URL...');
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000); // 20 seconds

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: data.url }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      console.log('Response received:', res.status, res.statusText);
      
      if (!res.ok) {
        let errorMessage = 'Analysis request failed';
        try {
          const errorData = await res.json();
          errorMessage = errorData.error || errorMessage;
        } catch (e) {
          errorMessage = res.statusText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      const result = await res.json();
      
      if (result.classification === 'error') {
        throw new Error(result.error || 'The analysis server returned an error.');
      }

      // Transform the Python API response to match the frontend's expected data structure.
      let riskLevel: 'low' | 'medium' | 'high';
      switch (result.classification) {
        case 'legitimate':
          riskLevel = 'low';
          break;
        case 'suspicious':
          riskLevel = 'medium';
          break;
        case 'fake':
          riskLevel = 'high';
          break;
        default: // Fallback for any unexpected classification
          riskLevel = 'high';
          break;
      }
      
      const securityScore = Math.max(0, 100 - result.security_score);

      const transformedResult: AnalysisResult = {
        url: result.url,
        riskLevel,
        securityScore,
        securityIssues: result.security_issues,
      };

      setAnalysisResult(transformedResult);

    } catch (e: any) {
      console.error('Analysis error:', e);
      let errorMessage = 'Could not analyze the URL. Please try again.';
      
      if (e.name === 'AbortError') {
        errorMessage = 'The request timed out. Please check your connection and try again.';
      } else if (e.message) {
        errorMessage = e.message;
      }

      toast({
        variant: "destructive",
        title: "Analysis Failed",
        description: errorMessage,
      });
    } finally {
      setIsLoading(false);
    }
  };

  const LoadingSkeleton = () => (
    <div className="mt-8 space-y-6">
      <Skeleton className="h-28 w-full" />
      <Skeleton className="h-40 w-full" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-20 w-full" />
      </div>
    </div>
  );

  return (
    <div className="flex-grow flex items-center justify-center">
      <div className="container mx-auto px-4 py-8 md:py-16">
        <header className="text-center mb-12">
          <h1 className="font-headline text-5xl md:text-7xl font-bold tracking-tighter mb-4 bg-gradient-to-br from-primary from-30% to-foreground/80 bg-clip-text text-transparent">
            PhishGuard
          </h1>
          <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto">
            Enter a URL to analyze its potential risk. Our tool will scan for threats and provide a detailed report.
          </p>
        </header>

        <main className="max-w-3xl mx-auto">
          <UrlInputForm onSubmit={handleAnalysis} isLoading={isLoading} />
          
          <div className="mt-8 transition-opacity duration-500 ease-in-out">
            {isLoading && <LoadingSkeleton />}
            
            {analysisResult && (
              <AnalysisResultDisplay result={analysisResult} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
