'use client';

import type { AnalysisResult, SecurityIssues } from '@/types/analysis';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import {
  AlertCircle,
  AlertTriangle,
  FileScan,
  Globe,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Shuffle,
  Unlock,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { ChevronDown, ChevronUp, Flag } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const riskConfig = {
  low: {
    label: 'Risk',
    className: 'bg-primary/10 text-primary border-primary/20',
    progressClass: 'bg-primary',
    Icon: (props: React.ComponentProps<LucideIcon>) => <ShieldCheck {...props} />,
    description: (score: number) => `With a high security score of ${score}, this URL appears to be safe.`,
  },
  medium: {
    label: 'Medium Risk',
    className: 'bg-accent/20 text-accent-foreground border-accent/30',
    progressClass: 'bg-accent',
    Icon: (props: React.ComponentProps<LucideIcon>) => <ShieldAlert {...props} className="text-accent" />,
    description: (score: number) => `With a score of ${score}, some potential issues were detected. Proceed with caution.`,
  },
  high: {
    label: 'High Risk',
    className: 'bg-destructive/10 text-destructive border-destructive/20',
    progressClass: 'bg-destructive',
    Icon: (props: React.ComponentProps<LucideIcon>) => <AlertTriangle {...props} />,
    description: (score: number) => `A low score of ${score} means this URL is potentially dangerous. We advise against visiting it.`,
  },
};

const getDetailItems = (issues?: SecurityIssues) => {
  const items: { Icon: LucideIcon; title: string; description: string; isIssue: boolean }[] = [];
  if (!issues) {
    return items;
  }

  if (issues.http_not_https) {
    items.push({
      Icon: Unlock,
      title: 'Not Secure (HTTP)',
      description: 'The connection to this site is not encrypted, making it vulnerable.',
      isIssue: true,
    });
  }
  if (issues.ip_address) {
    items.push({
      Icon: AlertTriangle,
      title: 'Uses IP Address',
      description: 'Using an IP address instead of a domain name can be a red flag.',
      isIssue: true,
    });
  }
  if (issues.has_at_symbol) {
    items.push({
      Icon: AlertTriangle,
      title: 'Contains "@" Symbol',
      description: 'The "@" symbol can be used to obscure the actual domain.',
      isIssue: true,
    });
  }
  if (issues.long_url) {
    items.push({
      Icon: AlertTriangle,
      title: 'Very Long URL',
      description: 'Unusually long URLs are sometimes used to hide malicious links.',
      isIssue: true,
    });
  }
  if (issues.many_subdomains) {
    items.push({
      Icon: AlertTriangle,
      title: 'Multiple Subdomains',
      description: 'Excessive subdomains can be a tactic to confuse users.',
      isIssue: true,
    });
  }
  if (issues.suspicious_keywords) {
    items.push({
      Icon: FileScan,
      title: 'Suspicious Keywords',
      description: 'The URL contains words often associated with phishing (e.g., "login", "secure").',
      isIssue: true,
    });
  }
  if (issues.typosquatting) {
    items.push({
      Icon: AlertCircle,
      title: 'Potential Typosquatting',
      description: `This URL is very similar to "${issues.most_similar_domain}" and may be an impersonation attempt.`,
      isIssue: true,
    });
  }
  if (issues.suspicious_tld) {
    items.push({
      Icon: Globe,
      title: 'Suspicious TLD',
      description: 'The top-level domain (e.g., .xyz, .top) is often used for malicious sites.',
      isIssue: true,
    });
  }
  if (issues.random_chars) {
    items.push({
      Icon: Shuffle,
      title: 'Random Characters',
      description: 'The domain contains random-looking characters, a common phishing pattern.',
      isIssue: true,
    });
  }

  if (items.length === 0) {
    items.push({
      Icon: ShieldCheck,
      title: 'All Clear',
      description: 'This URL appears safe and passes all our security checks.',
      isIssue: false,
    });
  }

  return items;
};

export default function AnalysisResultDisplay({ result }: { result: AnalysisResult }) {
  const config = riskConfig[result.riskLevel];
  const details = getDetailItems(result.securityIssues);
  const [reported, setReported] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleReport = () => {
    setReported(true);
    // Here you could send a report to your backend or analytics
    // e.g., fetch('/api/report', { method: 'POST', body: JSON.stringify({ url: result.url }) })
  };

  const handleHelpful = () => setFeedback('Thank you for your feedback!');
  const handleNotHelpful = () => setFeedback('We appreciate your feedback and will use it to improve.');

  return (
    <TooltipProvider>
      <div className="space-y-6 animate-in fade-in duration-500">
        <Card className={config.className + ' relative'}>
          <CardHeader>
            <div className="flex flex-row items-center gap-4 space-y-0">
              <Tooltip>
                <TooltipTrigger asChild>
                  <span><config.Icon className="h-10 w-10" /></span>
                </TooltipTrigger>
                <TooltipContent>
                  <span>{config.label}</span>
                </TooltipContent>
              </Tooltip>
              <div>
                <CardTitle className="text-2xl font-bold flex items-center gap-2">
                  {config.label}
                </CardTitle>
                <CardDescription className="text-base mt-1">{config.description(result.securityScore)}</CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-3 pt-3">
              <span className="text-sm font-medium w-28">Security Score</span>
              <Progress value={result.securityScore} className="h-2 flex-1" indicatorClassName={config.progressClass} />
              <span className="text-lg font-bold">{result.securityScore}</span>
            </div>
            {typeof result.confidence === 'number' && (
              <div className="pt-2 text-sm text-muted-foreground">
                <b>Model Confidence:</b> {(result.confidence * 100).toFixed(1)}%
              </div>
            )}
            {result.explanations && result.explanations.length > 0 && (
              <div className="pt-2">
                <b>Why this result?</b>
                <ul className="list-disc list-inside text-sm mt-1">
                  {result.explanations.map((ex, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-accent shrink-0" />
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span>{ex}</span>
                        </TooltipTrigger>
                        <TooltipContent>
                          <span>Explanation: {ex}</span>
                        </TooltipContent>
                      </Tooltip>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="flex gap-2 pt-4">
              <Button variant="destructive" size="sm" onClick={handleReport} disabled={reported} className="flex items-center gap-1">
                <Flag className="w-4 h-4" />
                {reported ? 'Reported' : 'Report as Incorrect'}
              </Button>
            </div>
          </CardHeader>
        </Card>
        <div className="flex gap-2 mt-2">
          <button aria-label="Mark as helpful" onClick={handleHelpful}>👍</button>
          <button aria-label="Mark as not helpful" onClick={handleNotHelpful}>👎</button>
        </div>
        {feedback && <div className="text-green-700 bg-green-50 p-2 rounded mt-2">{feedback}</div>}
        {error && <div className="text-red-600 bg-red-50 p-2 rounded">{error}</div>}
      </div>
    </TooltipProvider>
  );
}
