export interface SecurityIssues {
  [key: string]: any;
  ip_address: boolean;
  http_not_https: boolean;
  has_at_symbol: boolean;
  long_url: boolean;
  many_subdomains: boolean;
  suspicious_keywords: boolean;
  typosquatting: boolean;
  typosquatting_similarity?: number;
  most_similar_domain?: string;
  suspicious_tld: boolean;
  random_chars: boolean;
}

export interface AnalysisResult {
  url: string;
  riskLevel: 'low' | 'medium' | 'high';
  securityScore: number;
  securityIssues: SecurityIssues;
  explanations?: string[];
  confidence?: number;
  features?: { [key: string]: any };
}
