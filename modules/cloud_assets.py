import requests
import boto3
from azure.storage.blob import BlobServiceClient
from typing import List, Dict

class CloudScanner:
    def __init__(self, aws_keys: Dict = None, azure_conn: str = None):
        self.aws_keys = aws_keys
        self.azure_conn = azure_conn
        
    def scan_s3_buckets(self, company_name: str) -> List[Dict]:
        """Discover exposed S3 buckets"""
        buckets = []
        common_patterns = [
            company_name,
            f"{company_name}-public",
            f"{company_name}-assets",
            f"{company_name}-cdn",
            f"{company_name}-backup"
        ]
        
        for pattern in common_patterns:
            bucket_name = pattern.lower().replace('_', '-')
            if self.check_s3_bucket_access(bucket_name):
                buckets.append({
                    'name': bucket_name,
                    'type': 's3',
                    'public': True,
                    'url': f"https://{bucket_name}.s3.amazonaws.com"
                })
                
        return buckets
    
    def check_s3_bucket_access(self, bucket_name: str) -> bool:
        """Check if S3 bucket is publicly accessible"""
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com"
            response = requests.get(url, timeout=5)
            
            # Check if bucket listing is enabled
            if response.status_code == 200:
                if 'ListBucketResult' in response.text:
                    return True
            return False
        except:
            return False
    
    def scan_azure_blobs(self, account_name: str) -> List[Dict]:
        """Discover exposed Azure blobs"""
        blobs = []
        try:
            url = f"https://{account_name}.blob.core.windows.net/"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                blobs.append({
                    'name': account_name,
                    'type': 'azure_blob',
                    'url': url
                })
        except:
            pass
            
        return blobs
    
    def scan_github_repos(self, org_name: str) -> List[Dict]:
        """Scan GitHub for exposed repositories"""
        repos = []
        url = f"https://api.github.com/orgs/{org_name}/repos"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for repo in response.json():
                    if not repo.get('private', True):
                        repos.append({
                            'name': repo['name'],
                            'url': repo['html_url'],
                            'description': repo.get('description', ''),
                            'type': 'github'
                        })
        except:
            pass
            
        return repos
    
    def check_public_storage(self, base_name: str) -> List[Dict]:
        """Check multiple cloud storage providers"""
        results = []
        
        # Check S3
        results.extend(self.scan_s3_buckets(base_name))
        
        # Check Azure
        results.extend(self.scan_azure_blobs(base_name))
        
        # Check GCP
        gcp_url = f"https://storage.googleapis.com/{base_name}"
        try:
            response = requests.get(gcp_url, timeout=5)
            if response.status_code == 200:
                results.append({
                    'name': base_name,
                    'type': 'gcp_bucket',
                    'url': gcp_url
                })
        except:
            pass
            
        return results
