"""Live cloud scanning (read-only) for AWS and Azure.

Complements the IaC scanner: instead of reading config files, this logs in to a
live account with your credentials and audits the *actual* resources - read-only
(Describe/Get/List), producing the same validated Findings as everything else.
"""

from cloudnova.cloud.aws import AwsInventory, analyze_aws, scan_aws
from cloudnova.cloud.azure import AzureInventory, analyze_azure, scan_azure
from cloudnova.cloud.gcp import GcpInventory, analyze_gcp, scan_gcp

__all__ = [
    "AwsInventory",
    "AzureInventory",
    "GcpInventory",
    "analyze_aws",
    "analyze_azure",
    "analyze_gcp",
    "scan_aws",
    "scan_azure",
    "scan_gcp",
]
