"""Live cloud scanning (read-only) for AWS and Azure.

Complements the IaC scanner: instead of reading config files, this logs in to a
live account with your credentials and audits the *actual* resources — read-only
(Describe/Get/List), producing the same validated Findings as everything else.
"""

from cloudnova.cloud.aws import AwsInventory, analyze_aws, scan_aws
from cloudnova.cloud.azure import AzureInventory, analyze_azure, scan_azure

__all__ = [
    "AwsInventory",
    "AzureInventory",
    "analyze_aws",
    "analyze_azure",
    "scan_aws",
    "scan_azure",
]
