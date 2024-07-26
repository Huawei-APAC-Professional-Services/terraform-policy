from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from base.securitygroups import UnRestrictedIngressTraffic
class SecurityGroupUnrestrictedIngress3389(UnRestrictedIngressTraffic):
    def __init__(self):
        super().__init__(check_id="CKV_HWC_NET_2", port=3389)
    

check = SecurityGroupUnrestrictedIngress3389()