from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class UnRestrictedIngressTraffic(BaseResourceCheck):
    def __init__(self, check_id, port):
        name = "Ensure no security groups allow ingress from 0.0.0.0 to port %d" % port
        supported_resources = ['huaweicloud_networking_secgroup_rule']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=check_id, categories=categories, supported_resources=supported_resources)
        self.port = port
        
    def scan_resource_conf(self, conf: dict[str,list[any]]) -> CheckResult:
        """
            Looks for configuration at security group ingress rules :
            https://registry.terraform.io/providers/huaweicloud/huaweicloud/latest/docs/resources/networking_secgroup_rule

            Return PASS if:
            - The resource is an huaweicloud_networking_secgroup_rule 'ingress' that does not violate the check.
            - The resource is not an huaweicloud_networking_secgroup_rule
            - The resource is an huaweicloud_networking_secgroup_rule of type "Egress"

            Return FAIL if:
            - The resource is an huaweicloud_networking_secgroup_rule of type 'ingress' that violates the check.

        :param conf: huaweicloud_networking_secgroup_rule configuration
        :return: <CheckResult>
        """

        if conf['direction'][0] == 'egress':  # This means it's an huaweicloud_networking_secgroup_rule egress resource.
            return CheckResult.PASSED
        
        # This means if this rule's effect is deny and no need to check it
        if 'action' in conf and conf['action'][0] == 'deny':
            return CheckResult.PASSED
        
        # This means this group uses ip address group which doesn't allow 0.0.0.0/0
        if 'remote_ip_prefix' not in conf:
            return CheckResult.PASSED
        
        if conf['remote_ip_prefix'][0] == '0.0.0.0/0':
            if 'port_range_min' in conf:
                if int(conf['port_range_min'][0]) <= int(self.port) <= int(conf['port_range_max'][0]):
                    return CheckResult.FAILED
            
            if 'ports' in conf:
                if str(self.port) in str.split(conf['ports'][0],","):
                    return CheckResult.FAILED
        
        return CheckResult.PASSED
    

class SecurityGroupUnrestrictedIngress22(UnRestrictedIngressTraffic):
    def __init__(self):
        super().__init__(check_id="HW_NETWORK_001", port=22)
    

check = SecurityGroupUnrestrictedIngress22()