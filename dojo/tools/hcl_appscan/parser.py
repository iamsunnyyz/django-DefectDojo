from xml.dom import NamespaceErr
from defusedxml import ElementTree as ET
from dojo.models import Endpoint, Finding

class HCLAppScanParser:
    def get_scan_types(self):
        return ["HCLAppScan XML"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import XML output of HCL AppScan."

    def xmltreehelper(self, input):
        if input.text is None:
            output = None
        elif "\n" in input.text:
            output = ""
            for i in input:
                output = output + " " + i.text
        else:
            output = " " + input.text
        return output

    def get_findings(self, file, test):
        findings = []
        tree = ET.parse(file)
        root = tree.getroot()
        if "xml-report" not in root.tag:
            msg = "This doesn't seem to be a valid HCLAppScan xml file."
            raise NamespaceErr(msg)
        report = root.find("issue-group")
        if report is not None:
            for finding in report:
                name = ""
                description = ""
                remediation = ""
                advisory = ""
                severity = "Info"
                cwe = 0
                impact = "Null"
                steps_to_reproduce = "Null"
                severity_justification = "Null"
                references = "Null"
                host = ""
                port = ""
                domain = ""
                entity = ""
                causeid = ""
                urlname = ""
                path = ""

                for item in finding:
                    match item.tag:
                        case 'severity':
                            output = self.xmltreehelper(item)
                            if output is None:
                                severity = "Info"
                            else:
                                severity = output.strip(" ").capitalize()
                        case 'cwe':
                            cwe = int(self.xmltreehelper(item))
                        case 'remediation':
                            remediation = self.xmltreehelper(item)
                        case 'advisory':
                            advisory = self.xmltreehelper(item)
                        case 'issue-type':
                            issue_type = self.xmltreehelper(item).strip()
                            name += issue_type
                            description += f"Issue Type: {issue_type}\n"
                        case 'issue-type-name':
                            issue_type_name = self.xmltreehelper(item).strip()
                            description += f"Issue Type Name: {issue_type_name}\n"
                        case 'location':
                            location = self.xmltreehelper(item)
                            description += f"Location: {location}\n"
                        case 'domain':
                            domain = self.xmltreehelper(item)
                            name += f"_{domain.strip()}"
                            description += f"Domain: {domain}\n"
                        case 'threat-class':
                            threatclass = self.xmltreehelper(item)
                            description += f"Threat Class: {threatclass}\n"
                        case 'entity':
                            entity = self.xmltreehelper(item)
                            name += f"_{entity.strip()}"
                            description += f"Entity: {entity}\n"
                        case 'security-risks':
                            security_risks = self.xmltreehelper(item)
                            description += f"Security Risks: {security_risks}\n"
                        case 'cause-id':
                            causeid = self.xmltreehelper(item)
                            name += f"_{causeid.strip()}"
                            description += f"Cause ID: {causeid}\n"
                        case 'url-name':
                            urlname = self.xmltreehelper(item)
                            name += f"_{urlname.strip()}"
                            description += f"URL Name: {urlname}\n"
                        case 'element':
                            element = self.xmltreehelper(item)
                            description += f"Element: {element}\n"
                        case 'element-type':
                            elementtype = self.xmltreehelper(item)
                            description += f"Element Type: {elementtype}\n"
                        case 'path':
                            path = self.xmltreehelper(item)
                            name += f"_{path.strip()}"
                            description += f"Path: {path}\n"
                        case 'scheme':
                            scheme = self.xmltreehelper(item)
                            description += f"Scheme: {scheme}\n"
                        case 'host':
                            host = self.xmltreehelper(item)
                            description += f"Host: {host}\n"
                        case 'port':
                            port = self.xmltreehelper(item)
                            description += f"Port: {port}\n"
                        case 'impact':
                            impact = self.xmltreehelper(item)
                        case 'steps-to-reproduce':
                            steps_to_reproduce = self.xmltreehelper(item)
                        case 'severity-justification':
                            severity_justification = self.xmltreehelper(item)
                        case 'references':
                            references = self.xmltreehelper(item)
                
                name = f"{issue_type}_{domain}_{entity}_{causeid}_{urlname}_{path}"
                mitigation = f"Remediation: {remediation}\nAdvisory: {advisory}"

                finding = Finding(
                    title=name,
                    description=description,
                    severity=severity,
                    cwe=cwe,
                    mitigation=mitigation,
                    impact=impact,
                    steps_to_reproduce=steps_to_reproduce,
                    severity_justification=severity_justification,
                    references=references,
                    dynamic_finding=True,
                    static_finding=False,
                )
                findings.append(finding)
                try:
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=host, port=port)
                    finding.unsaved_endpoints.append(endpoint)
                except UnboundLocalError:
                    pass
            return findings
        else:
            return findings

if __name__ == "__main__":
    parser = HCLAppScanParser()
    findings = parser.get_findings('example.xml', None)
    for finding in findings:
        print(f"Name: {finding.name}")
        print(f"Description: {finding.description}")
        print(f"Severity: {finding.severity}")
        print(f"CWE: {finding.cwe}")
        print(f"Mitigation: {finding.mitigation}")
        print(f"Impact: {finding.impact}")
        print(f"Steps to Reproduce: {finding.steps_to_reproduce}")
        print(f"Severity Justification: {finding.severity_justification}")
        print(f"References: {finding.references}")
        for endpoint in finding.unsaved_endpoints:
            print(f"Endpoint: {endpoint.host}:{endpoint.port}")
        print("----------")
