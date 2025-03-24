from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import BooleanVar
import requests
import os
from datetime import datetime
import re
from nautobot_device_lifecycle_mgmt.models import SoftwareLCM, CVELCM, VulnerabilityLCM
from nautobot.dcim.models import Platform

class LinuxCVEandEOL(Job):
    """
    Nautobot Job to fetch CVE and EOL data for Linux OSes and populate CVELCM, VulnerabilityLCM, and SoftwareLCM models.
    """
    class Meta:
        name = "Linux CVE and EOL Sync"
        description = "Syncs CVE and EOL data for Ubuntu, Rocky Linux, and Red Hat from SoftwareLCM"

    fetch_cves = BooleanVar(
        description="Check to fetch and sync CVEs",
        default=True
    )
    update_eol = BooleanVar(
        description="Check to update EOL data in SoftwareLCM",
        default=True
    )

    # Configuration
    NVD_API_KEY = os.getenv("NVD_API_KEY", "your-nvd-api-key-here")
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EOL_API_URL = "https://endoflife.date/api"
    NVD_LINK_BASE = "https://nvd.nist.gov/vuln/detail/"

    def run(self, fetch_cves, update_eol):
        """Main execution method"""
        self.logger.info("Starting Linux CVE and EOL sync job")

        if not self.NVD_API_KEY or "your-nvd-api-key-here" in self.NVD_API_KEY:
            self.logger.error("NVD API key not configured. Set NVD_API_KEY environment variable.")
            return

        # Fetch Platforms for Ubuntu, Rocky, and Red Hat
        supported_os = ["Ubuntu", "Rocky Linux", "Red Hat Enterprise Linux"]

        # Use case-insensitive matching to find platforms
        platforms = Platform.objects.filter(name__in=supported_os)

        if not platforms:
            available_platforms = [p.name for p in Platform.objects.all()]
            self.logger.warning(f"No platforms found matching {supported_os}. Available platforms: {available_platforms}")
            return

        self.logger.info(f"Found platforms: {[p.name for p in platforms]}")

        # Fetch SoftwareLCM entries linked to these platforms
        software_list = SoftwareLCM.objects.filter(
            device_platform__in=platforms
        ).select_related("device_platform")

        if not software_list:
            self.logger.warning("No matching software found in SoftwareLCM for the specified platforms.")
            return

        self.logger.info(f"Found {len(software_list)} software entries to process.")

        for software in software_list:
            os_name = software.device_platform.name.lower()
            full_version = software.version

            parsed_version = self.parse_version(full_version, os_name)
            if not parsed_version:
                self.logger.warning(f"Could not parse version for {os_name} {full_version}. Skipping.")
                continue

            context = f"[{os_name.upper()} {software.version}]"
            self.logger.info(f"{context} Processing software entry (parsed version: {parsed_version})")

            # Update EOL data if enabled
            if update_eol and os_name in [os.lower() for os in supported_os]:
                self.sync_eol_data(software, os_name, parsed_version)

            # Fetch and sync CVEs if enabled
            if fetch_cves:
                self.sync_cve_data(software, os_name, parsed_version)

        self.logger.info("Linux CVE and EOL sync completed successfully.")

    def parse_version(self, full_version, os_name):
        """Extracts the major.minor version from the full version string."""
        
        # Ubuntu: "Ubuntu 22.04.3 LTS" -> "22.04"
        if "ubuntu" in os_name.lower():
            match = re.search(r"(\d+\.\d+)", full_version)
            return match.group(1) if match else None

        # Red Hat: "Red Hat Enterprise Linux 8.4 (Ootpa)" -> "8.4"
        elif "red hat" in os_name.lower():
            match = re.search(r"(\d+\.\d+)", full_version)
            return match.group(1) if match else None

        # Rocky Linux: "Rocky Linux 9.2 (Blue Onyx)" -> "9.2"
        elif "rocky" in os_name.lower():
            match = re.search(r"(\d+\.\d+)", full_version)
            return match.group(1) if match else None

        # Default: Extract first major.minor version
        else:
            match = re.search(r"(\d+\.\d+)", full_version)
            return match.group(1) if match else None

    def sync_eol_data(self, software, os_name, parsed_version):
        """Fetch EOL data and update SoftwareLCM"""
        
        context = f"[{os_name.upper()} {software.version}]"

        # Normalize OS name for API lookup
        if "red hat" in os_name.lower():
            os_name = "redhat"
            parsed_version = parsed_version.split('.')[0]  # Use major version only
        elif "rocky" in os_name.lower():
            os_name = "rocky"
            parsed_version = parsed_version.split('.')[0]  # Use major version only

        # Construct API request URL
        url = f"{self.EOL_API_URL}/{os_name}/{parsed_version}.json"

        try:
            response = requests.get(url, timeout=10, verify=False)
            self.logger.warning("SSL verification disabled for EOL API due to certificate issues.")
            response.raise_for_status()
            eol_data = response.json()

            updated = False
            eol_date = eol_data.get("eol")
            support_date = eol_data.get("support")

            if eol_date:
                parsed_eol = datetime.strptime(eol_date, "%Y-%m-%d").date()
                if software.end_of_support != parsed_eol:
                    software.end_of_support = parsed_eol
                    updated = True
                    self.logger.info(f"{context} Updated end_of_support: {parsed_eol}")

            if support_date:
                parsed_support = datetime.strptime(support_date, "%Y-%m-%d").date()
                if software.release_date != parsed_support:
                    software.release_date = parsed_support
                    updated = True
                    self.logger.info(f"{context} Updated release_date: {parsed_support}")

            if updated:
                software.save()
                self.logger.info(f"{context} SoftwareLCM updated with EOL and release data.")
            else:
                self.logger.info(f"{context} No changes to release or EOL dates.")

        except requests.HTTPError as http_err:
            self.logger.warning(f"{context} EOL API returned error: {http_err}")
        except requests.RequestException as e:
            self.logger.error(f"{context} Failed to fetch EOL data: {str(e)}")
        except ValueError as ve:
            self.logger.error(f"{context} Failed to parse EOL dates: {ve}")


    def sync_cve_data(self, software, os_name, parsed_version):
        """Fetch CVE data from NVD and populate CVELCM and associate with SoftwareLCM"""
        context = f"[{os_name.upper()} {software.version}]"

        # Normalize OS and map Rocky Linux to RHEL CPE
        normalized_os = os_name.lower()
        if "ubuntu" in normalized_os:
            cpe_name = f"cpe:2.3:o:canonical:ubuntu_linux:{parsed_version}:*:*:*:*:*:*:*"
        elif "rocky" in normalized_os:
            cpe_name = f"cpe:2.3:o:redhat:enterprise_linux:{parsed_version}:*:*:*:*:*:*:*"
            self.logger.info(f"{context} Using Red Hat CPE mapping for Rocky Linux")
        elif "red hat" in normalized_os:
            cpe_name = f"cpe:2.3:o:redhat:enterprise_linux:{parsed_version}:*:*:*:*:*:*:*"
        else:
            self.logger.warning(f"{context} OS name '{os_name}' not in known CPE mappings.")
            return

        headers = {"apiKey": self.NVD_API_KEY}
        start_index = 0
        total_cves = 0
        created_count = 0
        linked_count = 0

        while True:
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": 2000,
                "startIndex": start_index
            }

            try:
                response = requests.get(self.NVD_API_URL, headers=headers, params=params, timeout=15)
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id")
                    description = cve.get("descriptions", [{}])[0].get("value", "No description available") or ""
                    published_date = cve.get("published")

                    severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN").upper()
                    cvss_v3 = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
                    cvss_v2 = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore")

                    # Truncate long fields
                    if len(description) > 255:
                        self.logger.warning(f"{context} Truncating description for {cve_id}")
                        description = description[:252] + "..."

                    fix_info = "No fix available"

                    cve_obj, created = CVELCM.objects.get_or_create(
                        name=cve_id,
                        defaults={
                            "published_date": datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f").date() if published_date else None,
                            "link": f"{self.NVD_LINK_BASE}{cve_id}",
                            "description": description,
                            "severity": severity if severity in [c[0] for c in CVELCM._meta.get_field("severity").choices] else "NONE",
                            "cvss_v3": cvss_v3,
                            "cvss_v2": cvss_v2,
                            "fix": fix_info,
                        }
                    )

                    if not created:
                        # Update fields if already exists
                        cve_obj.published_date = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f").date() if published_date else None
                        cve_obj.description = description
                        cve_obj.severity = severity
                        cve_obj.cvss_v3 = cvss_v3
                        cve_obj.cvss_v2 = cvss_v2
                        cve_obj.fix = fix_info
                        cve_obj.save()
                    else:
                        created_count += 1
                        self.logger.info(f"{context} Created CVE: {cve_id}")

                    # Always link CVE to this software (if not already)
                    if not cve_obj.affected_softwares.filter(pk=software.pk).exists():
                        cve_obj.affected_softwares.add(software)
                        linked_count += 1
                        self.logger.info(f"{context} Linked CVE {cve_id} to software")

                total_cves += len(vulnerabilities)

                if total_cves >= data.get("totalResults", 0):
                    break
                start_index += len(vulnerabilities)

            except requests.RequestException as e:
                self.logger.error(f"{context} Failed to fetch CVE data: {str(e)}")
                break
            except Exception as e:
                self.logger.error(f"{context} Unexpected error processing CVEs: {str(e)}")
                break

        self.logger.info(f"{context} CVEs processed: {total_cves}, created: {created_count}, linked: {linked_count}")


register_jobs(LinuxCVEandEOL)
