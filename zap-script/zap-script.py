import json
import subprocess
import os
import sys

class ZapLogEventWazuh:
    def __init__(self, ip, port, alert, alert_desc, severity, url, request_header, request_body, solution, solution_reference):
        self.event = {
            "source": "zap-event",
            "ip": ip,
            "app_port": port,
            "alert": alert,
            "alert_desc": alert_desc,
            #"risk": risk,
            #"confidence": confidence,
            "severity": severity,
            "url": url,
            "request_header": request_header,
            "request_body": request_body,
            "solution": solution,
            "solution_reference": solution_reference
        }

    def __str__(self):
        return json.dumps(self.event, indent=4) 

ZAP_REPORT_FILE=""
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE="/var/log/zap_events.log"


def execute_zap():
    global ZAP_REPORT_FILE
    if len(sys.argv) != 3:
        raise ValueError("Usage: python zap_script.py <zap_automation_framework.yaml> <report_name.json>")
     
    ZAP_REPORT_FILE=SCRIPT_DIR + "/framework/" + sys.argv[2]

    try:
        print("Subprocess command...")
        result = subprocess.run(
            ["zap.sh", "-cmd", "-autorun", f"{SCRIPT_DIR}/framework/" + sys.argv[1]],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error running ZAP scan:", e.stderr, e.stdout)
        return None

count = 0
def parse_zap_report(report: str):
    """
    Parsing the report.json file created
    """
    try:
        global count
        with open(report, "r") as file:
            data = json.load(file)
            site_list = data.get("site")
            for site in site_list:
                ip  = site.get("@host")
                port = site.get("@port")
                alert_list = site.get("alerts")
                for alert in alert_list:
                    alert_name = alert.get("alert")
                    severity = alert.get("riskdesc")
                    desc = alert.get("desc").replace("<p>","").replace("</p>","")
                    solution = alert.get("solution").replace("<p>","").replace("</p>","")
                    solution_ref = alert.get("reference")
                    instance_list = alert.get("instances")
                    for instance in instance_list:
                        #Here we create one object for each vulnerable endpoint
                        url = instance.get("uri")
                        request_header = instance.get("request-header")
                        request_body = instance.get("request-body")
                        response_header = instance.get("response-header")
                        response_body = instance.get("response-body")

                        # Create the ZapEventWazuh object
                        event = ZapLogEventWazuh(
                            ip,
                            port,
                            alert_name,
                            desc,
                            severity,
                            url,
                            request_header,
                            request_body,
                            solution,
                            solution_ref
                        ).event
                        count += 1
                        with open(LOG_FILE, "a") as log_file:
                            log_file.write(json.dumps(event) + "\n")

    except FileNotFoundError:
        print(report + " was not found.")

if __name__ == "__main__":
    #Execute Zap test
    execute_zap()
    print(ZAP_REPORT_FILE)
    if os.path.exists(ZAP_REPORT_FILE):
        parse_zap_report(ZAP_REPORT_FILE)
        os.remove(ZAP_REPORT_FILE)
        print(count)
    else:
        print("Zap report file not found")