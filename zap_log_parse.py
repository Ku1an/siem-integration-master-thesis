import json
import subprocess
import os


class ZapLogEventWazuh:
    def __init__(self, timestamp, ip, port, alert, alert_desc, risk, confidence, url, request_header, request_body, response_header, response_body, solution, solution_reference):
        self.event = {
            "source": "zap-event",
            "timestamp": timestamp,
            "ip": ip,
            "app_port": port,
            "alert": alert,
            "alert_desc": alert_desc,
            "risk": risk,
            "confidence": confidence,
            "url": url,
            "request_header": request_header,
            "request_body": request_body,
            "response_header": response_header,
            "response_body": response_body,
            "solution": solution,
            "solution_reference": solution_reference
        }

    def __str__(self):
        return json.dumps(self.event, indent=4) 



LOG_DIR = "/zap/src/logs"
LOG_FILE = os.path.join(LOG_DIR, "zap_events.log")

ZAP_AUTOMATION_CONFIG_FILENAME = "zap-automationtest.yaml"
REMOVE_ZAP_SCAN_REPORT = True
ZAP_REPORT_FILE = os.path.join(LOG_DIR, "report.json")



# Make sure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)


def run_zap_scan():
    """
    Run ZAP automation YAML.
    """
    try:
        # Run ZAP scan, we are assuming that the file is in the same dir as the python file
        #Starting subprocess which run
        print("Subprocess command...")
        result = subprocess.run(
            ["zap.sh", "-cmd", "-autorun", "/zap/src/" + ZAP_AUTOMATION_CONFIG_FILENAME],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error running ZAP scan:", e.stdout)
        return None




def parse_zap_report():
    """
    Parsing the report.json file created
    """
    try:
        with open(ZAP_REPORT_FILE, "r") as file:
            data = json.load(file)
            site_list = data.get("site")
            timestamp = data.get("created")
            for site in site_list:
                ip  = site.get("@host")
                port = site.get("@port")
                alert_list = site.get("alerts")
                for alert in alert_list:
                    alert_name = alert.get("alert")
                    risk = int(alert.get("riskcode"))
                    confidence = int(alert.get("confidence"))
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
                            timestamp,
                            ip,
                            port,
                            alert_name,
                            desc,
                            risk,
                            confidence,
                            url,
                            request_header,
                            request_body,
                            response_header,
                            response_body,
                            solution,
                            solution_ref
                        ).event

                        # Append Event to Log :D
                        with open(LOG_FILE,"a") as log_file:
                            log_file.write(json.dumps(event) + "\n")

    except FileNotFoundError:
        print(ZAP_REPORT_FILE + " was not found in " + LOG_DIR)



if __name__ == "__main__":
    print("Starting ZAP scan...")
    print("Zap Config file used: " + ZAP_AUTOMATION_CONFIG_FILENAME)
    scan_data = run_zap_scan()
    if scan_data == None:
        print("Existing program due to failure running zap scan...")
    else:
        parse_zap_report()
        print(f"Alerts written to {LOG_FILE}")
        if REMOVE_ZAP_SCAN_REPORT and os.path.exists(ZAP_REPORT_FILE):
            os.remove(ZAP_REPORT_FILE)
            print(ZAP_REPORT_FILE + " were successfully removed")
        else: 
            print("No report file found in: " + ZAP_REPORT_FILE)




